export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================================
    // ADMIN LOGIN
    // =========================================
    if (
      url.pathname === "/api/admin-login" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();
        const password = String(body.password ?? "");

        if (!env.ADMIN_PASSWORD) {
          return json(
            {
              authenticated: false,
              error: "ADMIN_PASSWORD no está configurado."
            },
            500
          );
        }

        if (!password) {
          return json(
            {
              authenticated: false,
              error: "Falta la contraseña."
            },
            400
          );
        }

        if (!safeEqual(password, String(env.ADMIN_PASSWORD))) {
          return json(
            {
              authenticated: false,
              error: "Contraseña incorrecta."
            },
            401
          );
        }

        const session = await createAdminSession(
          String(env.ADMIN_PASSWORD)
        );

        return new Response(
          JSON.stringify({
            authenticated: true
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json; charset=UTF-8",
              "Cache-Control": "no-store",
              "Set-Cookie":
                `rets_admin_session=${session}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=7200`
            }
          }
        );

      } catch (error) {
        console.error(error);

        return json(
          {
            authenticated: false,
            error: "Solicitud inválida."
          },
          400
        );
      }
    }


    // =========================================
    // ADMIN LOGOUT
    // =========================================
    if (
      url.pathname === "/api/admin-logout" &&
      request.method === "POST"
    ) {
      return new Response(
        JSON.stringify({
          success: true
        }),
        {
          status: 200,
          headers: {
            "Content-Type":
              "application/json; charset=UTF-8",
            "Cache-Control": "no-store",
            "Set-Cookie":
              "rets_admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
          }
        }
      );
    }


    // =========================================
    // LISTAR TESTERS
    // =========================================
    if (
      url.pathname === "/api/admin/testers" &&
      request.method === "GET"
    ) {
      if (!(await verifyAdminSession(request, env))) {
        return json(
          {
            success: false,
            error: "No autorizado."
          },
          401
        );
      }

      try {
        const result = await env.DB
          .prepare(`
            SELECT
              id,
              code,
              name,
              email,
              status,
              created_at,
              revoked_at
            FROM testers
            ORDER BY id DESC
          `)
          .all();

        return json({
          success: true,
          testers: result.results || []
        });

      } catch (error) {
        console.error("LIST TESTERS ERROR:", error);

        return json(
          {
            success: false,
            error: "No se pudieron cargar los testers."
          },
          500
        );
      }
    }


    // =========================================
    // GENERAR TESTER
    // =========================================
    if (
      url.pathname === "/api/admin/testers/generate" &&
      request.method === "POST"
    ) {
      if (!(await verifyAdminSession(request, env))) {
        return json(
          {
            success: false,
            error: "No autorizado."
          },
          401
        );
      }

      try {
        const body = await request.json();

        const name = String(body.name ?? "").trim();
        const email = String(body.email ?? "").trim();

        if (!name || !email) {
          return json(
            {
              success: false,
              error: "Nombre y correo son obligatorios."
            },
            400
          );
        }

        let code = null;

        // Evitar duplicados.
        for (let attempt = 0; attempt < 10; attempt++) {
          const candidate = generateTesterCode();

          const existing = await env.DB
            .prepare(
              "SELECT id FROM testers WHERE code = ? LIMIT 1"
            )
            .bind(candidate)
            .first();

          if (!existing) {
            code = candidate;
            break;
          }
        }

        if (!code) {
          return json(
            {
              success: false,
              error: "No se pudo generar un código único."
            },
            500
          );
        }

        const insert = await env.DB
          .prepare(`
            INSERT INTO testers
            (code, name, email, status)
            VALUES (?, ?, ?, 'active')
          `)
          .bind(code, name, email)
          .run();

        if (!insert.success) {
          return json(
            {
              success: false,
              error: "No se pudo guardar el tester."
            },
            500
          );
        }

        return json({
          success: true,
          code
        });

      } catch (error) {
        console.error("GENERATE TESTER ERROR:", error);

        return json(
          {
            success: false,
            error: "No se pudo generar el tester."
          },
          500
        );
      }
    }


    // =========================================
    // REVOCAR TESTER
    // =========================================
    if (
      url.pathname === "/api/admin/testers/revoke" &&
      request.method === "POST"
    ) {
      if (!(await verifyAdminSession(request, env))) {
        return json(
          {
            success: false,
            error: "No autorizado."
          },
          401
        );
      }

      try {
        const body = await request.json();

        const id = Number(body.id);

        if (!Number.isInteger(id) || id <= 0) {
          return json(
            {
              success: false,
              error: "Identificador inválido."
            },
            400
          );
        }

        const result = await env.DB
          .prepare(`
            UPDATE testers
            SET
              status = 'revoked',
              revoked_at = CURRENT_TIMESTAMP
            WHERE id = ?
              AND status = 'active'
          `)
          .bind(id)
          .run();

        if (!result.success) {
          return json(
            {
              success: false,
              error: "No se pudo revocar el tester."
            },
            500
          );
        }

        return json({
          success: true
        });

      } catch (error) {
        console.error("REVOKE TESTER ERROR:", error);

        return json(
          {
            success: false,
            error: "No se pudo revocar el tester."
          },
          500
        );
      }
    }


    // =========================================
    // TESTER LOGIN
    // =========================================
    if (
      url.pathname === "/api/tester-login" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const code = String(body.code ?? "")
          .trim()
          .toUpperCase();

        if (
          !/^RETS-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)
        ) {
          return json(
            {
              valid: false
            },
            200
          );
        }

        const tester = await env.DB
          .prepare(`
            SELECT
              id,
              code,
              name,
              status
            FROM testers
            WHERE code = ?
            LIMIT 1
          `)
          .bind(code)
          .first();

        if (!tester) {
          return json({
            valid: false
          });
        }

        if (tester.status !== "active") {
          return json({
            valid: false
          });
        }

        return new Response(
          JSON.stringify({
            valid: true,
            message: "Access granted."
          }),
          {
            status: 200,
            headers: {
              "Content-Type":
                "application/json; charset=UTF-8",
              "Cache-Control": "no-store"
            }
          }
        );

      } catch (error) {
        console.error("TESTER LOGIN ERROR:", error);

        return json(
          {
            valid: false
          },
          500
        );
      }
    }


    // =========================================
    // STATIC ASSETS
    // =========================================
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response(
      "RETS Worker activo.",
      {
        status: 200,
        headers: {
          "Content-Type":
            "text/plain; charset=UTF-8"
        }
      }
    );
  }
};


// =========================================
// JSON
// =========================================

function json(data, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type":
          "application/json; charset=UTF-8",
        "Cache-Control": "no-store"
      }
    }
  );
}


// =========================================
// ADMIN SESSION
// =========================================

async function createAdminSession(password) {
  const timestamp = Date.now().toString();

  const hash = await sha256(
    `${timestamp}.${password}`
  );

  return `${timestamp}.${hash}`;
}


async function verifyAdminSession(request, env) {
  if (!env.ADMIN_PASSWORD) {
    return false;
  }

  const cookieHeader =
    request.headers.get("Cookie") || "";

  const match = cookieHeader.match(
    /(?:^|;\s*)rets_admin_session=([^;]+)/
  );

  if (!match) {
    return false;
  }

  const parts = match[1].split(".");

  if (parts.length !== 2) {
    return false;
  }

  const timestamp = Number(parts[0]);
  const suppliedHash = parts[1];

  if (!Number.isFinite(timestamp)) {
    return false;
  }

  const age = Date.now() - timestamp;

  if (age < 0 || age > 2 * 60 * 60 * 1000) {
    return false;
  }

  const expectedHash = await sha256(
    `${timestamp}.${env.ADMIN_PASSWORD}`
  );

  return safeEqual(
    suppliedHash,
    expectedHash
  );
}


// =========================================
// SAFE EQUAL
// =========================================

function safeEqual(a, b) {
  const encoder = new TextEncoder();

  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);

  if (aBytes.length !== bBytes.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < aBytes.length; i++) {
    result |= aBytes[i] ^ bBytes[i];
  }

  return result === 0;
}


// =========================================
// SHA-256
// =========================================

async function sha256(text) {
  const data =
    new TextEncoder().encode(text);

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return Array.from(
    new Uint8Array(digest)
  )
    .map(
      byte =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}


// =========================================
// RETS CODE GENERATOR
// =========================================

function generateTesterCode() {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  const values =
    new Uint32Array(8);

  crypto.getRandomValues(values);

  let code = "";

  for (let i = 0; i < values.length; i++) {
    code +=
      chars[
        values[i] % chars.length
      ];
  }

  return (
    `RETS-${code.slice(0, 4)}-${code.slice(4, 8)}`
  );
}
