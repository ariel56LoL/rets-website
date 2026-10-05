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
              success: false,
              authenticated: false,
              error: "ADMIN_PASSWORD no está configurado en Cloudflare."
            },
            500
          );
        }

        if (!password) {
          return json(
            {
              success: false,
              authenticated: false,
              error: "Introduce la contraseña."
            },
            400
          );
        }

        const valid = safeEqual(
          password,
          String(env.ADMIN_PASSWORD)
        );

        if (!valid) {
          return json(
            {
              success: false,
              authenticated: false,
              error: "Contraseña incorrecta."
            },
            401
          );
        }

        // Crear sesión temporal
        const session = await createSession(
          String(env.ADMIN_PASSWORD)
        );

        return new Response(
          JSON.stringify({
            success: true,
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
        console.error("ADMIN LOGIN ERROR:", error);

        return json(
          {
            success: false,
            authenticated: false,
            error: "Solicitud de inicio de sesión inválida."
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
            "Content-Type": "application/json; charset=UTF-8",
            "Cache-Control": "no-store",
            "Set-Cookie":
              "rets_admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
          }
        }
      );
    }

    // =========================================
    // ADMIN SESSION
    // =========================================
    if (
      url.pathname === "/api/admin-session" &&
      request.method === "GET"
    ) {
      const authenticated = await verifySession(
        request,
        env
      );

      return json({
        authenticated
      });
    }

    // =========================================
    // LISTAR TESTERS
    // =========================================
    if (
      url.pathname === "/api/admin/testers" &&
      request.method === "GET"
    ) {
      const authenticated = await verifySession(
        request,
        env
      );

      if (!authenticated) {
        return json(
          {
            success: false,
            error: "No autorizado."
          },
          401
        );
      }

      // Aún no tenemos almacenamiento persistente.
      return json({
        success: true,
        testers: []
      });
    }

    // =========================================
    // GENERAR CÓDIGO DE TESTER
    // =========================================
    if (
      url.pathname === "/api/admin/testers/generate" &&
      request.method === "POST"
    ) {
      const authenticated = await verifySession(
        request,
        env
      );

      if (!authenticated) {
        return json(
          {
            success: false,
            error: "No autorizado."
          },
          401
        );
      }

      let body = {};

      try {
        body = await request.json();
      } catch {
        body = {};
      }

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

      const code = generateTesterCode();

      // Temporalmente no se guarda en una base de datos.
      return json({
        success: true,
        code,
        tester: {
          id: code,
          code,
          name,
          email,
          status: "active"
        }
      });
    }

    // =========================================
    // REVOCAR TESTER
    // =========================================
    if (
      url.pathname === "/api/admin/testers/revoke" &&
      request.method === "POST"
    ) {
      const authenticated = await verifySession(
        request,
        env
      );

      if (!authenticated) {
        return json(
          {
            success: false,
            error: "No autorizado."
          },
          401
        );
      }

      let body = {};

      try {
        body = await request.json();
      } catch {
        body = {};
      }

      const id = String(body.id ?? "").trim();

      if (!id) {
        return json(
          {
            success: false,
            error: "Falta el identificador del tester."
          },
          400
        );
      }

      // La persistencia real la conectaremos después.
      return json({
        success: true,
        revoked: id
      });
    }

    // =========================================
    // SITIO ESTÁTICO
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
// JSON RESPONSE
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
// COMPARACIÓN DE CONTRASEÑA
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
// CREAR SESIÓN
// =========================================

async function createSession(password) {
  const timestamp = Date.now().toString();

  const data = `${timestamp}.${password}`;

  const hash = await sha256(data);

  return `${timestamp}.${hash}`;
}


// =========================================
// VERIFICAR SESIÓN
// =========================================

async function verifySession(request, env) {
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

  const session = match[1];

  const parts = session.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const timestamp = Number(parts[0]);
  const hash = parts[1];

  if (!Number.isFinite(timestamp)) {
    return false;
  }

  const MAX_AGE =
    2 * 60 * 60 * 1000;

  const age = Date.now() - timestamp;

  if (age < 0 || age > MAX_AGE) {
    return false;
  }

  const expected = await sha256(
    `${timestamp}.${env.ADMIN_PASSWORD}`
  );

  return safeEqual(hash, expected);
}


// =========================================
// SHA-256
// =========================================

async function sha256(text) {
  const encoder = new TextEncoder();

  const data = encoder.encode(text);

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
        byte.toString(16).padStart(2, "0")
    )
    .join("");
}


// =========================================
// GENERADOR DE CÓDIGOS RETS
// =========================================

function generateTesterCode() {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  function randomPart(length) {
    const values =
      new Uint32Array(length);

    crypto.getRandomValues(values);

    let result = "";

    for (let i = 0; i < length; i++) {
      result +=
        chars[
          values[i] % chars.length
        ];
    }

    return result;
  }

  return `RETS-${randomPart(4)}-${randomPart(4)}`;
}
