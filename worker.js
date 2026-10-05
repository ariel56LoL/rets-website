export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ==============================
    // ADMIN LOGIN
    // ==============================
    if (url.pathname === "/api/admin-login" && request.method === "POST") {
      try {
        const body = await request.json();
        const password = String(body.password || "");

        if (!env.ADMIN_PASSWORD) {
          return json(
            {
              success: false,
              error: "ADMIN_PASSWORD no está configurado en Cloudflare."
            },
            500
          );
        }

        if (!password) {
          return json(
            {
              success: false,
              error: "Introduce la contraseña."
            },
            400
          );
        }

        // Comparación segura evitando filtrar directamente la contraseña.
        const valid = await safeEqual(password, env.ADMIN_PASSWORD);

        if (!valid) {
          return json(
            {
              success: false,
              error: "Contraseña incorrecta."
            },
            401
          );
        }

        // Creamos una sesión firmada.
        const session = await createSession(env.ADMIN_PASSWORD);

        return new Response(
          JSON.stringify({
            success: true
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "Set-Cookie":
                `rets_admin_session=${session}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=7200`
            }
          }
        );
      } catch {
        return json(
          {
            success: false,
            error: "Solicitud de inicio de sesión inválida."
          },
          400
        );
      }
    }

    // ==============================
    // ADMIN LOGOUT
    // ==============================
    if (url.pathname === "/api/admin-logout" && request.method === "POST") {
      return new Response(
        JSON.stringify({ success: true }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie":
              "rets_admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
          }
        }
      );
    }

    // ==============================
    // COMPROBAR SESIÓN
    // ==============================
    if (url.pathname === "/api/admin-session" && request.method === "GET") {
      const valid = await verifySession(request, env);

      return json({
        authenticated: valid
      });
    }

    // ==============================
    // TESTERS — TEMPORAL
    // ==============================
    if (url.pathname === "/api/admin/testers" && request.method === "GET") {
      const valid = await verifySession(request, env);

      if (!valid) {
        return json(
          {
            success: false,
            error: "No autorizado."
          },
          401
        );
      }

      // Por ahora devolvemos una lista vacía.
      // Después conectaremos almacenamiento real (D1/KV).
      return json({
        success: true,
        testers: []
      });
    }

    // ==============================
    // GENERAR TESTER — TEMPORAL
    // ==============================
    if (
      url.pathname === "/api/admin/testers/generate" &&
      request.method === "POST"
    ) {
      const valid = await verifySession(request, env);

      if (!valid) {
        return json(
          {
            success: false,
            error: "No autorizado."
          },
          401
        );
      }

      const code = generateTesterCode();

      return json({
        success: true,
        code
      });
    }

    // ==============================
    // REVOCAR TESTER — TEMPORAL
    // ==============================
    if (
      url.pathname === "/api/admin/testers/revoke" &&
      request.method === "POST"
    ) {
      const valid = await verifySession(request, env);

      if (!valid) {
        return json(
          {
            success: false,
            error: "No autorizado."
          },
          401
        );
      }

      return json({
        success: true
      });
    }

    // ==============================
    // RESTO DEL SITIO
    // ==============================
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("RETS Worker activo.", {
      status: 200,
      headers: {
        "Content-Type": "text/plain; charset=UTF-8"
      }
    });
  }
};


// ========================================
// FUNCIONES
// ========================================

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}


async function safeEqual(a, b) {
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


async function createSession(password) {
  const timestamp = Date.now().toString();

  const data = `${timestamp}.${password}`;

  const hash = await sha256(data);

  return `${timestamp}.${hash}`;
}


async function verifySession(request, env) {
  if (!env.ADMIN_PASSWORD) {
    return false;
  }

  const cookieHeader = request.headers.get("Cookie") || "";

  const match = cookieHeader.match(
    /(?:^|;\s*)rets_admin_session=([^;]+)/
  );

  if (!match) {
    return false;
  }

  const value = match[1];
  const parts = value.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const timestamp = Number(parts[0]);
  const hash = parts[1];

  if (!Number.isFinite(timestamp)) {
    return false;
  }

  const TWO_HOURS = 2 * 60 * 60 * 1000;

  if (Date.now() - timestamp > TWO_HOURS) {
    return false;
  }

  const expected = await sha256(
    `${timestamp}.${env.ADMIN_PASSWORD}`
  );

  return await safeEqual(hash, expected);
}


async function sha256(text) {
  const encoder = new TextEncoder();

  const data = encoder.encode(text);

  const digest = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}


function generateTesterCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  const randomPart = (length) => {
    const values = new Uint32Array(length);
    crypto.getRandomValues(values);

    let result = "";

    for (let i = 0; i < length; i++) {
      result += chars[values[i] % chars.length];
    }

    return result;
  };

  return `RETS-${randomPart(4)}-${randomPart(4)}`;
}
