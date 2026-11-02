# Identity Service

## Autenticación

Endpoints principales: `POST /auth/login`, `POST /auth/refresh`, `POST /auth/logout`, `POST /auth/logout-all`, `GET /sessions` y `DELETE /sessions/:sessionId`.

El servicio emite access tokens JWT HS256 con una duración de 15 minutos y refresh tokens opacos con una duración inicial de 30 días. En MongoDB solo se almacena el hash SHA-256 del refresh token.

Cada sesión tiene una familia independiente de refresh tokens. La renovación consume el token anterior y crea el siguiente dentro de una transacción MongoDB con reintentos ante conflictos. Un token usado nuevamente revoca la sesión completa en una transacción independiente. Los tokens usados se conservan hasta `expiresAt`; los índices TTL solo realizan limpieza y no participan en la autorización.

## Transporte

Las aplicaciones web usan la cookie `pichu_refresh_token` (`HttpOnly`, `SameSite=Lax`, `Path=/auth` y `Secure` en producción). Las renovaciones basadas en cookie requieren un encabezado `Origin` que coincida con `AUTH_COOKIE_ORIGIN`. Los clientes nativos pueden solicitar el transporte en el cuerpo usando `X-Refresh-Token-Transport: body`; una solicitud no puede enviar cookie y cuerpo simultáneamente.

Si `X-Refresh-Token-Transport` se omite, se selecciona explícitamente el transporte `cookie`. Cualquier otro valor es rechazado; `body` es el único transporte alternativo permitido.

Los refresh tokens no deben guardarse en `localStorage`, registrarse en logs ni incluirse en documentación pública.

## Variables JWT

- `JWT_SECRET`: secreto de al menos 32 bytes.
- `JWT_ISSUER`: emisor esperado.
- `JWT_AUDIENCE`: audiencia esperada.
- `ACCESS_TOKEN_TTL_SECONDS`: duración del access token.
- `REFRESH_TOKEN_TTL_SECONDS`: duración máxima de la sesión y sus refresh tokens.
- `AUTH_COOKIE_ORIGIN`: origen permitido para renovaciones mediante cookie; debe usar HTTPS en producción.

La autenticación JWT valida firma, algoritmo HS256, issuer, audience, expiración, `sub`, `sid` y el estado activo de la sesión. Esta última comprobación consulta MongoDB para que la revocación tenga efecto inmediato.
