# TKT-008 — propuesta final de staging con Identity

**READY para commit del snapshot descrito; despliegue todavía condicionado.** Sustituye la propuesta anterior de 32 archivos.

## Selección exacta

Incluir el contenido del snapshot para estos archivos. Todos coinciden con el working tree salvo las selecciones parciales indicadas abajo y formato Prettier:

- `apps/api-gateway/.env.example`
- `apps/api-gateway/package.json`
- `apps/api-gateway/src/app.ts`
- `apps/api-gateway/src/config/env.ts`
- `apps/api-gateway/src/lib/openapi.ts`
- `apps/api-gateway/src/lib/proxy.ts`
- `apps/api-gateway/src/lib/rate-limiter.ts`
- `apps/api-gateway/src/routes/docs.ts`
- `apps/api-gateway/src/routes/identity-errors.ts`
- `apps/api-gateway/src/schemas/gateway.schema.ts`
- `apps/api-gateway/src/security/internal-auth.ts`
- `apps/api-gateway/src/security/jwt.ts`
- `apps/api-gateway/src/server.ts`
- `apps/api-gateway/test/config.test.ts`
- `apps/api-gateway/test/health-rate-limit.test.ts`
- `apps/api-gateway/test/identity-flow.test.ts`
- `apps/api-gateway/test/jwt.test.ts`
- `apps/api-gateway/test/proxy.test.ts`
- `apps/api-gateway/test/rate-limiter.test.ts`
- `apps/api-gateway/test/verification.test.ts`
- `docs/tickets/TKT-008.md`
- `packages/contracts/src/common.ts`
- `packages/contracts/test/common-internal.test.ts`
- `pnpm-lock.yaml`
- `apps/api-gateway/test/internal-transport.test.ts`
- `packages/contracts/src/identity.ts`
- `packages/contracts/src/vehicle.ts`
- `packages/contracts/test/identity.test.ts`
- `packages/contracts/test/contracts.test.ts`
- `packages/contracts/test/vehicle-device.test.ts`
- `packages/contracts/README.md`
- `docs/tickets/TKT-008-staging.md`
- `package.json`
- `services/identity-service/package.json`
- `services/identity-service/src/email/email-provider.ts`
- `services/identity-service/src/email/resend-email.provider.ts`
- `services/identity-service/src/models/user.model.ts`
- `services/identity-service/src/routes/auth.ts`
- `services/identity-service/src/routes/docs.ts`
- `services/identity-service/src/routes/errors.ts`
- `services/identity-service/src/routes/health.ts`
- `services/identity-service/src/schemas/auth.schema.ts`
- `services/identity-service/src/schemas/error.schema.ts`
- `services/identity-service/src/services/email-verification.service.ts`
- `services/identity-service/src/services/login.service.ts`
- `services/identity-service/src/services/password-recovery.service.ts`
- `services/identity-service/src/services/registration.service.ts`
- `services/identity-service/src/services/user-profile.service.ts`
- `services/identity-service/test/auth-route.test.ts`
- `services/identity-service/test/email-provider.test.ts`
- `services/identity-service/test/email-verification.integration.test.ts`
- `services/identity-service/test/error-assertion.ts`
- `services/identity-service/test/error-response.test.ts`
- `services/identity-service/test/health.test.ts`
- `services/identity-service/test/jwt.test.ts`
- `services/identity-service/test/models.test.ts`
- `services/identity-service/test/password-recovery.integration.test.ts`
- `services/identity-service/test/password-recovery.route.test.ts`
- `services/identity-service/test/registration.integration.test.ts`
- `services/identity-service/test/registration.test.ts`
- `services/identity-service/test/unverified-access.test.ts`
- `services/identity-service/src/app.ts`

## Hunks parciales obligatorios

- `services/identity-service/src/app.ts`: incluir integración de perfil, errores, documentación y dependencias públicas. Excluir imports de UserModel y verifyInternalRequest, y los dos bloques app.get de `/internal/users/:userId/exists` y `/internal/users/:userId/verified`. Importar solo UserProfileService del módulo de perfil. Estas rutas no existen en HEAD; permanecen fuera del commit, sin introducir un endpoint sin autenticación.
- `services/identity-service/test/unverified-access.test.ts`: incluir perfil, login no verificado y flujo de verificación; excluir imports InternalRequestModel/internalSignature y exclusivamente la prueba `signed internal verification endpoint reports the latest state to domain services`, correspondiente al endpoint TKT-009 excluido. Las pruebas del Gateway permanecen intactas.
- `services/identity-service/package.json`: dependencias actuales; conservar scripts de HEAD, sin introducir el runner de integración local.
- `pnpm-lock.yaml`: partir del índice previo e incluir adicionalmente solo importers raíz e Identity del working tree. Conservar las resoluciones transitivas del índice y aplicar formato. No incluir importers Vehicle, Device o Automation.
- `package.json` raíz: openapi-types requerido por la documentación de Identity y formato existente.

## Dependencia coherente de Identity

Rutas auth + schemas compartidos + normalización de errores resuelven los tres fallos. Registro requiere modelo User, normalización y unicidad de username, servicios de registro/verificación/recuperación y contrato de errores del proveedor de correo. Perfil requiere UserProfileService y su inyección en app. La documentación de rutas requiere Swagger, schemas de error y openapi-types. Los tests incluidos acompañan estas interfaces; las pruebas de integración actualizadas se conservan aunque no se ejecutaron contra una base de datos.

No incluir config/env, server, bootstrap, verificadores internos, modelo internal-request, runner de integración ni scripts locales. Tampoco implementaciones de Vehicle, Device o Automation. El test JWT ya staged de Identity sí forma parte de esta propuesta y se ejecutó en su suite.

## Preparación manual

Revisar el parche exacto del snapshot referido en el informe. Usar selección de hunks para los archivos parciales; no preparar app.ts ni unverified-access.test.ts completos desde el working tree. Para los demás archivos, preparar los contenidos enumerados, con el formato del snapshot. Comparar `git diff --cached` con el parche antes de hacer commit. El agente no alteró el índice.

El snapshot fue construido desde HEAD y solo esta selección. Reutiliza paquetes externos instalados; los enlaces de contratos apuntan a fuentes compiladas dentro del snapshot. No se certifica instalación limpia desde registro.
