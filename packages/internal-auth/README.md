# @pichu/internal-auth

Primitivas Node.js de `pichu-s2s-v2`, conforme a
[`TKT-009`](../../docs/tickets/TKT-009.md). No integra servicios ni acepta v1.
Depende exclusivamente de `@pichu/contracts` y de primitivas de Node.js.

## API

- `signRequest(context, unsignedHeaders, request)`: firma con clave activa explícita,
  verificando identidad, entorno, vigencia, tiempo, target y bytes originales.
- `verifyRequest(context, rawHeaders, request)`: lanza `InternalAuthError` ante fallo;
  valida la misma información y compara el HMAC en tiempo constante.
- `buildCanonicalFields`, `serializeCanonicalFields`, `sha256`, `signCanonicalFields`,
  `verifyCanonicalSignature`: composición y criptografía de bajo nivel. Las dos últimas
  no comprueban vigencia de claves ni frescura; usar las funciones de request en adaptadores.
- `generateNonce`: 32 bytes de `randomBytes`; generar uno por intento HTTP.
- `parseRequestHeaders`, `validateUnsignedHeaders`, `decodeBytes32`,
  `validateRequestTarget`, `validateTimestampAndDeadline`: validación sin normalización.
- `validateKeyring`, `resolveKey`: selección exacta por entorno/emisor/receptor/keyId;
  no hay fallback. Devuelve copia de la clave, nunca una referencia al keyring.
- Tipos: `AuthContext`, `RequestBytes`, `CanonicalFields`, `KeyIdentity`, `KeyEntry`,
  `Keyring`, `InternalAuthErrorCode`.

El contexto aporta `environment`, `sender`, `audience`, `keyring` y `now` Unix ms.
El adaptador receptor fija audience/entorno desde configuración confiable y selecciona
el sender esperado mediante su política explícita; no concede permisos copiando headers.
`RequestBytes` contiene `method`, `target` original y `body: Uint8Array` original.
No reconstruir el body desde JSON. `parseRequestHeaders` requiere el array original de
nombres/valores alternados, antes de combinar duplicados. Rechaza duplicados también
en headers de transporte. El adaptador debe rechazar trailers efectivamente recibidos,
además de la cabecera Trailer que ya rechaza la biblioteca.

`verifyRequest` NO autoriza operaciones, valida JWT ni reserva nonces. Su éxito solo
demuestra las comprobaciones criptográficas y temporales. Antes de ejecutar negocio,
el futuro receptor debe aplicar política de operación, JWT, antirreplay persistente,
validación segura JSON/DTO y autorización de dominio. TLS y límites de transporte
siguen siendo responsabilidad del adaptador/despliegue. Ningún servicio consume aún v2.

La biblioteca no lee variables de entorno ni reloj global, no consulta MongoDB,
no implementa retries y no conoce claves reales. El keyring es configuración explícita
readonly: el propietario debe reemplazarlo atómicamente y no mutarlo durante uso.
Admite como máximo una clave activa y una anterior por pareja/entorno. La distribución,
el solapamiento de rotación y la prohibición histórica de reutilizar keyId son controles
operacionales; no se pueden probar con un único snapshot del keyring.

Errores tipados con mensaje fijo y sin valores/cause: `INVALID_FORMAT`, `INVALID_AUTH`,
`DEADLINE_EXCEEDED`, `INVALID_CONFIG`. No serializar inputs ni errores Zod en logs.
Las funciones puras no asignan estados HTTP; esa traducción corresponde al adaptador.

## Validación

Construir contracts antes del paquete para resolver sus exports `dist`:

```powershell
pnpm --filter @pichu/contracts build
pnpm --filter @pichu/internal-auth build
pnpm --filter @pichu/internal-auth lint
pnpm --filter @pichu/internal-auth typecheck
pnpm --filter @pichu/internal-auth test
pnpm --filter @pichu/contracts test
```

Los tests incluyen los tres vectores normativos y 45 mutaciones como casos independientes.
Todo material criptográfico de fixtures es sintético. No hay pruebas omitidas de MongoDB:
la persistencia y los adaptadores HTTP pertenecen a etapas posteriores y no se implementan aquí.
