# @pichu/internal-auth-adapters — TKT-009.3

Adaptadores opt-in de `pichu-s2s-v2`, conforme a
[`TKT-009`](../../docs/tickets/TKT-009.md). Ninguna aplicación o servicio los registra
todavía. No añaden rutas de negocio, autenticación JWT, permisos de usuario, reintentos,
clientes HTTP ni una base central. `@pichu/internal-auth` permanece sin dependencias
Fastify/MongoDB y sin modificaciones en esta etapa.

## API y propiedad

Entradas públicas:

- `@pichu/internal-auth-adapters/fastify`: `internalAuthPlugin`,
  `InternalAuthPluginOptions`, `getInternalPrincipal(request)`, `getInternalSignal(request)`.
- `@pichu/internal-auth-adapters/mongodb`: `MongoNonceStore`, `createNonceIndexes(db)`,
  `validateNonceIndexes(indexes)`, `NONCE_COLLECTION`, `NONCE_INDEXES`, `NonceDocument`.
- `@pichu/internal-auth-adapters/types`: `NonceStore`, `NonceReservation`,
  `NonceStoreUnavailable`, `InternalPrincipal`, `OperationPolicy`.

Cada receptor entrega **su propio `Db`** a `new MongoNonceStore(db)`; la biblioteca no
abre conexiones ni lee configuración ambiental. El propietario mantiene/cierra su
conexión. El runtime necesita hello, listIndexes e insert; la cuenta de despliegue
ejecuta `createNonceIndexes(db)` explícitamente. Readiness y admisión no crean índices.
No compartir la colección entre servicios. Readiness exige replica set y primario.

`NonceStore.assertReady()` verifica disponibilidad/índices reales; `reserve(input, signal)`
retorna únicamente `reserved` o `replay`. Cualquier resultado ambiguo lanza
`NonceStoreUnavailable`. El adaptador HTTP rechaza también retornos inesperados.
No hay implementación de almacenamiento en memoria en el paquete productivo.

Registrar el plugin con `environment`, `audience`, proveedor `keyring`, `nonces`,
`policies` y callback async `routes(scope)`. Registrar las rutas protegidas dentro de
ese callback; Fastify conserva el encapsulamiento porque no se usa `fastify-plugin`.
El callback no autoriza endpoints preexistentes por su mera existencia.

Cada ruta declara `config: { internalOperation: 'id-estatico' }`. La política para ese
ID declara método, plantilla exacta (incluido prefix) y emisores permitidos. Comparación
exacta, sin wildcard ni permiso por prefijo. Ausencia, ID desconocido, método/plantilla
distintos o sender no permitido producen 403 después de verificar HMAC, sin reserva.
Ningún encabezado del caller selecciona el operationId. HEAD automático requiere
política propia: no hereda implícitamente permiso GET.

`getInternalPrincipal` devuelve un objeto congelado con identidad de servicio,
environment, audience, keyId, operationId, requestId, nonce, timestamp y deadline.
No contiene actor de usuario ni permisos de dominio. No está disponible antes de
confirmar la reserva y parsear JSON. `getInternalSignal` entrega cancelación cooperativa
para trabajo subordinado; no autoriza ni revierte efectos.

## Orden real de procesamiento Fastify

1. `onReady`: consultar topology e índices reales. Fallar impide abrir el listener.
2. `onRequest`: copiar `rawHeaders`, método y `raw.url`; validar formatos, duplicados,
   target, timestamp/deadline y framing para GET/HEAD. Iniciar presupuesto monotónico.
3. `preParsing`: exigir el stream original. Un guard final por ruta rechaza también
   streams sustituidos por hooks del scope/ancestros. Hooks preParsing de ruta se
   rechazan al registrar; no se permite descompresión ni reescritura de payload.
4. Parser encapsulado `parseAs: 'buffer'`: Fastify aplica bodyLimit y longitud;
   guardar copia privada de bytes originales y retornar temporalmente Buffer. Se usa
   parser wildcard para capturar también payload sin Content-Type y rechazarlo conforme
   al protocolo. Sin payload, la copia permanece vacía aunque Fastify omita el parser.
5. `preValidation`: rechazar trailers, verificar HMAC/identidad/audience/versión/keyring
   y vigencia mediante TKT-009.2, aplicar política estática y reservar nonce. Solo tras
   confirmación ejecutar `getDefaultJsonParser('error', 'error')` de Fastify, asignar
   request.body y publicar principal. La biblioteca criptográfica ya validó UTF-8/BOM.
6. Hooks posteriores de preValidation, validación de schema Fastify y preHandler.
   Aquí deberán incorporarse JWT y controles del dominio en la etapa autorizada.
7. Guard de presupuesto al entrar al handler, después de todos los preHandler.
8. `onResponse`: cancelar trabajo subordinado, limpiar temporizador y estado privado.

Las rutas públicas hermanas conservan sus parsers. JSON inválido o prototype poisoning
con firma válida consume nonce; no se libera ante errores de parseo/schema/negocio.
Con firma inválida no se ejecuta el parser JSON ni se reserva nonce.

El host debe registrar este scope sin hooks ancestrales que consuman/modifiquen bytes
en el stream original, alteren headers/raw.url o ejecuten negocio antes de admisión.
No usar rewriteUrl, parsers sustitutos ni plugins que debiliten estos controles dentro
del scope. El código de registro es configuración confiable, no un sandbox frente a
plugins maliciosos. Las pruebas detectan sustituciones de stream y verifican el orden.

Límites: body hasta 1 MiB (ruta puede reducirlo), headers 16 KiB y Authorization 8192
bytes según contratos. HTTP Node puede rechazar framing/headers antes de Fastify.
Usar maxHeaderSize acorde, límites de conexiones y red/TLS al integrar. Desactivar o
redactar el logging de request del host para no registrar Authorization, cookies,
firmas, cuerpos o query sensible; este paquete no registra inputs ni errores originales.

## MongoDB

Colección local `internal_request_nonces`:

```text
_id: ObjectId
environment, sender, audience, nonce: string
acceptedAt: Date
expiresAt: Date(timestamp + 120000)
```

Índices verificados mediante `listIndexes`, incluyendo opciones:

```text
internal_nonce_unique: {environment:1, sender:1, audience:1, nonce:1}, unique:true
internal_nonce_expiry: {expiresAt:1}, expireAfterSeconds:0
```

No se admite índice parcial, sparse o collation no simple. El índice TTL no puede ser
único. No incluir keyId: la rotación no permite reutilizar nonce. TTL limpia solamente;
la admisión temporal viene de TKT-009.2 y no depende de que MongoDB borre puntualmente.

Reserva: un comando `insert` de un documento, sin upsert/find previo, con
`writeConcern: {w:'majority', j:true, wtimeout:500}`, primary y sin reintento automático.
Se usa `Db.command` deliberadamente: el driver 7.7 elimina wtimeout en `insertOne` al
usar CSOT. El comando explícito conserva los tres campos y admite AbortSignal +
timeoutMS. La prueba de monitoreo de comandos comprueba los valores realmente enviados.
Se exige `ok:1`, `n:1`, sin writeErrors ni writeConcernError antes de confirmar.
Duplicate key sin error de write concern implica replay. Otros errores/ack ambiguo
implican indisponibilidad. Nunca borrar un nonce tras un timeout o error de negocio.

Readiness consulta hello y ambos índices. Cada reserva revalida índices y topology;
no se confía en readiness cacheada. El despliegue debe prohibir DDL concurrente de
la colección en tráfico: listIndexes e insert no son una transacción con dropIndex.
La cuenta runtime no debe poder eliminar índices. Usar clocks sincronizados según TKT-009.

## Tiempo y errores

Presupuesto monotónico por intento: mínimo de deadline restante y 1000 ms para GET/HEAD,
2000 ms para otros métodos. El protocolo limita la cadena a 5000 ms. Lectura de body,
verificación, reserva y handler comparten ese presupuesto. Reserva completa hasta 500 ms,
con temporizador y señal; aunque una dependencia ignore cancelación, un resultado tardío
no puede pasar al handler. El driver tiene además su timeout y la escritura su wtimeout.

El deadline dispara 504 y cancelación; el guard final comprueba tiempo monotónico incluso
si un hook bloqueó el event loop. Una vez iniciado negocio, solo la cooperación con
AbortSignal puede detenerlo: no se promete rollback ni seguridad de actuadores.
No existen reintentos automáticos en estos adaptadores.

Respuestas `{error, message, requestId?}` con mensaje fijo: formato 400, autenticación o
replay 401, política 403, payload 413, deadline 504, almacenamiento/configuración 503,
fallo inesperado 500. No exponen causa, keyring, índices, firmas, JWT ni errores Zod/Mongo.
No serializar el principal completo en respuestas productivas; los tests lo hacen solo
con datos sintéticos para comprobar el contrato.

## Pruebas reproducibles y límites de evidencia

```powershell
pnpm --filter @pichu/contracts build
pnpm --filter @pichu/internal-auth build
pnpm --filter @pichu/internal-auth-adapters build
pnpm --filter @pichu/internal-auth-adapters lint
pnpm --filter @pichu/internal-auth-adapters typecheck
pnpm --filter @pichu/internal-auth-adapters test
pnpm --filter @pichu/internal-auth-adapters test:mongo
```

`test` usa Fastify con sockets HTTP reales en loopback y un doble explícito de NonceStore
para fallos del adaptador; esas pruebas no demuestran persistencia MongoDB.

`test:mongo` requiere Docker y la imagen local `mongo:8.0.17`. Crea un contenedor con nombre
aleatorio, etiqueta de propiedad, puerto aleatorio solo en 127.0.0.1, datos tmpfs y replica
set de un miembro. No acepta URI externa ni carga .env. La limpieza comprueba la etiqueta
antes de eliminar únicamente su contenedor. No usa volúmenes o bases existentes. Sin
Docker/imagen, el runner marca SKIP explícito; no se puede reportar validación MongoDB.

Comprueba índices, expiración almacenada, replay entre conexiones concurrentes, HTTP real
con persistencia real, eliminación de índice, write concern error y bloqueo de insert
mediante failpoints exclusivos del contenedor de pruebas. El comando de reserva conserva
majority+journal+wtimeout también bajo timeout de cliente. Nunca se ejecutan acciones físicas.

Un replica set de un miembro no demuestra failover o pérdida de mayoría entre varios
nodos. Tampoco se prueba aislamiento TLS/ACL ni distribución de secretos, despliegues
parciales, rotación operacional o integración JWT/dominio: siguen pendientes para las
etapas posteriores. No declarar servicios migrados ni despliegue listo con estos tests.
