# TKT-009.8: aislamiento y despliegue coordinado

## Topología autorizada

El Gateway es el único servicio con listener público. Vehicle, Device e Identity deben
escuchar únicamente en la red privada del despliegue; sus puertos no se publican al host.
MongoDB pertenece a la red privada y no se publica en entornos compartidos.

La composición local actual (`infrastructure/docker/compose.yml`) levanta únicamente el
MongoDB de desarrollo y publica `127.0.0.1:27018` para inspección local. No es un manifiesto
de producción ni despliega los servicios HTTP. Un proveedor de despliegue debe conectar los
servicios a una red privada equivalente y publicar solo el listener del Gateway. No se debe
interpretar la publicación local de MongoDB como una configuración válida para producción.

Matriz de comunicación:

| Origen                    | Destino                            | Permitido              |
| ------------------------- | ---------------------------------- | ---------------------- |
| Cliente externo           | Gateway                            | HTTPS público          |
| Gateway                   | Vehicle, Device, Identity          | HTTPS/red privada      |
| Vehicle                   | Identity, Device                   | HTTPS/red privada y v2 |
| Device                    | Identity                           | HTTPS/red privada y v2 |
| Cualquier cliente externo | Vehicle, Device, Identity, MongoDB | Denegado               |

No existe proxy genérico hacia `/internal/*`; las rutas internas solo aceptan el principal v2,
audiencia, operación y nonce correspondientes.

## TLS y secretos

En `production`, las URLs de servicios del Gateway deben ser `https://`; el cliente HTTP usa
validación de certificados del runtime y rechaza redirects. El proveedor termina TLS público
en el Gateway y debe usar TLS también entre servicios, con CA verificable y rotación de
certificados fuera del repositorio.

Cada pareja dirigida recibe su propio keyring v2 (`environment`, sender, audience, keyId,
vigencia). Los secretos se inyectan desde el gestor de secretos del proveedor; nunca se
registran valores, firmas, JWT ni cuerpos.

## Readiness y smoke test

`/health` y `/health/live` solo indican liveness. `/health/ready` es obligatorio antes de
recibir tráfico protegido:

- Gateway comprueba `/health/ready` de Identity, Vehicle y Device.
- Vehicle y Device comprueban conexión MongoDB, replica set primario e índices único/TTL
  mediante `MongoNonceStore.assertReady()`.
- Identity comprueba ping MongoDB.
- Configuración HMAC ausente o inválida impide el arranque.

El smoke test debe verificar readiness 200, una solicitud v2 autorizada por servicio y una
solicitud externa directa a cada servicio interno que resulte inaccesible.

## Despliegue y rollback

1. Preparar variables y secretos v2 por entorno y pareja.
2. Validar keyrings y certificados sin exponer valores.
3. Arrancar receptores y esperar `/health/ready` 200.
4. Arrancar Gateway con sus URLs HTTPS fijas y esperar su readiness.
5. Drenar tráfico, ejecutar smoke tests y reanudarlo solo tras resultados correctos.

Para rollback, drenar Gateway, detener emisores incompatibles, mantener receptores v2 con
la clave anterior durante el solapamiento autorizado y volver únicamente a una versión v2
compatible. No se reactiva HMAC v1, no se limpian nonces y no se reabre una clave revocada.

La publicación de Vehicle/Device/Identity y la terminación TLS dependen del proveedor. El
repositorio ya contiene el Blueprint declarativo `render.yaml`, pero no se ha desplegado ni
validado contra recursos reales de Render; por ello TLS productivo continúa pendiente.

## Blueprint Render (TKT-009.8B)

`render.yaml` declara cuatro servicios en la misma región: `pichu-api-gateway` como único
`web` público y `pichu-identity`, `pichu-vehicle` y `pichu-device` como `pserv` privados.
Cada servicio instala el workspace desde la raíz con pnpm 12.16.1, compila su paquete y
arranca el entrypoint de producción. Render consulta `/health/ready` en los cuatro servicios.

Las variables sensibles (`DATABASE_URL`, JWT, Resend, CORS y keyrings v2) están marcadas
`sync: false` y deben rellenarse en el panel/secret store de Render. El Blueprint no contiene
credenciales ni valores secretos. MongoDB Atlas debe proporcionar una URI `mongodb+srv://`
por servicio, con bases y usuarios separados, TLS habilitado, replica set y allowlist de
salida de Render; este repositorio no crea ni modifica Atlas.

Render documenta que su private networking ofrece conectividad privada, pero no equivale por
sí solo a mTLS ni garantiza certificados verificables entre servicios. Los nombres reales de
los servicios se deben cargar como secretos/configuración de despliegue; no se inventan en Git.

La implementación local de TKT-009.8D permite configurar `TLS_CERT_PATH`, `TLS_KEY_PATH` y
`TLS_CA_PATH` en Identity, Vehicle y Device. Gateway usa `TLS_CA_PATH`; los clientes internos
validan la CA, la cadena y el hostname del URL mediante `https.request` con verificación TLS
activa. En producción las rutas deben apuntar a Secret Files de Render, con certificados cuyo
SAN coincida exactamente con el hostname privado real obtenido del panel Connect. Los nombres
privados no se fijan en Git ni en el Blueprint.

La integración local TKT-009.8E ejecutó por HTTPS real Vehicle → Identity, Vehicle → Device y
Device → Identity con CA/certificados efímeros y MongoDB autenticado; el smoke TKT-009.8D validó
además rechazo de CA y hostname incorrectos y de HTTP contra receptores TLS. Esta evidencia sólo
cubre el transporte local. Antes de producción se deben crear los Secret Files, distribuir la
CA, emitir certificados con SAN de los hostnames privados reales, verificar permisos de lectura,
definir renovación/revocación y repetir readiness y smoke tests dentro de Render.

El runner activo `scripts/tkt0098e-https.integration.ts` también cubre Gateway → Vehicle/Device
mediante HTTPS interno: rutas públicas de creación, listado y detalle, lectura de dispositivo,
persistencia de nonce, JWT inválido, saneamiento de headers internos, replay, audience/deadline
inválidos y receptor no disponible. Sustituye a
`scripts/tkt0096b-gateway-real.integration.ts`, que conserva transporte HTTP interno y queda
fuera del conjunto de pruebas y del staging de TKT-009. No debe reactivarse como prueba
obligatoria ni usarse como justificación para habilitar fallback HTTP.

El plan `starter` se usa como marcador operativo para Private Services; disponibilidad, precio,
región y requisitos de plan deben confirmarse en la cuenta Render antes de crear recursos.
No se ejecutó ningún despliegue ni se crearon servicios remotos.

Checklist previo a producción:

- [ ] Confirmar soporte de Node 24.14.0 y pnpm 12.16.1 en la cuenta.
- [ ] Cargar secretos v2 por pareja dirigida y validar solapamiento active/previous.
- [ ] Cargar URIs Atlas separadas con TLS y allowlist restringida.
- [ ] Confirmar certificados/CA para `https://pichu-*` y validación de hostname.
- [ ] Verificar `/health/ready` 200 antes de drenar y reanudar tráfico.
- [ ] Ejecutar smoke tests públicos Gateway y pruebas negativas v2.
- [ ] Confirmar rollback coordinado sin HMAC v1.
