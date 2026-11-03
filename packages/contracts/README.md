# @pichu/contracts

Las llamadas HTTP internas pueden reutilizar los contratos de `internal.ts` para
propagar el servicio llamante, la versión del contrato y el identificador de
petición. Estos campos facilitan la trazabilidad, pero no autentican una llamada:
cada servicio debe aplicar además el mecanismo criptográfico de autenticación
interna que se defina para el despliegue.

Contratos versionados para la comunicación HTTP entre el API Gateway y los
servicios de PICHU.

Este paquete contiene schemas Zod y tipos inferidos. No contiene modelos
Mongoose, acceso a bases de datos ni lógica de dominio.

Los cambios incompatibles deben publicarse bajo una nueva versión de contrato.

## Versionado

`@pichu/contracts` utiliza SemVer para la compatibilidad del paquete. El valor
`CONTRACTS_VERSION` identifica la versión del protocolo compartido y no sustituye
la versión npm. Las rutas públicas futuras deberán adoptar `/api/v1`; las rutas
existentes no se cambian retroactivamente en este ticket.

Los cambios compatibles pueden añadir DTOs, campos opcionales o nuevos códigos
documentados. Los cambios incompatibles requieren una nueva versión de protocolo
y una estrategia de transición. No se deben reutilizar nombres con semántica
distinta.

## Identificadores y llamadas internas

Los ObjectId se transportan como 24 caracteres hexadecimales en minúscula. Los
request IDs se recortan, tienen entre 1 y 128 caracteres y no pueden contener
caracteres de control. Las solicitudes internas requieren request ID, nombre del
caller y `x-contract-version`. `api-gateway` es un caller válido, mientras que
los cuatro servicios de dominio se exponen también mediante el conjunto de
servicios de dominio.

Los schemas `x-timestamp` y `x-signature` solo describen formato. No verifican
firmas, frescura ni replay; esas responsabilidades pertenecen a TKT-009.

## Contratos de Identity

Los DTOs cerrados de Identity rechazan propiedades desconocidas. Esta regla se
aplica a bodies, params y respuestas para detectar cambios accidentales en el
wire format. Los schemas de headers reciben solamente una proyección de las
cabeceras contractuales; no deben aplicarse directamente al objeto completo de
headers de Node.js o Fastify.

El transporte de refresh tokens se declara mediante
`x-refresh-token-transport`. Si la cabecera se omite, el transporte es `cookie`.
El transporte `cookie` exige un body ausente o un objeto vacío, mientras que
`body` exige el refresh token en el body. Los contratos no modelan cookies.
Las cabeceras criptográficas solo tienen schemas de formato en `internal.ts`;
no se verifican aquí. Logout y eliminación de sesión no admiten body.

## Contratos de Vehicle y Device

Los DTOs de Vehicle usan `id` para representar el recurso vehículo y mantienen
`vehicleId` y `userId` explícitos en referencias. El body público de creación no
incluye `userId`: la identidad del propietario procede de autenticación. Los
DTOs de invitación reflejan el endpoint actual; membresías y permisos no
constituyen una implementación de autorización en este paquete. El DTO público
no contiene `inviterUserId`; Gateway debe derivarlo de la autenticación y Vehicle
debe comprobar la autorización. El DTO interno añade `inviterUserId` únicamente
después de esa derivación.

Los DTOs de Device usan `deviceId` como identificador de recurso. La identidad
pública del dispositivo se compone de `deviceId`, `identifier`, `vehicleId` y
`status`; el material de clave pública solo aparece en el DTO interno de
provisioning. Un identificador textual no demuestra posesión de una clave.

Los schemas de challenge y completion son provisionales. No fijan el algoritmo,
el formato de firma ni el protocolo BLE; esas decisiones quedan para los tickets
de Device y del protocolo criptográfico.

## BLE

BLE contracts are provisional and do not define an approved authorization or
cryptographic protocol.
