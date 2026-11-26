# Rotación de credenciales internas pichu-s2s-v2

Este procedimiento aplica por pareja dirigida (`environment`, emisor, receptor). No se
comparten claves entre audiencias y no se reutiliza un `keyId` retirado.

## Preparación

1. Generar una clave aleatoria de 32 bytes fuera del repositorio y codificarla en base64url.
2. Crear un `keyId` nuevo y registrar `notBefore`, `notAfter` y estado `active` en la
   configuración segura del emisor y del receptor.
3. Mantener la clave anterior como `previous`, con una ventana de solapamiento máxima de
   15 minutos. La configuración debe contener como máximo una activa y una anterior por
   pareja.
4. Distribuir la configuración mediante el mecanismo de secretos del despliegue. Nunca
   incluir claves en Git, imágenes, logs, tickets o bases de dominio.

## Activación

1. Verificar readiness y los límites de vigencia en todos los receptores.
2. Recargar la configuración de forma atómica en los receptores.
3. Activar el nuevo `keyId` en el emisor; las nuevas firmas usan exclusivamente la clave
   activa. No se prueban claves alternativas después de un 401.
4. Confirmar métricas de solicitudes v2 aceptadas y ausencia de emisores antiguos.

## Retiro y rollback

Después de al menos 65 segundos desde la última emisión con la clave anterior, retirarla
antes de que termine el solapamiento. Si quedan emisores antiguos, detenerlos o aislarlos;
no ampliar silenciosamente la ventana.

El rollback solo puede volver a una versión compatible con v2 y a claves no revocadas.
Una clave comprometida se revoca inmediatamente, se aísla cualquier receptor que no haya
recibido la revocación y se rota la pareja afectada. No se limpian nonces ni se reactiva una
clave comprometida para recuperar disponibilidad.

## Diagnóstico seguro

Registrar únicamente `requestId`, emisor, audiencia, `keyId`, código de error y latencias.
Nunca registrar secretos, firmas completas, JWT, cuerpos ni encabezados de autenticación.
Un fallo de keyring, vigencia, nonce o MongoDB debe fallar cerrado y no ejecutar negocio.
