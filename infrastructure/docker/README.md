# MongoDB local con Docker Compose

Esta configuración levanta una sola instancia de MongoDB Community 8.0.17 para desarrollo local y crea las bases `identity_db`, `vehicle_db`, `device_db` y `automation_db`, con un usuario de aplicación independiente por base. MongoDB funciona como un replica set de un solo nodo (`pichu-rs`) para permitir transacciones multidocumento, requeridas por la verificación consistente del correo en Identity Service. El keyfile se genera automáticamente en el volumen dedicado `mongo_keyfile`, montado en `/run/mongo-keyfile/pichu-keyfile`, fuera del directorio de datos.

Las contraseñas de `.env.example` son marcadores inseguros para desarrollo. Sustitúyelas por valores locales antes de iniciar MongoDB. No uses esas credenciales ni el usuario administrador en aplicaciones o entornos compartidos.

## Requisitos previos

- Docker Desktop o Docker Engine en ejecución.
- Docker Compose v2 (`docker compose`).
- PowerShell.

## Configuración inicial

Desde la raíz del repositorio:

```powershell
Copy-Item infrastructure\docker\.env.example infrastructure\docker\.env
notepad infrastructure\docker\.env
```

Reemplaza cada valor `replace-with-local-only-...` por una contraseña local distinta. El `.env` real está cubierto por las reglas raíz de `.gitignore`; no lo agregues al control de versiones.

## Iniciar y verificar MongoDB

Ejecuta los comandos desde `infrastructure\docker`, donde Compose carga `.env`:

```powershell
Set-Location infrastructure\docker
docker compose -f compose.yml config
docker compose -f compose.yml up -d
docker compose -f compose.yml ps
docker compose -f compose.yml logs mongo
```

Espera hasta que el servicio muestre `healthy`. El entrypoint oficial crea el usuario administrador y ejecuta los scripts de `/docker-entrypoint-initdb.d` en un `mongod` temporal sin `--replSet`; después, el comando Compose inicia el servidor definitivo, configura `pichu-rs` si aún no existe y espera a que sea `PRIMARY`. El healthcheck también confirma que MongoDB es el primario escribible.

MongoDB se publica únicamente en `127.0.0.1:27018`; no queda expuesto en otras interfaces de red. Los contenedores conectados a la red privada de Compose usan el nombre `mongo` como hostname.

### Actualizar una instalación existente sin perder datos

Al activar el replica set por primera vez, conserva ambos volúmenes y recrea únicamente el contenedor. No ejecutes `down --volumes`:

```powershell
docker compose -f compose.yml up -d --force-recreate mongo
docker compose -f compose.yml ps
```

La inicialización de MongoDB detecta el volumen de datos existente y no vuelve a ejecutar los scripts de `/docker-entrypoint-initdb.d`. El comando de inicio comprueba el estado del replica set y lo inicializa automáticamente solo si aún no está configurado. No es necesario borrar ni inicializar manualmente los datos. Comprueba el primario y el estado del contenedor:

```powershell
docker compose -f compose.yml exec mongo mongosh --quiet --username pichu_local_admin --authenticationDatabase admin --password --eval "db.hello()"
docker compose -f compose.yml ps
```

El healthcheck cambiará a `healthy` cuando el nodo sea primario. El keyfile se conserva en el volumen `mongo_keyfile` y debe permanecer allí para la autenticación interna del replica set. El script de inicialización no migra automáticamente usuarios ni datos de un volumen existente.

## Conexión con MongoDB Compass

Para inspeccionar una base como aplicación, usa la credencial de servicio correspondiente y selecciona esa base como `authSource`. Por ejemplo, para Identity:

```text
mongodb://identity_user:<IDENTITY_DB_PASSWORD>@localhost:27018/identity_db?authSource=identity_db
```

Sustituye el marcador por el valor de `IDENTITY_DB_PASSWORD` en `.env`. Para las demás bases, utiliza su usuario y contraseña propios (`vehicle_user`, `device_user` o `automation_user`) y su base respectiva.
Si una contraseña contiene caracteres reservados de URI, codifícala para usarla dentro de la cadena de conexión.

El administrador local puede usarse para tareas de mantenimiento desde Compass con `authSource=admin`, pero nunca desde una aplicación. No guardes contraseñas en archivos versionados ni compartas capturas que las muestren.

## Conexiones de las aplicaciones

Dentro de la red Compose, cada servicio debe usar exclusivamente su propio usuario:

| Servicio   | URI local dentro de Docker                                                                                                  |
| ---------- | --------------------------------------------------------------------------------------------------------------------------- |
| Identity   | `mongodb://identity_user:<IDENTITY_DB_PASSWORD>@mongo:27017/identity_db?authSource=identity_db&replicaSet=pichu-rs`         |
| Vehicle    | `mongodb://vehicle_user:<VEHICLE_DB_PASSWORD>@mongo:27017/vehicle_db?authSource=vehicle_db&replicaSet=pichu-rs`             |
| Device     | `mongodb://device_user:<DEVICE_DB_PASSWORD>@mongo:27017/device_db?authSource=device_db&replicaSet=pichu-rs`                 |
| Automation | `mongodb://automation_user:<AUTOMATION_DB_PASSWORD>@mongo:27017/automation_db?authSource=automation_db&replicaSet=pichu-rs` |

Estos son ejemplos de conexión para uso futuro; esta infraestructura no configura ni modifica los microservicios. Los clientes que se ejecuten en el host pueden usar `localhost:27018` y `directConnection=true` junto con `authSource`; los clientes dentro de Docker deben usar el hostname anunciado `mongo:27017` y `replicaSet=pichu-rs`. No uses el usuario administrador ni compartas contraseñas entre servicios.

La verificación de correo de Identity Service usa transacciones MongoDB. Los reenvíos para un mismo usuario se coordinan con un lease atómico en su documento de usuario, renovado mientras se envía el correo; la invalidación y liberación del lease se confirman juntas en una transacción. Si el proceso cae, el lease vence y otro reenvío puede continuar; un propietario vencido no puede invalidar tokens después de perder la coordinación. El envío del correo y la invalidación de tokens anteriores no forman una transacción distribuida: si el proveedor acepta el correo y después falla la transacción que invalida los tokens, el correo puede haber sido entregado y los tokens anteriores pueden seguir siendo válidos. El endpoint responde de forma genérica ante ese fallo.

El registro y el reenvío limitan a cinco solicitudes por IP cada 15 minutos usando memoria local. Es una protección de instancia única: para desplegar varias instancias se deberá sustituir por una solución de rate limiting compartida.

## Detener y conservar datos

Desde `infrastructure\docker`:

```powershell
docker compose -f compose.yml down
```

Esto detiene y elimina el contenedor y la red, pero conserva los volúmenes nombrados `mongo_data` y `mongo_keyfile`.

## Eliminar los datos conscientemente

El siguiente comando elimina los volúmenes persistentes `mongo_data` (bases de datos) y `mongo_keyfile` (autenticación interna), además de todos los datos de MongoDB:

```powershell
docker compose -f compose.yml down --volumes
```

La eliminación no se puede deshacer. Úsalo solo cuando deliberadamente quieras reinicializar la instancia desde cero. El script de inicialización volverá a ejecutarse cuando se cree un volumen vacío nuevo.

## Bases, usuarios e inicialización

El archivo `mongo/init/01-create-databases.js` se monta en `/docker-entrypoint-initdb.d` de la imagen oficial. En la primera inicialización del volumen, crea cada base lógica al crear su usuario:

| Base            | Usuario           | Rol                                          |
| --------------- | ----------------- | -------------------------------------------- |
| `identity_db`   | `identity_user`   | `readWrite` únicamente sobre `identity_db`   |
| `vehicle_db`    | `vehicle_user`    | `readWrite` únicamente sobre `vehicle_db`    |
| `device_db`     | `device_user`     | `readWrite` únicamente sobre `device_db`     |
| `automation_db` | `automation_user` | `readWrite` únicamente sobre `automation_db` |

El script toma las contraseñas del entorno del contenedor. Cada cuenta recibe solamente el rol `readWrite` de su base; no recibe roles de administración.

Importante: los scripts de `/docker-entrypoint-initdb.d` se ejecutan solamente cuando MongoDB inicializa un directorio de datos vacío. No se repiten en cada arranque. El entrypoint oficial omite `--replSet` durante su inicialización temporal cuando se configuran credenciales root; por eso el script crea las cuentas de servicio y el comando de inicio configura el replica set después de arrancar el servidor definitivo. La comprobación de volumen inicializado del entrypoint busca marcadores concretos (`WiredTiger`, `journal`, `local.0` y `storage.bson`); el keyfile aislado no es uno de ellos. Aun así, el keyfile se mantiene en un volumen dedicado y externo a `/data/db`. En un volumen ya inicializado no se repiten los scripts; el mismo comando detecta un replica set ya configurado y conserva sus datos. Cambiar `.env` o editar el script no modifica usuarios existentes.

### Crear usuarios o rotar contraseñas en un volumen existente

Para rotar la contraseña de un usuario de aplicación, con el servicio iniciado, abre una sesión administrativa interactiva. El siguiente ejemplo usa el nombre de administrador predeterminado; si lo cambiaste en `.env`, usa ese nombre:

```powershell
docker compose -f compose.yml exec mongo mongosh --username pichu_local_admin --authenticationDatabase admin --password
```

`mongosh` solicitará la contraseña administrativa. En el shell, cambia la contraseña de la cuenta del servicio con el prompt seguro de `mongosh`; por ejemplo:

```javascript
db.getSiblingDB('identity_db').changeUserPassword('identity_user', passwordPrompt());
```

Ejecuta el cambio antes de actualizar `.env`. Después guarda allí la nueva contraseña, reinicia/recrea el contenedor para que el healthcheck reciba el valor nuevo y actualiza la configuración del servicio consumidor cuando exista. Cambiar solo `.env` no actualiza la contraseña almacenada en MongoDB. Repite para la base/usuario correspondientes.

Para crear un usuario adicional, conéctate como administrador y ejecuta un comando equivalente a este, reemplazando la base y el usuario:

```javascript
db.getSiblingDB('identity_db').createUser({
  user: 'identity_user',
  pwd: passwordPrompt(),
  roles: [{ role: 'readWrite', db: 'identity_db' }],
});
```

No otorgues roles globales o administrativos.

El administrador inicial se crea desde `MONGO_INITDB_ROOT_USERNAME` y `MONGO_INITDB_ROOT_PASSWORD` cuando se inicializa el volumen vacío. Para rotar su contraseña en un volumen existente, conéctate usando la contraseña actual y ejecuta `db.getSiblingDB('admin').changeUserPassword('pichu_local_admin', passwordPrompt())`; luego actualiza `.env` y recrea el contenedor. Editar el archivo por sí solo no rota la credencial persistida. Si cambias el nombre de usuario administrador, reemplaza también el nombre del ejemplo.
