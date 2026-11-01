# MongoDB local con Docker Compose

Esta configuración levanta una sola instancia de MongoDB Community 8.0.17 para desarrollo local y crea las bases `identity_db`, `vehicle_db`, `device_db` y `automation_db`, con un usuario de aplicación independiente por base.

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

Espera hasta que el servicio muestre `healthy`. El healthcheck ejecuta `mongosh` dentro del contenedor y autentica contra `admin` para hacer `ping` a MongoDB.

MongoDB se publica únicamente en `127.0.0.1:27018`; no queda expuesto en otras interfaces de red. Los contenedores conectados a la red privada de Compose usan el nombre `mongo` como hostname.

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

| Servicio   | URI local dentro de Docker                                                                              |
| ---------- | ------------------------------------------------------------------------------------------------------- |
| Identity   | `mongodb://identity_user:<IDENTITY_DB_PASSWORD>@mongo:27017/identity_db?authSource=identity_db`         |
| Vehicle    | `mongodb://vehicle_user:<VEHICLE_DB_PASSWORD>@mongo:27017/vehicle_db?authSource=vehicle_db`             |
| Device     | `mongodb://device_user:<DEVICE_DB_PASSWORD>@mongo:27017/device_db?authSource=device_db`                 |
| Automation | `mongodb://automation_user:<AUTOMATION_DB_PASSWORD>@mongo:27017/automation_db?authSource=automation_db` |

Estos son ejemplos de conexión para uso futuro; esta infraestructura no configura ni modifica los microservicios. No uses el usuario administrador ni compartas contraseñas entre servicios.

## Detener y conservar datos

Desde `infrastructure\docker`:

```powershell
docker compose -f compose.yml down
```

Esto detiene y elimina el contenedor y la red, pero conserva el volumen nombrado `mongo_data`.

## Eliminar los datos conscientemente

El siguiente comando elimina también el volumen persistente y todos los datos de MongoDB:

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

Importante: los scripts de `/docker-entrypoint-initdb.d` se ejecutan solamente cuando MongoDB inicializa un directorio de datos vacío. No se repiten en cada arranque. Cambiar `.env` o editar el script no modifica usuarios existentes en un volumen ya inicializado.

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
