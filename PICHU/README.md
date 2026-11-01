# PICHU

Aplicación web de PICHU para consultar el vehículo y explorar la interfaz de control del sunroof.

## Requisitos

- Node.js 22 o posterior (requisito de Capacitor 8).
- pnpm.

## Desarrollo

```bash
pnpm install
pnpm dev
```

La aplicación estará disponible en `http://localhost:3000`.

## Validación y exportación estática

```bash
pnpm lint
pnpm typecheck
pnpm build
```

Next.js genera la exportación estática en `out/`. El build también genera `out/sw.js` con el inventario de archivos públicos que precarga el service worker.

## Progressive Web App

La aplicación incluye un manifest estático (`/manifest.webmanifest`), iconos instalables, una pantalla offline y un service worker. Publica el contenido de `out/` en el directorio raíz de un sitio con HTTPS. El service worker no se registra en desarrollo; `localhost` es la excepción segura del navegador.

La caché está versionada por versión y recursos del build. Precarga solo páginas y archivos públicos generados en `out/`; al activarse una actualización se eliminan las cachés antiguas. Si hay una nueva versión mientras la aplicación está abierta, PICHU ofrece actualizar y recarga después de la confirmación.

La caché de navegación es network-first con páginas públicas guardadas como respaldo. Los recursos estáticos del build usan cache-first. Las solicitudes a API, otros orígenes, métodos distintos de GET y respuestas privadas no se almacenan. No se guardan tokens, credenciales BLE ni información del vehículo.

### Instalación y límites de plataforma

- **Android:** Chrome y otros navegadores compatibles pueden ofrecer «Instalar aplicación» o «Agregar a pantalla principal».
- **iPhone/iPad:** instala desde Safari con Compartir → «Agregar a pantalla de inicio». La disponibilidad y presentación pueden variar por versión de iOS/iPadOS y navegador.
- **Windows:** Chrome y Edge permiten instalar desde el menú del navegador.
- **macOS:** Chrome/Edge ofrecen instalación desde el menú; Safari permite agregar al Dock en macOS Sonoma o posterior.
- La instalación y el service worker requieren HTTPS, salvo `localhost`. Sin conexión se pueden abrir las pantallas públicas que ya están guardadas; no se garantiza la navegación en navegadores que no soporten service workers.
- Web Bluetooth no se utiliza. PICHU todavía no controla el ESP32 ni implementa comunicación BLE; esa integración requerirá Capacitor y APIs nativas.

El estado del sunroof es local y no se conserva al recargar la página. No hay backend ni comunicación Bluetooth con el vehículo.

## Aplicaciones nativas con Capacitor

PICHU mantiene una sola interfaz Next.js/React. Capacitor 8 empaqueta la exportación estática de Next (`out/`) en los proyectos nativos de `android/` e `ios/`; `capacitor.config.ts` declara `com.pichu.vehicle` como identificador de aplicación. La PWA sigue siendo un destino web independiente.

Después de instalar dependencias, genera la web, actualiza ambos proyectos nativos y abre Android Studio:

```bash
pnpm install
pnpm run cap:android
```

Para compilar e instalar directamente en un dispositivo o emulador Android conectado:

```bash
pnpm run cap:run:android
```

En macOS, abre el proyecto de Xcode o compila y ejecuta para un simulador/dispositivo iOS:

```bash
pnpm run cap:ios
pnpm run cap:run:ios
```

`pnpm run cap:sync` vuelve a generar la exportación web y sincroniza los recursos y plugins en Android e iOS. Después de cada cambio web, ejecuta ese comando antes de abrir o compilar el proyecto nativo. `pnpm run build` por sí solo no copia los recursos a los proyectos nativos.

### Requisitos y limitaciones nativas

- **Android:** Android Studio, un JDK compatible (17 o posterior) y Android SDK 36 para compilar este proyecto (mínimo Android 7.0 / API 24); Gradle y el wrapper están en `android/`. Revisa `local.properties` localmente, sin incorporarlo al control de versiones.
- **iOS:** el proyecto Xcode está generado en `ios/`, pero compilar, ejecutar en simulador y firmar requiere macOS y Xcode. En Windows se puede sincronizar el proyecto, no compilarlo ni firmarlo.
- Capacitor sirve la exportación estática localmente dentro del WebView. El service worker de la PWA no se registra dentro del contenedor nativo. No configures `server.url` para desarrollo ni apuntes el contenedor publicado a un servidor remoto.
- La pantalla **Configuración** muestra si PICHU está en navegador, Android nativo o iOS nativo.

### Servicios de plataforma

`services/platform-service.ts` centraliza la detección de plataforma; `services/bluetooth-service.ts` define el contrato de BLE y reporta que el plugin aún no está configurado; `services/secure-storage-service.ts` define el contrato de almacenamiento seguro y falla explícitamente mientras no exista un adaptador nativo. La interfaz no invoca APIs nativas directamente. Los iconos y pantallas de inicio nativas usan la identidad visual de PICHU.

No se agregó un plugin BLE, no se conecta a un vehículo y no se guardan credenciales. Para implementar BLE después, añade un plugin nativo compatible y su adaptador dentro de `BluetoothService`. Para datos sensibles, implementa `SecureStorageService` con almacenamiento protegido del sistema operativo; no uses caché web, `localStorage` ni preferencias sin cifrar.
