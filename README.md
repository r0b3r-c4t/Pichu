# PICHU

Repositorio de PICHU. La aplicación web existente está en [`PICHU/`](./PICHU/) y se conserva temporalmente en esa ubicación, con su configuración y documentación independientes. Su traslado a `apps/web/` será una migración posterior.

## Arquitectura objetivo

La arquitectura acordada para el backend —servicios, límites de datos, seguridad, comunicación HTTP interna, permisos BLE offline y despliegue— está documentada en [docs/backend-architecture.md](./docs/backend-architecture.md).

Esta documentación es una especificación, no una implementación: todavía no hay servicios backend, API Gateway, modelos Mongoose ni infraestructura Docker en este repositorio.