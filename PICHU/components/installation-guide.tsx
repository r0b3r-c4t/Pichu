import { Download, ExternalLink } from 'lucide-react';

export function InstallationGuide() {
  return (
    <section className="rounded-2xl border border-border bg-card p-4 sm:p-5">
      <div className="flex items-start gap-3">
        <span className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-red-dark">
          <Download aria-hidden="true" size={18} className="text-primary-foreground" />
        </span>
        <div className="min-w-0">
          <h2 className="text-sm font-bold">Instalar PICHU</h2>
          <p className="mt-1 text-xs leading-[18px] text-muted-foreground">
            Agrégala a tu pantalla de inicio para abrirla como aplicación. Se requiere HTTPS, excepto
            en localhost.
          </p>
        </div>
      </div>

      <details className="group mt-3 border-t border-border pt-3">
        <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-3 text-xs font-semibold [&::-webkit-details-marker]:hidden">
          Instrucciones según tu dispositivo
          <ExternalLink
            aria-hidden="true"
            size={15}
            className="shrink-0 text-gold transition-transform group-open:rotate-45"
          />
        </summary>
        <ul className="flex flex-col gap-3 pb-1 pt-2 text-xs leading-[18px] text-muted-foreground">
          <li>
            <span className="font-semibold text-foreground">Android:</span> en Chrome, abre el menú
            y elige «Instalar aplicación» o «Agregar a pantalla principal».
          </li>
          <li>
            <span className="font-semibold text-foreground">iPhone y iPad:</span> en Safari, toca
            Compartir y elige «Agregar a pantalla de inicio». No se requiere Web Bluetooth.
          </li>
          <li>
            <span className="font-semibold text-foreground">Windows y macOS:</span> usa la opción
            «Instalar» del menú de Chrome o Edge. En macOS Sonoma o posterior, Safari permite
            «Agregar al Dock».
          </li>
        </ul>
      </details>

      <p className="mt-3 border-t border-border pt-3 text-[11px] leading-[17px] text-muted-foreground">
        Sin conexión solo están disponibles las pantallas públicas guardadas. La aplicación no
        guarda credenciales ni datos privados y todavía no puede controlar el ESP32 desde el
        navegador.
      </p>
    </section>
  );
}
