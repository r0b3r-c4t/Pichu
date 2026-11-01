import Link from 'next/link';
import { ArrowLeft, WifiOff } from 'lucide-react';

export default function OfflinePage() {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center bg-background px-6 py-12 text-center text-foreground">
      <div className="flex max-w-md flex-col items-center">
        <div className="mb-6 flex size-16 items-center justify-center rounded-2xl border border-border bg-card">
          <WifiOff aria-hidden="true" size={28} className="text-gold" />
        </div>
        <p className="text-[10px] font-semibold tracking-[1.5px] text-gold">PICHU · VISTA LOCAL</p>
        <h1 className="mt-2 text-2xl font-bold tracking-tight">Sin conexión</h1>
        <p className="mt-3 text-sm leading-6 text-muted-foreground">
          No pudimos cargar esta pantalla. Las pantallas principales guardadas pueden seguir
          disponibles, pero el control del vehículo requiere una conexión nativa que aún no está
          configurada.
        </p>
        <Link
          href="/"
          className="mt-7 flex min-h-12 items-center gap-2 rounded-xl border border-border bg-card px-5 text-sm font-semibold transition-colors hover:bg-secondary"
        >
          <ArrowLeft aria-hidden="true" size={17} />
          Ir al inicio
        </Link>
      </div>
    </main>
  );
}
