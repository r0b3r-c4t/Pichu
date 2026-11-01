import Link from 'next/link';

export default function NotFound() {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center gap-4 bg-background p-5 text-center text-foreground">
      <h1 className="text-xl font-bold">Esta pantalla no existe.</h1>
      <Link href="/" className="rounded-lg px-4 py-3 text-primary hover:underline">
        Volver al inicio
      </Link>
    </main>
  );
}
