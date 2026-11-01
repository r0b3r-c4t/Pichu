import Image from 'next/image';
import Link from 'next/link';
import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { ArrowUpRight, ChevronRight, LockKeyhole, Maximize, Radio, Sun } from 'lucide-react';

const moduleIcons: Record<string, LucideIcon> = {
  maximize: Maximize,
  sun: Sun,
  lock: LockKeyhole,
  radio: Radio,
};

export function ScreenFrame({
  children,
  safeAreaTop = false,
}: Readonly<{ children: ReactNode; safeAreaTop?: boolean }>) {
  return (
    <main
      className={`mx-auto flex w-full max-w-[1240px] flex-col gap-5 px-4 pb-[calc(6rem+env(safe-area-inset-bottom))] sm:px-6 md:gap-6 md:px-8 lg:pb-10 xl:px-10 ${
        safeAreaTop
          ? 'pt-[calc(env(safe-area-inset-top)+1.25rem)] sm:pt-[calc(env(safe-area-inset-top)+1.5rem)] md:pt-[calc(env(safe-area-inset-top)+2rem)]'
          : 'pt-5 sm:pt-6 md:pt-8'
      }`}
    >
      {children}
    </main>
  );
}

export function Wordmark() {
  return (
    <div className="flex items-center gap-[9px]">
      <span className="h-[27px] w-[3px] rounded-sm bg-primary" />
      <span>
        <span className="block text-lg font-bold tracking-[2.6px]">PICHU</span>
        <span className="mt-0.5 block text-[8px] font-medium tracking-[1.35px] text-muted-foreground">
          CONTROL VEHICULAR
        </span>
      </span>
    </div>
  );
}

export function ConnectionBadge() {
  return (
    <span
      aria-label="Bluetooth sin conexión. Vista local activa."
      className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-border bg-card px-2.5 py-[7px] text-[9px] font-semibold tracking-[0.65px] text-muted-foreground"
    >
      <span className="size-1.5 rounded-full bg-gold" />
      SIN CONEXIÓN
    </span>
  );
}

export function ScreenTop() {
  return (
    <div className="flex min-h-12 min-w-0 items-center justify-between gap-3">
      <Wordmark />
      <ConnectionBadge />
    </div>
  );
}

export function PageTitle({
  eyebrow,
  title,
  subtitle,
}: {
  eyebrow: string;
  title: string;
  subtitle?: string;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <p className="text-[10px] font-semibold tracking-[1.5px] text-gold">{eyebrow}</p>
      <h1 className="text-[28px] font-bold tracking-[-0.7px] sm:text-[32px] lg:text-[36px]">{title}</h1>
      {subtitle ? <p className="max-w-2xl text-[13px] leading-5 text-muted-foreground sm:text-sm">{subtitle}</p> : null}
    </div>
  );
}

export function CarStage({ className = '' }: { className?: string }) {
  return (
    <div
      className={`relative h-[clamp(220px,70vw,300px)] w-full overflow-hidden rounded-[18px] border border-border bg-card sm:h-[340px] lg:h-[400px] ${className}`}
    >
      <Image
        src="/images/mazda-3-2011.jpg"
        alt="Mazda 3 Sedan 2011 en rojo, vista frontal lateral"
        fill
        priority
        sizes="(max-width: 768px) 100vw, 1280px"
        className="object-contain"
      />
      <Link
        href="/sunroof/"
        aria-label="Abrir control del sunroof"
        data-testid="sunroof-hotspot"
        className="absolute left-[52%] top-[36%] flex -translate-x-1/2 flex-col items-center gap-[5px] transition-transform active:scale-90"
      >
        <span className="flex size-11 items-center justify-center rounded-full border border-transparent transition-colors hover:border-primary">
          <span className="flex size-[25px] items-center justify-center rounded-full border border-primary">
            <span className="size-2 rounded-full bg-primary" />
          </span>
        </span>
        <span className="rounded bg-background px-[5px] py-0.5 text-[8px] font-semibold tracking-wide">
          SUNROOF
        </span>
      </Link>
      <div className="absolute bottom-3 left-3 flex items-center gap-1.5 text-[8px] font-semibold tracking-[0.85px] text-muted-foreground sm:bottom-4 sm:left-4 sm:text-[9px]">
        TOCA EL TECHO PARA CONTROLAR
        <ArrowUpRight aria-hidden="true" size={13} className="text-gold" />
      </div>
    </div>
  );
}

export function ModuleRow({
  title,
  subtitle,
  icon,
  href,
}: {
  title: string;
  subtitle: string;
  icon: keyof typeof moduleIcons;
  href?: string;
}) {
  const Icon = moduleIcons[icon];
  const row = (
    <>
      <span
        className={`flex size-[38px] shrink-0 items-center justify-center rounded-[11px] ${
          href ? 'bg-red-dark' : 'bg-secondary'
        }`}
      >
        <Icon
          aria-hidden="true"
          size={18}
          className={href ? 'text-primary-foreground' : 'text-muted-foreground'}
        />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-[13px] font-semibold">{title}</span>
        <span className="mt-1 block text-[11px] text-muted-foreground">{subtitle}</span>
      </span>
      {href ? (
        <ChevronRight aria-hidden="true" size={18} className="shrink-0 text-muted-foreground" />
      ) : (
        <span className="shrink-0 text-[8px] font-semibold tracking-wide text-muted-foreground">
          PRÓXIMAMENTE
        </span>
      )}
    </>
  );
  const className =
    'flex min-h-[76px] items-center gap-3 rounded-[14px] border border-border bg-card px-[13px] py-3 sm:min-h-[82px] sm:px-4';

  if (!href) {
    return (
      <div aria-label={`${title}, próximamente disponible`} className={`${className} opacity-[0.68]`}>
        {row}
      </div>
    );
  }

  return (
    <Link href={href} className={`${className} transition-opacity hover:opacity-80`}>
      {row}
    </Link>
  );
}

export function ActionButton({
  title,
  icon: Icon,
  variant = 'primary',
  disabled = false,
  onClick,
}: {
  title: string;
  icon: LucideIcon;
  variant?: 'primary' | 'secondary' | 'outline';
  disabled?: boolean;
  onClick: () => void;
}) {
  const variantClass =
    variant === 'primary'
      ? 'border-primary bg-primary text-primary-foreground'
      : variant === 'secondary'
        ? 'border-secondary bg-secondary text-foreground'
        : 'border-border bg-transparent text-muted-foreground';

  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={`flex min-h-14 flex-1 items-center justify-center gap-[9px] rounded-[13px] border px-3 text-[11px] font-bold tracking-[0.75px] transition-opacity hover:opacity-80 active:scale-[0.99] disabled:cursor-not-allowed disabled:opacity-45 sm:min-h-[60px] ${variantClass}`}
    >
      <Icon aria-hidden="true" size={16} />
      {title}
    </button>
  );
}

export function InfoRow({
  icon: Icon,
  label,
  value,
  last = false,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  last?: boolean;
}) {
  return (
    <div
      className={`flex min-h-[57px] items-center gap-3 ${
        last ? '' : 'border-b border-border'
      }`}
    >
      <Icon aria-hidden="true" size={17} className="shrink-0 text-gold" />
      <span className="flex-1 text-xs text-muted-foreground">{label}</span>
      <span className="text-xs font-semibold">{value}</span>
    </div>
  );
}
