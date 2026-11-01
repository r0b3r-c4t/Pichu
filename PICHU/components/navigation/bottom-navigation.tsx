'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { House, Navigation, Radio, Settings } from 'lucide-react';

const items = [
  { href: '/', label: 'Inicio', icon: House },
  { href: '/vehicle/', label: 'Vehículo', icon: Navigation },
  { href: '/devices/', label: 'Dispositivos', icon: Radio },
  { href: '/settings/', label: 'Configuración', icon: Settings },
];

export function BottomNavigation() {
  const pathname = usePathname();

  return (
    <nav
      aria-label="Navegación principal"
      className="fixed inset-x-0 bottom-0 z-10 border-t border-border bg-background/95 pb-[env(safe-area-inset-bottom)] backdrop-blur lg:hidden"
    >
      <div className="mx-auto flex min-h-[68px] max-w-[1280px] items-center justify-around px-2 py-1 md:px-8">
        {items.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || (href !== '/' && pathname.startsWith(href));
          return (
            <Link
              key={href}
              href={href}
              aria-current={active ? 'page' : undefined}
              className={`flex min-h-14 min-w-0 flex-1 flex-col items-center justify-center gap-1 rounded-xl text-[10px] font-semibold tracking-[0.25px] transition-colors ${
                active ? 'text-primary' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Icon aria-hidden="true" size={25} strokeWidth={2} />
              <span>{label}</span>
            </Link>
          );
        })}
      </div>
    </nav>
  );
}

export function DesktopNavigation() {
  const pathname = usePathname();

  return (
    <nav aria-label="Navegación principal" className="hidden items-center gap-1 lg:flex">
      {items.map(({ href, label, icon: Icon }) => {
        const active = pathname === href || (href !== '/' && pathname.startsWith(href));
        return (
          <Link
            key={href}
            href={href}
            aria-current={active ? 'page' : undefined}
            className={`flex min-h-11 items-center gap-2 rounded-xl px-3 text-xs font-semibold transition-colors xl:px-4 ${
              active
                ? 'bg-primary/10 text-primary'
                : 'text-muted-foreground hover:bg-secondary hover:text-foreground'
            }`}
          >
            <Icon aria-hidden="true" size={17} strokeWidth={2} />
            {label}
          </Link>
        );
      })}
    </nav>
  );
}
