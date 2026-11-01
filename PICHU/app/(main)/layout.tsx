import type { ReactNode } from 'react';
import { BottomNavigation, DesktopNavigation } from '@/components/navigation/bottom-navigation';
import { ScreenTop } from '@/components/pichu-ui';

export default function MainLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <div className="min-h-dvh bg-background text-foreground">
      <header className="mx-auto w-full max-w-[1320px] px-4 pt-[calc(env(safe-area-inset-top)+1rem)] sm:px-6 md:px-8 md:pt-8 xl:px-10">
        <div className="flex items-center justify-between gap-4">
          <ScreenTop />
          <DesktopNavigation />
        </div>
      </header>
      {children}
      <BottomNavigation />
    </div>
  );
}
