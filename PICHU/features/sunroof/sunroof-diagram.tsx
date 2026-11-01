'use client';

import { useEffect, useRef } from 'react';
import type { SunroofStatus } from '@/types/sunroof';

const MOVEMENT_DURATION_MS = 2200;

export function SunroofDiagram({ status }: { status: SunroofStatus }) {
  const panelRef = useRef<HTMLSpanElement>(null);
  const animationRef = useRef<Animation | null>(null);

  useEffect(() => {
    const panel = panelRef.current;
    if (!panel) return;

    if (status === 'stopped' || status === 'unknown') {
      animationRef.current?.pause();
      return;
    }

    const target = status === 'opening' || status === 'open' ? -22 : 0;
    const transform = window.getComputedStyle(panel).transform;
    const current = transform === 'none' ? 0 : new DOMMatrixReadOnly(transform).m42;

    if (status === 'open' || status === 'closed') {
      animationRef.current?.cancel();
      animationRef.current = null;
      panel.style.transform = `translateY(${target}px)`;
      return;
    }

    animationRef.current?.cancel();
    const duration = MOVEMENT_DURATION_MS * Math.abs((target - current) / 22);
    if (duration === 0) {
      panel.style.transform = `translateY(${target}px)`;
      return;
    }

    const animation = panel.animate(
      [
        { transform: `translateY(${current}px)` },
        { transform: `translateY(${target}px)` },
      ],
      { duration, easing: 'ease-out', fill: 'forwards' },
    );
    animationRef.current = animation;
    animation.onfinish = () => {
      panel.style.transform = `translateY(${target}px)`;
      animation.cancel();
      if (animationRef.current === animation) animationRef.current = null;
    };
  }, [status]);

  useEffect(() => () => animationRef.current?.cancel(), []);

  return (
    <section
      aria-label="Diagrama animado del movimiento del sunroof"
      className="flex min-h-[294px] flex-col items-center justify-center gap-[15px] rounded-[18px] border border-border bg-card py-5 sm:min-h-[330px] lg:min-h-[min(60vh,520px)]"
    >
      <p className="text-[9px] font-semibold tracking-[1.3px] text-muted-foreground">VISTA SUPERIOR</p>
      <div className="flex h-[202px] w-[118px] flex-col items-center rounded-[54px] border border-border bg-background pt-6 sm:h-[230px] sm:w-[134px] sm:rounded-[62px] sm:pt-7">
        <div className="h-[34px] w-[70px] rounded-[24px] bg-secondary opacity-75 sm:h-10 sm:w-[82px]" />
        <div className="mt-3 flex h-[81px] w-[75px] items-center justify-center border-x border-[#383838] sm:h-[95px] sm:w-[87px]">
          <div className="relative flex h-[52px] w-[47px] items-center justify-center overflow-hidden rounded-[9px] bg-secondary sm:h-[62px] sm:w-[55px]">
            <span className="absolute inset-0 bg-gold/40" />
            <span
              ref={panelRef}
              className="relative h-11 w-[43px] rounded-[7px] border border-primary bg-red-dark sm:h-[52px] sm:w-[51px]"
              style={{ transform: 'translateY(0px)' }}
            />
          </div>
        </div>
        <div className="mt-3 h-[25px] w-[67px] rounded-[14px] bg-secondary opacity-75 sm:h-7 sm:w-[78px]" />
      </div>
      <p className="text-[9px] font-semibold tracking-[0.8px] text-muted-foreground">
        {status === 'opening'
          ? 'DESPLAZANDO HACIA ATRÁS'
          : status === 'closing'
            ? 'CERRANDO EL PANEL'
            : status === 'open'
              ? 'PANEL ABIERTO'
              : status === 'stopped'
                ? 'MOVIMIENTO DETENIDO'
                : 'PANEL CERRADO'}
      </p>
    </section>
  );
}
