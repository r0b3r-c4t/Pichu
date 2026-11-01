# PICHU web application

PICHU is a Next.js App Router application built with React, TypeScript, and Tailwind CSS. Use pnpm for dependency management and project commands.

## Commands

```bash
pnpm dev
pnpm lint
pnpm typecheck
pnpm build
```

The production build is a static export in `out/`. Do not add runtime server features such as Server Actions or dynamic Route Handlers.

## Architecture

- Route entries and layouts live in `app/`.
- Shared UI lives in `components/`; domain behavior belongs in `features/`.
- Keep pages as Server Components by default. Add `'use client'` only where browser interaction, state, or client hooks are required.
- Use Tailwind utility classes for component styling and keep design tokens centralized in `app/globals.css`.
- Keep static images and fonts in `public/`.

The sunroof interface currently has local-only state. Do not imply that it is connected to a vehicle; backend and BLE integration are out of scope until explicitly requested.

<!-- BEGIN:nextjs-agent-rules -->

## This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->
