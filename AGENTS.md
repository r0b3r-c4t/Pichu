# PICHU Engineering Guide

This file is the primary repository-wide guide for coding agents. Follow it together with the approved ticket and the current code. The existing `PICHU/AGENTS.md` adds frontend-specific instructions for that subtree and must also be followed when working there.

## Project Overview

PICHU is a vehicle management and automation system initially developed for a personal 2011 Mazda 3 2.0 automatic sedan.

The system must support future growth without unnecessary overengineering.

The root `README.md` and `docs/backend-architecture.md` describe the intended architecture. They are not evidence that every described service or feature is already implemented. Inspect the current code and ticket before making claims or changes.

## Technology Stack

The repository is a pnpm monorepo. The root `package.json` requires Node.js `>=24.14.0` and pins pnpm `12.16.1`.

The backend uses Node.js, TypeScript, Fastify, MongoDB, Mongoose, and Zod. Docker Compose provides the local MongoDB environment. The existing frontend in `PICHU/` uses Next.js, React, TypeScript, Tailwind CSS, PWA support, and Capacitor. Use only dependencies present in the relevant package manifest; do not infer that a technology is available from this overview.

Repository configuration uses strict TypeScript (`tsconfig.base.json`), ESLint (`eslint.config.mjs`), and Prettier (`.prettierrc.json`). Prettier uses semicolons, single quotes, trailing commas, a 100-character print width, two-space indentation, and LF line endings. The frontend has its own TypeScript and ESLint configuration.

## Architecture and Service Boundaries

The following are architectural boundaries for implementation, not a claim that every component is complete:

- **Identity Service:** authentication, users, credentials, and sessions.
- **Vehicle Service:** vehicles, ownership, memberships, and permissions.
- **Device Service:** physical device identity, credentials, linking, and revocation.
- **Automation Service:** modules, automation rules, and reported states.
- **API Gateway:** public HTTP entry point and cross-cutting request handling.
- **`packages/contracts`:** shared DTOs and transport contracts only.

Each service owns its domain and database. The local Compose setup may host the services' separate logical databases on one MongoDB deployment; that does not permit cross-service collection access. Services must not read or write another service's database directly. Use the owning service's approved API for cross-domain data and authorization.

Avoid circular service dependencies. Shared contracts must not contain persistence access or business logic. Do not add microservices or broaden service responsibilities without project-owner approval. Follow `docs/backend-architecture.md` for the intended dependency direction, while checking the current ticket and implementation for actual status.

## Security

- Never treat a client-supplied `userId` as proof of identity. Derive identity from verified authentication context.
- Authentication and authorization are separate concerns. Enforce authorization at the appropriate domain boundary and scope resource operations to authenticated users with verified ownership, membership, or explicitly granted permissions.
- Never log or expose secrets, passwords, tokens, private keys, or sensitive payloads.
- Protect internal service communication with the approved service-authentication mechanism. Caller names or other plain headers alone do not authenticate a service.
- A textual device identifier does not prove cryptographic identity, and BLE pairing does not grant application authorization.
- Prevent replay attacks wherever the protocol or operation requires it.
- Preserve credential and device-revocation requirements; never bypass revocation checks to make a flow succeed.

## Vehicle and Physical Safety

PICHU may eventually control an ESP32 connected to vehicle components, including the sunroof. Treat physical actuator operations as safety-critical.

- Never assume software timeouts alone provide adequate safety.
- Require safe hardware behavior on boot, reset, and communication loss.
- Preserve OEM safety mechanisms.
- Do not implement actuator control without explicit ticket approval.
- Do not introduce unsafe relay activation behavior.

## Coding Standards

- Follow the conventions and abstractions already present in the relevant package.
- Keep TypeScript strict and use explicit, accurate types; avoid weakening types to bypass errors.
- Prefer Zod schemas for transport validation where consistent with the existing service and contracts.
- Keep transport, domain, and persistence concerns separated.
- Prefer existing utilities over new dependencies and avoid unnecessary abstractions.
- Handle errors explicitly and consistently; do not hide operational failures behind success-shaped responses.
- Add or update documentation when a change materially affects an architectural decision or operational behavior.

## Testing and Validation

- Add positive, negative, and boundary tests for changed behavior.
- Cover security-sensitive failures and test concurrency and idempotency where relevant.
- Run only applicable scripts that exist in the relevant `package.json`; inspect that manifest rather than assuming root scripts exist for build or tests.
- Root scripts currently include `pnpm lint`, `pnpm typecheck`, and `pnpm format:check`. The root does not define a test or build script.
- `pnpm format` rewrites the workspace; do not use it as a check or format unrelated files. Prefer a scoped formatter invocation only when appropriate and authorized.
- Report tests that were skipped, unavailable, or not run. Never claim a test passed unless it was executed.
- Do not modify or weaken tests merely to conceal a failure.

## Ticket Workflow

Work on one approved ticket at a time and do not expand its scope without approval.

Before changing code:

1. Inspect the relevant implementation, tests, and package scripts.
2. Identify the files and behavior affected.
3. Confirm the ticket boundary and preserve existing local changes.
4. Report conflicts, ambiguous requirements, or overlap with another agent before proceeding.

After changes, summarize the behavior and files changed, report validation results and remaining risks, then stop and await review.

## Git and Repository Safety

Unless the project owner explicitly authorizes otherwise:

- Do not run `git add`, commit, push, or switch branches.
- Do not discard, overwrite, or revert existing changes, including untracked work.
- Do not modify `.env` files or expose secrets.
- Do not install dependencies.
- Do not perform destructive database operations.
- Do not change infrastructure.

Preserve all existing uncommitted work. Before editing, inspect `git status` and relevant diffs. If a change would overlap with work in progress, stop and coordinate rather than editing around it.

## Agent Collaboration

- **ChatGPT:** technical orchestration, planning, and review.
- **OpenAI Codex:** structured ticket implementation, audits, and refactoring.
- **GitHub Copilot:** day-to-day coding assistance, autocomplete, and small approved changes.
- **Project owner:** final approval of architectural changes, scope, and commits.

Agents must not edit the same files concurrently. Do not modify another agent's in-progress work; coordinate or wait if the requested change overlaps.

## Design Philosophy

Build secure, maintainable software using professional conventions. Prefer incremental development, clear responsibilities, and complexity justified by an approved requirement.
