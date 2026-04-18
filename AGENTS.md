# Repository Guidelines

## Project Structure & Module Organization
- `docs/architecture/`: platform and subsystem architecture docs, including `aegis-architecture-design.md`, `aegis-sensor-architecture.md`, and `aegis-transport-architecture.md`.
- `docs/技术方案/`: implementation-focused technical specs, including `sensor-final技术解决方案.md`, `transport-final技术解决方案.md`, and `总技术解决方案.md`.
- Treat these files as paired sources of truth. A change to Sensor or Transport usually requires updates in both its architecture doc and its matching technical solution doc.

## Build, Test, and Development Commands
- No repo-local build or automated test toolchain is checked in. Validation is document-based.
- List tracked docs: `rg --files docs`
- Inspect heading structure: `rg -n '^#|^##|^###' docs`
- Review a section in context: `sed -n '1,120p' docs/architecture/aegis-sensor-architecture.md`
- Review pending edits before commit: `git diff -- AGENTS.md docs/`

## Writing Style & Naming Conventions
- Use Markdown with ATX headings (`#`, `##`, `###`), fenced code blocks, and tables for metrics, constraints, and comparisons.
- Preserve the repository’s current style: Chinese primary content, with English product names or technical terms only where precision matters.
- Keep filenames stable. Architecture docs follow `aegis-<domain>-architecture.md`; technical specs follow `<domain>-final技术解决方案.md`.
- When editing existing docs, preserve section numbering, TOC links, anchors, and diagram/code block structure unless the change explicitly requires restructuring.

## Testing Guidelines
- Manually verify every edited document renders correctly in Markdown preview.
- Re-check internal consistency: headings, anchor targets, tables, and cross-document references.
- For subsystem changes, confirm the platform-level architecture doc is still aligned with the subsystem docs.

## Commit & Pull Request Guidelines
- This repository currently has no commit history. Start with Conventional Commit style, for example: `docs(sensor): refine event pipeline and response flow`.
- Keep each commit scoped to one topic or subsystem.
- PRs should include: purpose, impacted files, cross-document sync notes, and any open assumptions that still need confirmation.

## Security & Confidentiality
- These documents describe internal architecture. Do not commit secrets, credentials, real hostnames, customer identifiers, or private certificates.
- Label uncertain content as an assumption or draft requirement instead of presenting it as a settled design decision.
