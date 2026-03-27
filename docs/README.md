# WXTLA Planning Docs

These documents lock the current direction for `wxtla`.

- `development-plan.md`: scope, boundaries, approved dependency set, concurrent read architecture, and migration phases.
- `architecture.md`: current crate architecture, module layering, and parser implementation patterns.
- `unified-source-model.md`: planned replacement for the split image/volume/filesystem/archive driver model.
- `format-inventory.md`: complete format inventory gathered from `keramics` and `regressor`, with proposed WXTLA ownership.
- `feature-completion-plan.md`: current unsupported or narrowly gated parser features that still need fixture-backed completion work.
- `implementation-workflow.md`: non-negotiable migration workflow and quality rules for the next agent.
- `apfs-phase-5a-plan.md`: APFS-specific research notes, staged fixture inventory, and a completeness-first implementation roadmap.

Current design decisions:

1. `wxtla` is a parser backend, not a session/VFS/runtime layer.
2. All complex parser logic stays in-house.
3. Only `tar` and `zip` may use mature parser libraries directly.
4. Other third-party crates are limited to mature infrastructure building blocks.
5. Dependency count stays intentionally small, with version requirements pinned at the minor level.
6. Every format is migrated to completion before the next format starts; no demo-grade partial drivers.
7. Library code must return structured errors instead of panicking.
8. `formats/` fixtures are mandatory for regression coverage whenever a format is implemented or extended.
9. Format research starts with `keramics` and `regressor`, then checks other mature implementations for missing cases.
10. `keramics` parser semantics are useful references, but its architecture and crates are not reusable in `wxtla`.
11. New work should prefer extending existing `wxtla` infrastructure instead of copying helpers from external projects.
