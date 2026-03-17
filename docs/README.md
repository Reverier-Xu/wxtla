# WXTLA Planning Docs

These documents lock the current direction for `wxtla`.

- `development-plan.md`: scope, boundaries, approved dependency set, concurrent read architecture, and migration phases.
- `format-inventory.md`: complete format inventory gathered from `keramics` and `regressor`, with proposed WXTLA ownership.

Current design decisions:

1. `wxtla` is a parser backend, not a session/VFS/runtime layer.
2. All complex parser logic stays in-house.
3. Only `tar` and `zip` may use mature parser libraries directly.
4. Other third-party crates are limited to mature infrastructure building blocks.
5. Dependency count stays intentionally small, with version requirements pinned at the minor level.
