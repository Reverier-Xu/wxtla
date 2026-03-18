# Implementation Workflow

## 0. Non-negotiable rules

The migration workflow for `wxtla` is strict.

1. Finish one format before starting the next.
2. Do not write a "demo" parser just to make tests pass.
3. Add or update `formats/`-backed tests whenever a format changes.
4. Commit each complete implementation step before moving on.
5. Keep library code panic-free; use structured errors instead.
6. Use `keramics` and external projects only for on-disk semantics, field meanings, and corner-case research, not as architectural templates.

## 0.1 Reference policy

Research for a format should begin with the in-repo references that define the current expected behavior:

1. `keramics`: `../keramics`
2. `regressor`: `../regressor`

Use those sources to understand:

- the currently supported feature surface
- fixture expectations
- metadata fields that matter to downstream consumers
- parser-visible behavior already assumed elsewhere

After that, compare against mature external implementations and public specifications to find missing version branches, integrity details, sparse/backing behavior, and unusual edge cases.

Do not copy `keramics` architecture. Only parser semantics, format docs, and test expectations are valid references. Runtime design, crate dependencies, and state-machine read patterns from `keramics` are explicitly out of scope for reuse.

## 1. Required development loop per format

For each format, the next agent should follow this order:

1. Research the format in `keramics`, format documentation, and mature external references.
   - start with `keramics` and `regressor`
   - then compare against mature external implementations to identify gaps
2. Identify the full feature set that matters for read-only support, including version differences, integrity fields, sparse behavior, backing chains, metadata side tables, and odd edge cases.
   - write down anything that current in-repo references do not already cover well
3. Implement one coherent step at a time.
   - prefer reusing existing `wxtla` source, cache, resolver, and typed interface layers over format-local one-offs
4. Extend fixture coverage and synthetic tests to match the newly implemented behavior.
5. Run the required checks:
   - `cargo +nightly fmt --all`
   - `cargo +nightly fmt --all -- --check`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo test --workspace --all-features`
6. Create an atomic gitmoji commit.
7. Only then start the next step or the next format.

## 2. Format ordering

The active migration order is now image-first after the already-landed volume layer.

### Completed

- `mbr`
- `gpt`
- `apm`
- `ewf`
- `qcow`
- `vhd`

### Current next target

- `vhdx`

### Remaining image targets after that

- `vmdk`
- `udif`
- `sparseimage`
- `sparsebundle`
- `pdi`
- `splitraw` runtime image surface (probe groundwork already exists)

### After images

- `tar` / `zip`
- filesystem formats (`fat`, `ntfs`, `ext`, `hfs`, `xfs`)
- `lvm2`

## 3. Quality policy for parser code

The following behaviors are mandatory:

- validate every fixed-size structure before decoding it
- reject unsupported feature flags early and explicitly
- use `checked_add`, `checked_mul`, and `try_from` for all offset, size, and count arithmetic
- treat mirrored metadata structures as consistency checks rather than assuming they are valid
- represent sparse and parent-backed data explicitly instead of silently materializing incorrect zeros
- keep caches bounded and format-local
- prefer extending existing `wxtla` infrastructure over introducing duplicate parser-local plumbing
- never take a dependency on `keramics` crates, even when a similar helper already exists there

## 4. Testing policy

`formats/` fixtures are the primary regression source. If the fixture set does not yet cover a case, add synthetic tests that exercise:

- malformed headers
- bad checksums
- sparse/unallocated reads
- backing-chain fallback
- compressed allocation units
- version-specific branches
- mirrored metadata disagreement

Synthetic tests are not a substitute for fixture coverage, but they are required when real fixtures are not yet available for an edge case.

## 5. Handoff expectation

The next agent should read, at minimum:

- `docs/development-plan.md`
- `docs/architecture.md`
- `docs/format-inventory.md`
- this file

Then continue from the next unimplemented format in the order listed here, preserving the same discipline of complete steps, fixture-backed testing, and atomic commits.
