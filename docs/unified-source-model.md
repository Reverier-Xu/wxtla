# Unified Source Model

## 0. Problem statement

The current `wxtla` surface works well for simple formats, but it splits opened
results into four unrelated families:

- `Image`
- `VolumeSystem`
- `FileSystem`
- `Archive`

That split becomes awkward once a format can expose several logical views of the
same underlying data. APFS is the immediate example, but the same pattern will
recur in Btrfs, ZFS, VMFS, VSS-like snapshot layers, modern encrypted
containers, and even some image formats with internal snapshots.

The recurring features are not APFS-specific. They are shared capabilities:

- one opened format can expose multiple child views
- child views can be volumes, snapshots, subvolumes, datasets, or partitions
- a view can expose bytes, a namespace, tables, or several of them at once
- open-time credentials and selectors apply to many formats, not just one
- file content is no longer just `open_file`; streams, forks, ADS, resource
  forks, and xattr-backed payloads need one generic model

Adding one custom surface per advanced format would duplicate the same ideas in
slightly different APIs.

## 1. Core design shift

The current byte-level `DataSource` is still the correct primitive for random
access bytes, but it is too narrow to be the only public surface.

The long-term model should therefore distinguish between:

1. `ByteSource`
   - positional immutable bytes
   - the current `DataSource` role
2. `DataSource`
   - one opened logical view of a parsed format
   - can expose bytes, a namespace, tables, and child views
3. `Driver`
   - one format-specific opener that always returns a `DataSource`

During migration, the current trait name can stay as a compatibility alias, but
architecturally it should be treated as `ByteSource`.

## 2. Proposed traits

The trait names below describe the target model. They are intentionally generic
enough for APFS, Btrfs, ZFS, VMFS, partition maps, archives, and table stores.

```rust
pub trait ByteSource: Send + Sync {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn size(&self) -> Result<u64>;
    fn capabilities(&self) -> ByteSourceCapabilities;
    fn telemetry_name(&self) -> &'static str;
}

pub type ByteSourceHandle = Arc<dyn ByteSource>;

pub trait Driver: Send + Sync {
    fn descriptor(&self) -> FormatDescriptor;
    fn open(&self, source: ByteSourceHandle, options: OpenOptions<'_>)
        -> Result<Box<dyn DataSource>>;
}

pub trait DataSource: Send + Sync {
    fn descriptor(&self) -> FormatDescriptor;
    fn facets(&self) -> DataSourceFacets;

    fn byte_source(&self) -> Option<ByteSourceHandle> {
        None
    }

    fn namespace(&self) -> Option<&dyn NamespaceSource> {
        None
    }

    fn table_source(&self) -> Option<&dyn TableSource> {
        None
    }

    fn views(&self) -> Result<Vec<DataViewRecord>> {
        Ok(Vec::new())
    }

    fn open_view(
        &self,
        selector: &DataViewSelector,
        options: OpenOptions<'_>,
    ) -> Result<Box<dyn DataSource>>;

    fn reopen(&self, options: OpenOptions<'_>) -> Result<Box<dyn DataSource>>;
}

pub trait NamespaceSource: Send + Sync {
    fn root_node_id(&self) -> NamespaceNodeId;
    fn node(&self, node_id: &NamespaceNodeId) -> Result<NamespaceNodeRecord>;
    fn read_dir(&self, directory_id: &NamespaceNodeId)
        -> Result<Vec<NamespaceDirectoryEntry>>;
    fn data_streams(&self, node_id: &NamespaceNodeId)
        -> Result<Vec<NamespaceStreamRecord>>;
    fn open_stream(
        &self,
        node_id: &NamespaceNodeId,
        stream_id: &NamespaceStreamId,
    ) -> Result<ByteSourceHandle>;
}
```

`TableSource` remains relevant, but it becomes one optional facet of a unified
opened `DataSource` rather than an entirely separate top-level world.

## 3. Open options and credentials

The current `SourceHints` model is useful but too small. Advanced formats need a
generic open-time option carrier, for example:

```rust
pub struct OpenOptions<'a> {
    pub hints: SourceHints<'a>,
    pub credentials: &'a [Credential<'a>],
    pub selector: Option<DataViewSelector>,
    pub verification: VerificationPolicy,
}

pub enum Credential<'a> {
    Password(&'a str),
    RecoveryPassword(&'a str),
    KeyData(&'a [u8]),
    NamedKey(&'a str, &'a [u8]),
}
```

This replaces format-specific mutable unlock APIs such as
`unlock_with_password(&mut self, ...)`. Reopening with more credentials is a
better fit for a read-only, immutable parser backend.

## 4. Views as the common abstraction

Advanced formats differ in terminology, but not in structure.

- GPT exposes partition views
- QCOW exposes snapshot views
- APFS exposes volume views, then snapshot views
- Btrfs exposes subvolume and snapshot views
- ZFS exposes dataset and snapshot views
- VMFS can expose logical datastores or snapshot-like views

Those should all go through one view catalog:

```rust
pub struct DataViewRecord {
    pub id: DataViewId,
    pub kind: DataViewKind,
    pub name: Option<String>,
    pub parent_id: Option<DataViewId>,
    pub tags: Vec<DataViewTag>,
}
```

The common fields stay small, while `tags` carry selector-friendly metadata such
as `uuid`, `role`, `xid`, `subvol_id`, `dataset`, or `guid`.

That keeps the core generic without hard-coding APFS concepts into shared
traits.

## 5. Namespace unification

`FileSystem` and `Archive` are currently almost the same abstraction with
different type names. That duplication will grow once APFS, NTFS, HFS, and
future filesystems need richer stream/fork behavior.

`NamespaceSource` should therefore unify:

- filesystems
- archives
- future structured container formats that behave like directory trees

The important change is replacing `open_file` with a stream catalog:

- default data stream
- named data streams
- resource forks
- xattr-backed streams
- alternate implementation-defined payloads

That gives one generic route for:

- NTFS ADS
- HFS resource forks
- APFS named forks and xattr streams
- archive entries that only have a single unnamed stream

## 6. How existing domains map into the new model

### 6.1 Images

An image driver returns a `DataSource` with a byte facet.

- `byte_source()` -> logical image bytes
- `views()` -> internal snapshots when the format supports them

### 6.2 Partition and volume systems

A partition map returns a `DataSource` that mainly exposes child views.

- `views()` -> partitions or logical volumes
- each opened view -> byte facet for the sliced volume

### 6.3 Filesystems and archives

A filesystem or archive returns a `DataSource` with a namespace facet.

- `namespace()` -> directory/file tree
- `views()` -> snapshots, subvolumes, datasets, or volume-group peers when the
  format supports them

### 6.4 Table and database formats

A database returns a `DataSource` with a table facet.

- `table_source()` -> rows, schemas, typed cells
- large blobs can still be opened as `ByteSource`s from table cells

## 7. Why this is better than format-specific side APIs

This model avoids several future problems:

- APFS does not need one custom container API while Btrfs, ZFS, and VMFS invent
  their own parallel versions later
- snapshots, subvolumes, partitions, and datasets share one selector model
- byte-oriented formats and namespace-oriented formats can still coexist cleanly
- stream/fork handling is unified across NTFS, HFS, APFS, and archives
- credentials and integrity policy become generic open-time concerns instead of
  ad hoc methods on random formats

## 8. Migration strategy

The refactor should be incremental rather than disruptive.

1. Treat the current `DataSource` as the byte primitive in documentation and
   design discussions.
2. Introduce the new `Driver`, `DataSource`, and `NamespaceSource` traits beside
   the current domain traits.
3. Add adapter wrappers:
   - `Image` -> `DataSource` with byte facet
   - `VolumeSystem` -> `DataSource` with view catalog
   - `FileSystem` / `Archive` -> `DataSource` with namespace facet
4. Port the first modern multi-view format, which should now be APFS, directly
   to the new model.
5. Gradually retire `ImageDriver`, `VolumeSystemDriver`, `FileSystemDriver`, and
   `ArchiveDriver` once existing formats are wrapped or ported.

## 9. Immediate consequence for APFS and later formats

APFS should be implemented as the first real consumer of this unified model, not
as a one-off exception.

Under this design:

- the APFS container is a `DataSource` with child views for volumes
- an opened APFS volume is a `DataSource` with a namespace facet
- snapshots are just child views of that volume
- system/data volume groups are expressed through view metadata and higher-level
  namespace helpers, not APFS-specific top-level traits

The same shape then works for Btrfs, ZFS, VMFS, and future modern
copy-on-write filesystems.
