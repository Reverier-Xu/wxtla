#[macro_export]
macro_rules! declare_driver {
  ($driver:ident, $type:ty, $descriptor:ident) => {
    #[derive(Debug, Default, Clone, Copy)]
    pub struct $driver;

    impl $driver {
      pub const fn new() -> Self {
        Self
      }

      pub fn open(source: $crate::ByteSourceHandle) -> $crate::Result<$type> {
        <$type>::open(source)
      }
    }

    impl $crate::Driver for $driver {
      fn descriptor(&self) -> $crate::FormatDescriptor {
        $descriptor
      }

      fn open(
        &self, source: $crate::ByteSourceHandle, _options: $crate::OpenOptions<'_>,
      ) -> $crate::Result<Box<dyn $crate::DataSource>> {
        Ok(Box::new(Self::open(source)?))
      }
    }
  };

  ($driver:ident, $type:ty, $descriptor:ident, with_hints) => {
    #[derive(Debug, Default, Clone, Copy)]
    pub struct $driver;

    impl $driver {
      pub const fn new() -> Self {
        Self
      }

      pub fn open(source: $crate::ByteSourceHandle) -> $crate::Result<$type> {
        <$type>::open(source)
      }

      pub fn open_with_hints(
        source: $crate::ByteSourceHandle, hints: $crate::SourceHints<'_>,
      ) -> $crate::Result<$type> {
        <$type>::open_with_hints(source, hints)
      }
    }

    impl $crate::Driver for $driver {
      fn descriptor(&self) -> $crate::FormatDescriptor {
        $descriptor
      }

      fn open(
        &self, source: $crate::ByteSourceHandle, options: $crate::OpenOptions<'_>,
      ) -> $crate::Result<Box<dyn $crate::DataSource>> {
        Ok(Box::new(<$type>::open_with_hints(source, options.hints)?))
      }
    }
  };
}
