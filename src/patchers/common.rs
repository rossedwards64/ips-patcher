use std::path::{self, Path, PathBuf};

pub trait GenericPatch {
    fn name(&self) -> &str;
}

pub trait GenericPatchReader {
    type Patch;

    fn new(path: &Path) -> Self;
    fn read_patch(&mut self) -> Self::Patch;
    fn data(&mut self) -> &mut Vec<u8>;

    fn read_sequence(&mut self, offset: usize, expected: &str) -> Vec<u8> {
        let sequence = self
            .data()
            .drain(offset..offset + expected.len())
            .collect::<Vec<u8>>();

        if sequence != expected.as_bytes() {
            if let Ok(sequence_str) = std::str::from_utf8(&sequence) {
                panic!("Sequence \"{expected}\" was not found. Instead found \"{sequence_str}\".");
            }
        }

        sequence
    }
}

pub trait GenericPatchWriter {
    type Patch: GenericPatch;

    fn new(source: PathBuf, patch: Self::Patch) -> Self;
    fn write_patch(&mut self);
    fn source(&self) -> &Path;
    fn patch(&self) -> &Self::Patch;
    fn file_ext() -> &'static str;

    fn make_target_path(&self) -> PathBuf {
        let path = self.source().to_str().map(ToString::to_string).unwrap();
        let source_file_ext = path
            .get(path.rfind('.').expect("ROM should have a file extension.") + 1..path.len())
            .unwrap();

        PathBuf::from(
            path.replace(
                path.get(
                    path.rfind(path::MAIN_SEPARATOR)
                        .expect("Didn't find a separator in path.")
                        + 1..path.len(),
                )
                .unwrap(),
                self.patch().name(),
            )
            .replace(Self::file_ext(), source_file_ext),
        )
    }
}
