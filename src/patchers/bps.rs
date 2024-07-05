use std::path::PathBuf;

pub struct BPSReader {
    data: Vec<u8>,
}

pub struct BPSWriter {
    rom: PathBuf,
    patch: BPSPatch,
}

pub struct BPSPatch {
    name: String,
    data: Vec<BPSRecordKind>,
}

pub enum BPSRecordKind {
    Record {},
}
