use std::{
    fs::File,
    io::{Read, Write},
    mem,
    path::{Path, PathBuf},
};

use super::common::{GenericPatch, GenericPatchReader, GenericPatchWriter};

pub struct BPSReader {
    name: String,
    data: Vec<u8>,
}

impl GenericPatchReader for BPSReader {
    type Patch = BPSPatch;

    fn new(path: &Path) -> Self {
        let name = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap()
            .to_string();

        let data = match File::open(path) {
            Ok(mut f) => {
                let mut buf = vec![];
                let _ = f.read_to_end(&mut buf);
                println!("Read {} bytes.", buf.len());
                buf
            }
            Err(err) => panic!("Failed to open file containing patch. {err}"),
        };

        Self { name, data }
    }

    fn read_patch(&mut self) -> BPSPatch {
        self.read_sequence(0, Self::BPS_HEADER);
        let source_size = self.decode();
        let target_size = self.decode();
        let metadata = self.read_metadata();
        let actions = {
            let mut actions = vec![];
            while let Some(action) = self.read_action() {
                actions.push(action);
            }
            actions
        };
        let source_checksum =
            u32::try_from(self.decode()).expect("Source checksum was truncated when decoded.");
        let target_checksum =
            u32::try_from(self.decode()).expect("Target checksum was truncated when decoded.");
        let patch_checksum =
            u32::try_from(self.decode()).expect("Patch checksum was truncated when decoded.");

        BPSPatch::new(
            self.name.clone(),
            actions,
            metadata,
            patch_checksum,
            source_checksum,
            source_size,
            target_checksum,
            target_size,
        )
    }

    fn data(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
}

impl BPSReader {
    const BPS_HEADER: &'static str = "BPS1";

    fn decode(&mut self) -> u64 {
        let mut result: u64 = 0;
        let mut shift: u64 = 1;

        loop {
            let x = self.data.remove(0);
            println!("Data: {x:#x}, Shift: {shift}");
            result += u64::from(x & 0x7f) * shift;

            if x & 0x80 != 0 {
                break;
            }

            shift <<= 7;
            result += shift;
        }

        result
    }

    fn read_metadata(&mut self) -> Option<BPSMetadata> {
        let size = self.decode();

        if size != 0 {
            let data: Vec<_> = self
                .data
                .drain(
                    0..usize::try_from(size)
                        .expect("Metadata size value was truncated after being decoded."),
                )
                .collect();

            Some(BPSMetadata {
                size,
                data: String::from_utf8(data)
                    .expect("Metadata should be a UTF-8 conforming string."),
            })
        } else {
            None
        }
    }

    fn read_action(&mut self) -> Option<BPSAction> {
        let data = self.decode();
        let action = {
            let length = (data >> 2) + 1;
            let action = data & 3;
            println!("Data: {data:#x}, Action: {action}, Length: {length}");
            BPSAction {
                payload: data,
                length,
                action: ACTIONS[action as usize],
            }
        };

        if self.is_at_end() {
            None
        } else {
            Some(action)
        }
    }

    fn is_at_end(&self) -> bool {
        self.data.len() <= (mem::size_of::<u32>() * 3)
    }
}

pub struct BPSMetadata {
    size: u64,
    data: String,
}

pub struct BPSAction {
    payload: u64,
    length: u64,
    action: BPSActionFn,
}

impl BPSAction {
    fn do_action(
        &mut self,
        output_offset: &mut usize,
        source: &mut [u8],
        source_relative_offset: &mut usize,
        target: &mut [u8],
        target_relative_offset: &mut usize,
    ) {
        (self.action)(
            self.payload,
            self.length,
            output_offset,
            source,
            source_relative_offset,
            target,
            target_relative_offset,
        );
    }
}

type BPSActionFn = fn(
    data: u64,
    length: u64,
    output_offset: &mut usize,
    source: &mut [u8],
    source_relative_offset: &mut usize,
    target: &mut [u8],
    target_relative_offset: &mut usize,
);

fn source_read(
    _data: u64,
    mut length: u64,
    output_offset: &mut usize,
    source: &mut [u8],
    _source_relative_offset: &mut usize,
    target: &mut [u8],
    _target_relative_offset: &mut usize,
) {
    while length != 0 {
        target[*output_offset] = source[*output_offset];
        length -= 1;
    }
}

fn target_read(
    data: u64,
    mut length: u64,
    output_offset: &mut usize,
    _source: &mut [u8],
    _source_relative_offset: &mut usize,
    target: &mut [u8],
    _target_relative_offset: &mut usize,
) {
    while length != 0 {
        target[*output_offset] = u8::try_from(data).expect("Data was truncated when decoded.");
        *output_offset += 1;
        length -= 1;
    }
}

fn source_copy(
    data: u64,
    mut length: u64,
    output_offset: &mut usize,
    source: &mut [u8],
    source_relative_offset: &mut usize,
    target: &mut [u8],
    _target_relative_offset: &mut usize,
) {
    *source_relative_offset += get_offset(data);

    while length != 0 {
        target[*output_offset] = source[*source_relative_offset];
        *output_offset += 1;
        *source_relative_offset += 1;
        length -= 1;
    }
}

fn target_copy(
    data: u64,
    mut length: u64,
    output_offset: &mut usize,
    _source: &mut [u8],
    source_relative_offset: &mut usize,
    target: &mut [u8],
    target_relative_offset: &mut usize,
) {
    *target_relative_offset += get_offset(data);

    while length != 0 {
        target[*output_offset] = target[*target_relative_offset];
        *output_offset += 1;
        *source_relative_offset += 1;
        length -= 1;
    }
}

fn get_offset(data: u64) -> usize {
    usize::try_from((if data & 1 != 0 { -1 } else { 1 }) * (data as i64 >> 1))
        .expect("Decoded value was truncated when converted to an offset.")
}

const ACTIONS: [BPSActionFn; 4] = [source_read, target_read, source_copy, target_copy];

pub struct BPSPatch {
    name: String,
    actions: Vec<BPSAction>,
    metadata: Option<BPSMetadata>,
    patch_checksum: u32,
    source_checksum: u32,
    source_size: u64,
    target_checksum: u32,
    target_size: u64,
}

impl BPSPatch {
    pub const fn new(
        name: String,
        actions: Vec<BPSAction>,
        metadata: Option<BPSMetadata>,
        patch_checksum: u32,
        source_checksum: u32,
        source_size: u64,
        target_checksum: u32,
        target_size: u64,
    ) -> Self {
        Self {
            name,
            actions,
            metadata,
            patch_checksum,
            source_checksum,
            source_size,
            target_checksum,
            target_size,
        }
    }
}

impl GenericPatch for BPSPatch {
    fn name(&self) -> &str {
        &self.name
    }
}

pub struct BPSWriter {
    source: PathBuf,
    patch: BPSPatch,
}

impl BPSWriter {
    const BPS_FILE_EXT: &'static str = "bps";

    fn verify_checksums(&self, source: &[u8], target: &[u8]) {
        let actual_source_checksum = crc32fast::hash(source);
        let actual_target_checksum = crc32fast::hash(target);
        let source_valid = actual_source_checksum == self.patch.source_checksum;
        let target_valid = actual_target_checksum == self.patch.target_checksum;

        if !source_valid {
            panic!(
                "Source checksum is invalid.\nExpected: {}, Actual: {}.\nNot applying patch.",
                self.patch.source_checksum, actual_source_checksum
            )
        } else if !target_valid {
            panic!(
                "Target checksum is invalid.\nExpected: {}, Actual: {}.\nNot applying patch.",
                self.patch.source_checksum, actual_source_checksum
            )
        }
    }
}

impl GenericPatchWriter for BPSWriter {
    type Patch = BPSPatch;

    fn new(source: PathBuf, patch: BPSPatch) -> Self {
        Self { source, patch }
    }

    fn write_patch(&mut self) {
        let mut source = {
            let mut f = File::options()
                .read(true)
                .write(true)
                .open(&self.source)
                .expect("Error opening source ROM.");
            let mut buf = vec![];
            let _ = f.read_to_end(&mut buf);
            buf
        };

        let target_name = self.make_target_path();
        let mut target_file = match File::create_new(&target_name) {
            Ok(f) => f,
            Err(err) => panic!("Failed to create target file. {err}"),
        };

        let mut target = {
            let mut buf = vec![];
            let _ = target_file.read_to_end(&mut buf);
            buf
        };

        let mut output_offset: usize = 0;
        let mut source_relative_offset: usize = 0;
        let mut target_relative_offset: usize = 0;

        self.patch.actions.iter_mut().for_each(|action| {
            assert!(source_relative_offset < source.len(), "Source offset {source_relative_offset:#x} cannot be larger than source file size {}.", source.len());
            assert!(target_relative_offset < output_offset, "Target offset {target_relative_offset:#x} cannot be larger than output offset {output_offset:#x}.");

            action.do_action(
                &mut output_offset,
                &mut source,
                &mut source_relative_offset,
                &mut target,
                &mut target_relative_offset,
            );
        });

        self.verify_checksums(&source, &target);

        match target_file.write(&target) {
            Ok(size) => println!(
                "Successfully wrote {size} bytes to {}.",
                &target_name.to_str().unwrap()
            ),
            Err(err) => panic!("Error writing to target. {err}"),
        }
    }

    fn source(&self) -> &Path {
        &self.source
    }

    fn patch(&self) -> &Self::Patch {
        &self.patch
    }

    fn file_ext() -> &'static str {
        Self::BPS_FILE_EXT
    }
}
