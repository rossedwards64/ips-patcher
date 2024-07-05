use super::common::GenericPatch;

use std::{
    fmt::Display,
    fs::{self, File},
    io::Read,
    os::unix::fs::FileExt,
    path::{self, Path, PathBuf},
};

pub struct IPSReader {
    data: Vec<u8>,
}

impl GenericPatch for IPSReader {}

impl IPSReader {
    const IPS_HEADER: &'static str = "PATCH";
    const IPS_EOF: &'static str = "EOF";
    const MAX_PATCH_SIZE: u64 = 7_340_032;

    pub fn new(path: &Path) -> Self {
        let data = match File::open(path) {
            Ok(mut f) => {
                <Self as GenericPatch>::check_file_size(&f, Self::MAX_PATCH_SIZE);
                let mut buf: Vec<u8> = Vec::new();
                let _ = f.read_to_end(&mut buf);
                println!("Read {} bytes.", buf.len());
                buf
            }
            Err(err) => panic!("Failed to open file containing patch. {err}"),
        };

        Self { data }
    }

    pub fn read_patch(&mut self) -> Vec<IPSRecordKind> {
        self.read_sequence(0, Self::IPS_HEADER);
        self.read_sequence(self.data.len() - 3, Self::IPS_EOF);
        let mut records = Vec::new();

        while let Some(record) = self.read_ips_record() {
            println!("Found {record}");
            records.push(record);
        }

        records
    }

    fn read_ips_record(&mut self) -> Option<IPSRecordKind> {
        if self.data.len() < 8 {
            return None;
        }

        let offset = self.read_three_bytes();
        let size = self.read_two_bytes();

        if size == 0 {
            let rle_size = {
                let result = self.read_two_bytes();
                if result > 0 {
                    result
                } else {
                    panic!("RLE Encoded record cannot have an RLE size of zero.")
                }
            };

            let rle_value = self.data.remove(0);

            Some(IPSRecordKind::RLERecord {
                offset,
                rle_size,
                rle_value,
            })
        } else if size as usize <= self.data.len() - 3 {
            let data: Vec<u8> = {
                let mut buf = Vec::with_capacity(size as usize);
                self.data
                    .drain(0..size as usize)
                    .for_each(|byte| buf.push(byte));
                buf
            };

            Some(IPSRecordKind::Record { offset, data })
        } else {
            None
        }
    }

    fn read_sequence(&mut self, offset: usize, expected: &str) -> Vec<u8> {
        let sequence = self
            .data
            .drain(offset..offset + expected.len())
            .collect::<Vec<u8>>();

        if sequence != expected.as_bytes() {
            if let Ok(sequence_str) = std::str::from_utf8(&sequence) {
                panic!("Sequence \"{expected}\" was not found. Instead found \"{sequence_str}\".");
            }
        }

        sequence
    }

    fn read_two_bytes(&mut self) -> u16 {
        let bytes: Vec<_> = self.data.drain(0..2).collect();
        (u16::from(bytes[0]) << 8) | u16::from(bytes[1])
    }

    fn read_three_bytes(&mut self) -> u32 {
        let bytes: Vec<_> = self.data.drain(0..3).collect();
        (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2])
    }
}

pub struct IPSWriter {
    rom: PathBuf,
    patch: IPSPatch,
}

impl GenericPatch for IPSWriter {}

impl IPSWriter {
    const MAX_ROM_SIZE: u64 = 2_147_483_648;
    const IPS_FILE_EXT: &'static str = "ips";

    pub const fn new(rom: PathBuf, patch: IPSPatch) -> Self {
        Self { rom, patch }
    }

    pub fn write_patch(&mut self) {
        let patched_rom = self.copy_rom();

        self.patch.data.iter().for_each(|record| {
            Self::write_record(record, &patched_rom);
        });
    }

    fn write_record(record: &IPSRecordKind, patched_rom: &File) {
        match record {
            IPSRecordKind::Record { offset, data } => {
                match patched_rom.write_at(data, u64::from(*offset)) {
                    Ok(bytes) => println!("Wrote {bytes} bytes starting at offset {offset:#x}."),
                    Err(e) => eprintln!("Error writing record at offset {offset:#x}: {e}"),
                }
            }
            IPSRecordKind::RLERecord {
                offset,
                rle_size,
                rle_value,
            } => {
                let mut rle_value_buf: Vec<u8> = Vec::with_capacity(*rle_size as usize);

                for _ in 0..*rle_size {
                    rle_value_buf.push(*rle_value);
                }

                match patched_rom.write_at(&rle_value_buf, u64::from(*offset)) {
                    Ok(bytes) => {
                        println!("Wrote {bytes} bytes of value {rle_value:#x} starting at offset {offset:#x}.");
                    }
                    Err(e) => {
                        eprintln!("Error writing RLE record at offset {offset:#x}: {e}");
                    }
                }
            }
        }
    }

    fn copy_rom(&self) -> File {
        let destination_path = self.make_destination_path();

        match fs::copy(&self.rom, &destination_path) {
            Ok(_) => {
                let f = File::options()
                    .read(true)
                    .write(true)
                    .open(&destination_path)
                    .expect("Error opening copy of ROM before patching.");
                <Self as GenericPatch>::check_file_size(&f, Self::MAX_ROM_SIZE);
                f
            }
            Err(e) => panic!(
                "Error copying {} to {}: {e}",
                self.rom.to_str().unwrap(),
                destination_path.to_str().unwrap()
            ),
        }
    }

    fn make_destination_path(&self) -> PathBuf {
        let path = self.rom.to_str().map(ToString::to_string).unwrap();
        let rom_file_ext = path
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
                &self.patch.name,
            )
            .replace(Self::IPS_FILE_EXT, rom_file_ext),
        )
    }
}

pub struct IPSPatch {
    name: String,
    data: Vec<IPSRecordKind>,
}

impl IPSPatch {
    pub const fn new(name: String, data: Vec<IPSRecordKind>) -> Self {
        Self { name, data }
    }
}

pub enum IPSRecordKind {
    Record {
        offset: u32,
        data: Vec<u8>,
    },
    RLERecord {
        offset: u32,
        rle_size: u16,
        rle_value: u8,
    },
}

impl Display for IPSRecordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Record { offset, data } => {
                write!(f, "Record {{ offset: {offset:#x}, size: {} }}", data.len())
            }
            Self::RLERecord {
                offset,
                rle_size,
                rle_value,
            } => write!(
                f,
                "RLERecord {{ offset: {offset:#x}, rle_size: {rle_size}, rle_value: {rle_value} }}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    const HEADER: &[u8] = &[0x50, 0x41, 0x54, 0x43, 0x48];
    const INCORRECT_HEADER: &[u8] = &[0x51, 0x42, 0x55, 0x44, 0x49];
    const RECORD: &[u8] = &[0x0, 0x1, 0xff, 0x0, 0x1, 0x1];
    const RLE_RECORD: &[u8] = &[0x0, 0x0, 0x0, 0x0, 0x0, 0xf, 0xf, 0x1];
    const EOF: &[u8] = &[0x45, 0x4f, 0x46];
    const INCORRECT_EOF: &[u8] = &[0x46, 0x50, 0x47];

    #[test]
    fn has_correct_header() {
        let patch = make_correct_patch();

        assert!(std::panic::catch_unwind(|| {
            let mut reader = write_patch_file(&patch);
            reader.read_patch()
        })
        .is_ok());
    }

    #[test]
    fn fails_on_incorrect_header() {
        let patch = make_patch_incorrect_header();

        assert!(std::panic::catch_unwind(|| {
            let mut reader = write_patch_file(&patch);
            reader.read_patch()
        })
        .is_err());
    }

    #[test]
    fn fails_on_incorrect_eof() {
        let patch = make_patch_incorrect_eof();

        assert!(std::panic::catch_unwind(|| {
            let mut reader = write_patch_file(&patch);
            reader.read_patch()
        })
        .is_err());
    }

    #[test]
    fn records_do_not_contain_eof() {
        let patch = make_correct_patch();
        let mut reader = write_patch_file(&patch);
        let patch = reader.read_patch();
        assert!(!patch.iter().any(|record| match record {
            IPSRecordKind::Record { offset: _, data } => data.ends_with(EOF),
            IPSRecordKind::RLERecord {
                offset: _,
                rle_size: _,
                rle_value: _,
            } => false,
        }));
    }

    fn write_patch_file(data: &[u8]) -> IPSReader {
        let mut file = tempfile::Builder::new().suffix(".ips").tempfile().unwrap();
        let _ = file.write(data);
        IPSReader::new(file.path())
    }

    fn make_correct_patch() -> Vec<u8> {
        make_patch_data(Some(HEADER), Some(EOF))
    }

    fn make_patch_incorrect_header() -> Vec<u8> {
        make_patch_data(None, Some(EOF))
    }

    fn make_patch_incorrect_eof() -> Vec<u8> {
        make_patch_data(Some(HEADER), None)
    }

    fn make_patch_data(header: Option<&[u8]>, eof: Option<&[u8]>) -> Vec<u8> {
        let mut patch = Vec::new();
        patch.extend_from_slice(header.map_or(INCORRECT_HEADER, |h| h));

        for _ in 0..3 {
            patch.extend_from_slice(RECORD);
            patch.extend_from_slice(RLE_RECORD);
        }

        patch.extend_from_slice(eof.map_or(INCORRECT_EOF, |e| e));

        patch
    }
}
