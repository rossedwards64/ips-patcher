use std::{
    fmt::Display,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

static IPS_HEADER: &str = "PATCH";
static IPS_EOF: &str = "EOF";

pub struct IPSReader {
    data: Vec<u8>,
}

impl IPSReader {
    pub fn new(path: &Path) -> Self {
        let data = match File::open(path) {
            Ok(mut f) => {
                let mut buf: Vec<u8> = vec![];
                let _ = f.read_to_end(&mut buf);
                buf
            }
            Err(err) => panic!("Failed to open file containing patch. {err}"),
        };

        Self { data }
    }

    pub fn read_patch(&mut self) -> Vec<IPSRecordKind> {
        self.read_sequence(0, IPS_HEADER);
        self.read_sequence(self.data.len() - 3, IPS_EOF);
        let mut records = Vec::new();

        while let Some(record) = self.read_ips_record() {
            println!("Found {}", record);
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

            Some(IPSRecordKind::Record { offset, size, data })
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
        ((bytes[0] as u16) << 8) | bytes[1] as u16
    }

    fn read_three_bytes(&mut self) -> u32 {
        let bytes: Vec<_> = self.data.drain(0..3).collect();
        ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32
    }
}

pub struct IPSWriter {
    rom: File,
    patch_filename: String,
    patch: Vec<IPSRecordKind>,
}

impl IPSWriter {
    pub fn new(rom: PathBuf, patch_path: PathBuf, patch: Vec<IPSRecordKind>) -> Self {
        Self {
            rom: File::open(rom).expect("Could not open ROM {rom}."),
            patch_filename: patch_path
                .file_name()
                .expect("Failed to get file name of patch {patch_path}.")
                .to_str()
                .expect("Failed to convert {patch_path} to a String.")
                .to_string(),
            patch,
        }
    }

    pub fn write_patch(&mut self) {
        unimplemented!()
    }
}

pub enum IPSRecordKind {
    Record {
        offset: u32,
        size: u16,
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
            Self::Record {
                offset,
                size,
                data: _,
            } => {
                write!(f, "Record {{ offset: {:#x}, size: {} }}", offset, size)
            }
            Self::RLERecord {
                offset,
                rle_size,
                rle_value,
            } => write!(
                f,
                "RLERecord {{ offset: {:#x}, rle_size: {}, rle_value: {} }}",
                offset, rle_size, rle_value
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
    const EOF: &[u8] = &[0x45, 0x4f, 0x46];
    const INCORRECT_EOF: &[u8] = &[0x46, 0x50, 0x47];

    #[test]
    fn has_correct_header() {
        assert!(std::panic::catch_unwind(|| {
            let mut reader = write_patch_file(make_correct_patch());
            reader.read_patch()
        })
        .is_ok());
    }

    #[test]
    fn fails_on_incorrect_header() {
        assert!(std::panic::catch_unwind(|| {
            let mut reader = write_patch_file(make_patch_incorrect_header());
            reader.read_patch()
        })
        .is_err());
    }

    #[test]
    fn fails_on_incorrect_eof() {
        assert!(std::panic::catch_unwind(|| {
            let mut reader = write_patch_file(make_patch_incorrect_eof());
            reader.read_patch()
        })
        .is_err());
    }

    #[test]
    fn records_do_not_contain_eof() {
        let mut reader = write_patch_file(make_correct_patch());
        let patch = reader.read_patch();
        assert!(patch
            .iter()
            .filter(|record| match record {
                IPSRecordKind::Record {
                    offset: _,
                    size: _,
                    data,
                } => data.ends_with(EOF),
                IPSRecordKind::RLERecord {
                    offset: _,
                    rle_size: _,
                    rle_value: _,
                } => false,
            })
            .collect::<Vec<_>>()
            .is_empty());
    }

    fn write_patch_file(data: Vec<u8>) -> IPSReader {
        let mut file = tempfile::Builder::new().suffix(".ips").tempfile().unwrap();
        let _ = file.write(&data);
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
        patch.extend_from_slice(match header {
            Some(h) => h,
            None => INCORRECT_HEADER,
        });

        for _ in 0..3 {
            patch.extend_from_slice(RECORD)
        }

        patch.extend_from_slice(match eof {
            Some(e) => e,
            None => INCORRECT_EOF,
        });

        patch
    }
}
