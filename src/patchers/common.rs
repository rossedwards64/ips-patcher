use std::{
    fs::File,
    io::{Seek, SeekFrom},
};

pub trait GenericPatch {
    fn check_file_size(mut f: &File, max_size: u64) {
        if f.seek(SeekFrom::End(0))
            .is_ok_and(|filesize| filesize >= max_size)
        {
            panic!("Patch must be smaller than {max_size}.")
        } else {
            let _ = f.seek(SeekFrom::Start(0));
        }
    }
}
