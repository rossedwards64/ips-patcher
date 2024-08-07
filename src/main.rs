mod patchers;

use std::path::{Path, PathBuf};

use clap::{arg, command, value_parser, ArgMatches};

use patchers::{
    bps::{BPSReader, BPSWriter},
    common::{GenericPatchReader, GenericPatchWriter},
    ips::{IPSPatch, IPSReader, IPSWriter},
};

fn main() {
    let matches = parse_args();

    let rom_path = get_matched_path("rom", &matches);
    let patch_path = get_matched_path("patch", &matches);

    if check_file_extension(&patch_path, "ips") {
        let patch = {
            let records = IPSReader::new(&patch_path).read_patch();
            let patch_name = patch_path
                .file_name()
                .and_then(|s| s.to_str().map(ToString::to_string))
                .unwrap();

            IPSPatch::new(patch_name, records)
        };

        IPSWriter::new(rom_path, patch).write_patch();
    } else if check_file_extension(&patch_path, "bps") {
        let patch = BPSReader::new(&patch_path).read_patch();
        BPSWriter::new(rom_path, patch).write_patch();
    } else {
        panic!(
            "Invalid patch file found: {}.",
            patch_path.to_str().unwrap()
        );
    }
}

fn check_file_extension(path: &Path, expected: &str) -> bool {
    path.extension().is_some_and(|actual| expected == actual)
}

fn get_matched_path(id: &str, matches: &ArgMatches) -> PathBuf {
    matches.get_one(id).map_or_else(
        || panic!("Couldn't find path with ID: {id}"),
        std::clone::Clone::clone,
    )
}

#[allow(clippy::cognitive_complexity)]
fn parse_args() -> ArgMatches {
    command!()
        .arg(
            arg!(-r --rom <ROM> "ROM to apply patch to")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-p --patch <PATCH> "Patch to apply")
                .required(true)
                .value_parser(value_parser!(PathBuf)),
        )
        .get_matches()
}
