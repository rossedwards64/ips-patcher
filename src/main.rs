mod patchers;

use std::path::PathBuf;

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

    if patch_path
        .extension()
        .map(|ext| ext == "ips")
        .unwrap_or(false)
    {
        let patch = {
            let mut reader = IPSReader::new(&patch_path);
            IPSPatch::new(
                patch_path
                    .file_name()
                    .and_then(|s| s.to_str().map(ToString::to_string))
                    .unwrap(),
                reader.read_patch(),
            )
        };

        IPSWriter::new(rom_path, patch).write_patch();
    } else if patch_path
        .extension()
        .map(|ext| ext == "bps")
        .unwrap_or(false)
    {
        let patch = BPSReader::new(&patch_path).read_patch();
        BPSWriter::new(rom_path, patch).write_patch();
    } else {
        panic!(
            "Invalid patch file found: {}.",
            patch_path.to_str().unwrap()
        );
    }
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
