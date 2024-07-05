mod ips;

use std::path::PathBuf;

use clap::{arg, command, value_parser, ArgMatches};
use ips::IPSPatch;

fn main() {
    let matches = parse_args();

    let rom_path = get_matched_path("rom", &matches);
    let patch_path = get_matched_path("patch", &matches);
    let patch = {
        let mut reader = ips::IPSReader::new(&patch_path);
        IPSPatch::new(
            patch_path
                .file_name()
                .and_then(|s| s.to_str().map(ToString::to_string))
                .unwrap(),
            reader.read_patch(),
        )
    };

    ips::IPSWriter::new(rom_path, patch).write_patch();
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
