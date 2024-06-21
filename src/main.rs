mod ips;

use std::path::PathBuf;

use clap::{arg, command, value_parser, ArgMatches};

fn main() {
    let matches = parse_args();

    let rom_path = get_matched_path("rom", &matches);
    let patch_path = get_matched_path("patch", &matches);
    let patch = {
        let mut reader = ips::IPSReader::new(&patch_path);
        reader.read_patch()
    };

    let writer = ips::IPSWriter::new(rom_path, patch_path, patch);
}

fn get_matched_path(id: &str, matches: &ArgMatches) -> PathBuf {
    match matches.get_one::<PathBuf>(id) {
        Some(path) => path.to_path_buf(),
        None => panic!("Couldn't find path with ID: {id}"),
    }
}

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
