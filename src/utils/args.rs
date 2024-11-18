use std::sync::LazyLock;
use clap::ArgMatches;

use crate::VERSION;

use super::statics::LOGGER;

// Styling and colors
pub const CLAP_STYLING: clap::builder::styling::Styles = clap::builder::styling::Styles::styled()
    .header(clap_cargo::style::HEADER)
    .usage(clap_cargo::style::USAGE)
    .literal(clap_cargo::style::LITERAL)
    .placeholder(clap_cargo::style::PLACEHOLDER)
    .error(clap_cargo::style::ERROR)
    .valid(clap_cargo::style::VALID)
    .invalid(clap_cargo::style::INVALID);

// Main args variable
pub static ARGS: LazyLock<ArgMatches> = LazyLock::new(||{
    // Check if color is disabled and if so, do the same in clap
    let color_choice: clap::ColorChoice;
    let lock = LOGGER.read().unwrap();
    if lock.get_color() {
        color_choice = clap::ColorChoice::Auto;
    } else {
        color_choice = clap::ColorChoice::Never;
    }
    drop(lock);

    let cmd = clap::Command::new("YPScan")
        .version(VERSION)
        .color(color_choice)
        .bin_name("YPScan")
        .styles(CLAP_STYLING)
        .arg(
            clap::Arg::new("ansi-encoding")
                    .long("ansi-encoding")
                    .num_args(0)
                    .global(true)
                    .action(clap::ArgAction::SetTrue)
                    .display_order(16)
                    .help("Enable encoding using windows ansi pages, only works in non tty")
        )
        .arg(
            clap::Arg::new("debug")
                    .short('d')
                    .long("debug")
                    .num_args(0)
                    .global(true)
                    .conflicts_with_all(["trace","only-alerts"])
                    .action(clap::ArgAction::SetTrue)
                    .display_order(17)
                    .help("Enable more informative logging for debugging")
        )
        .arg(
            clap::Arg::new("trace")
                    .short('v')
                    .long("trace")
                    .num_args(0)
                    .global(true)
                    .conflicts_with_all(["debug","only-alerts"])
                    .action(clap::ArgAction::SetTrue)
                    .display_order(18)
                    .help("Enable extream logging for debugging")
        )
        .arg(
            clap::Arg::new("only-alerts")
                .long("only-alerts")
                .num_args(0)
                .global(true)
                .conflicts_with_all(["debug","trace"])
                .action(clap::ArgAction::SetTrue)
                .display_order(8)
                .help("Filter output level to alerts and higher")
        )
        .arg(
            clap::Arg::new("no-color")
                .long("no-color")
                .num_args(0)
                .global(true)
                .action(clap::ArgAction::SetTrue)
                .display_order(9)
                .help("Switch off console color")
        )
        .arg(
            clap::Arg::new("no-output")
                .long("no-output")
                .num_args(0)
                .global(true)
                .conflicts_with_all(["csv-output","json-output"])
                .action(clap::ArgAction::SetTrue)
                .display_order(10)
                .help("Switch off console output")
        )
        .arg(
            clap::Arg::new("csv-output")
                .long("csv-output")
                .num_args(0)
                .global(true)
                .conflicts_with("json-output")
                .action(clap::ArgAction::SetTrue)
                .display_order(11)
                .help("Change console logging to csv")
        )
        .arg(
            clap::Arg::new("json-output")
                .long("json-output")
                .num_args(0)
                .global(true)
                .conflicts_with("csv-output")
                .action(clap::ArgAction::SetTrue)
                .display_order(12)
                .help("Change console logging to json")
        )
        .arg(
            clap::Arg::new("no-log")
                .long("no-log")
                .num_args(0)
                .global(true)
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(["csv-log","json-log"])
                .display_order(13)
                .help("Switch off file output")
        )
        .arg(
            clap::Arg::new("csv-log")
                .long("csv-log")
                .num_args(0)
                .global(true)
                .conflicts_with("json-log")
                .action(clap::ArgAction::SetTrue)
                .display_order(14)
                .help("Change log file format to csv")
        )
        .arg(
            clap::Arg::new("json-log")
                .long("json-log")
                .num_args(0)
                .global(true)
                .conflicts_with("csv-log")
                .action(clap::ArgAction::SetTrue)
                .display_order(15)
                .help("Change log file format to json")
        )
        .subcommand_required(true)
        .subcommand(
            clap::command!("scan")
            .about("starts a file scan, by default scan all drives with 150 MB size limit and uses 1/2 CPUs")
            .arg(
                clap::Arg::new("all-drives")
                    .short('a')
                    .long("all-drives")
                    .num_args(0)
                    .action(clap::ArgAction::SetTrue)
                    .display_order(0)
                    .help("Scan all drives including removable (in windows only)")
            )
            .arg(
                clap::Arg::new("all-reasons")
                    .short('r')
                    .long("all-reasons")
                    .num_args(0)
                    .action(clap::ArgAction::SetTrue)
                    .display_order(1)
                    .help("Display all match reasons instead of only 9")
            )
            .arg(
                clap::Arg::new("path")
                    .short('p')
                    .long("path")
                    .value_name("PATH")
                    .display_order(2)
                    .help("Path to be scanned instead of all fixed drives")
            )
            .arg(
                clap::Arg::new("no-size")
                    .short('n')
                    .long("no-size")
                    .num_args(0)
                    .action(clap::ArgAction::SetTrue)
                    .display_order(3)
                    .help("Removes file size limit. Increased RAM usage possible depending on yara rules.")
            )
            .arg(
                clap::Arg::new("size")
                    .short('s')
                    .long("size")
                    .value_name("NUMBER")
                    .value_parser(clap::value_parser!(u64))
                    .display_order(4)
                    .help("Max size filter (in KB) to ignore large files in scan")
            )
            .arg(
                clap::Arg::new("threads")
                    .short('t')
                    .long("threads")
                    .value_name("NUMBER")
                    .value_parser(clap::value_parser!(u8))
                    .conflicts_with("power")
                    .display_order(5)
                    .help("Number of threads to use in scan")
            )
            .arg(
                clap::Arg::new("power")
                    .long("power")
                    .num_args(0)
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with("threads")
                    .display_order(6)
                    .help("Power scan mode, uses all avaliable cpu")
            )
            .arg(
                clap::Arg::new("no-progress")
                    .long("no-progress")
                    .num_args(0)
                    .action(clap::ArgAction::SetTrue)
                    .default_value_ifs([
                        ("no-output", "true", Some("true")),
                        ("csv-output", "true", Some("true")),
                        ("json-output", "true", Some("true")),
                        ("ansi-encoding", "true", Some("true")),
                    ])
                    .display_order(7)
                    .help("Disable progress display and tracking")
            )
        )
        .subcommand(
            clap::command!("encrypt")
                .about("encrypts yara file in order to avoid false positive AV detections")
                .arg(
                    clap::Arg::new("file")
                        .index(1)
                        .value_name("FILE")
                        .help("Path to file to be encrypted")
                )
                .arg(
                    clap::Arg::new("output-path")
                        .short('o')
                        .long("output-path")
                        .value_name("PATH")
                        .help("Path to output encrypted files")
                )
        )
        .subcommand(
            clap::command!("decrypt")
                .about("decrypts an encrypted yara file back to its original form")
                .arg(
                    clap::Arg::new("file")
                        .index(1)
                        .value_name("FILE")
                        .help("Path to file to be decrypted")
                )
                .arg(
                    clap::Arg::new("output-path")
                        .short('o')
                        .long("output-path")
                        .value_name("PATH")
                        .help("Path to output decrypted files")
                )
        );
    cmd.get_matches()
});