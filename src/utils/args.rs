use crate::utils::statics::{
    ARGS,
    LOGGER
};
use crate::utils::logger::{
    LOGLevel,
    OutputType
};

pub fn set_args() -> clap::Command {
    // Check if color is disabled and if so, do the same in clap
    let color_choice: clap::ColorChoice;
    let lock = LOGGER.read().unwrap();
    if lock.get_color() {
        color_choice = clap::ColorChoice::Auto;
    } else {
        color_choice = clap::ColorChoice::Never;
    }
    drop(lock);

    let binname: &str;
    if cfg!(feature = "yara_x") {
        binname = "YPScanX"
    } else {
        binname = "YPScan"
    }

    // Build the args
    clap::Command::new(binname)
        .version(crate::utils::constants::PKG_VERSION)
        .disable_version_flag(true)
        .color(color_choice)
        .styles(crate::utils::constants::CLAP_STYLING)
        .arg(
            clap::Arg::new("ansi-encoding")
                .long("ansi-encoding")
                .num_args(0)
                .global(true)
                .action(clap::ArgAction::SetTrue)
                .display_order(21)
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
                .display_order(22)
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
                .display_order(23)
                .help("Enable extream logging for debugging")
        )
        .arg(
            clap::Arg::new("only-alerts")
                .long("only-alerts")
                .num_args(0)
                .global(true)
                .conflicts_with_all(["debug","trace"])
                .action(clap::ArgAction::SetTrue)
                .display_order(11)
                .help("Filter output level to alerts and higher")
        )
        .arg(
            clap::Arg::new("no-color")
                .long("no-color")
                .num_args(0)
                .global(true)
                .action(clap::ArgAction::SetTrue)
                .display_order(12)
                .help("Switch off console color")
        )
        .arg(
            clap::Arg::new("no-output")
                .long("no-output")
                .num_args(0)
                .global(true)
                .conflicts_with_all(["csv-output","json-output"])
                .action(clap::ArgAction::SetTrue)
                .display_order(13)
                .help("Switch off console output")
        )
        .arg(
            clap::Arg::new("csv-output")
                .long("csv-output")
                .num_args(0)
                .global(true)
                .conflicts_with("json-output")
                .action(clap::ArgAction::SetTrue)
                .display_order(14)
                .help("Change console logging to csv")
        )
        .arg(
            clap::Arg::new("json-output")
                .long("json-output")
                .num_args(0)
                .global(true)
                .conflicts_with("csv-output")
                .action(clap::ArgAction::SetTrue)
                .display_order(15)
                .help("Change console logging to json")
        )
        .arg(
            clap::Arg::new("file-name")
                .long("file-name")
                .global(true)
                .value_name("FILENAME")
                .value_parser(clap::value_parser!(String))
                .conflicts_with("no-log")
                .display_order(16)
                .help("Sets a custom filename to the log file")
        )
        .arg(
            clap::Arg::new("no-log")
                .long("no-log")
                .num_args(0)
                .global(true)
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(["file-name","csv-log","json-log"])
                .display_order(17)
                .help("Switch off file output")
        )
        .arg(
            clap::Arg::new("csv-log")
                .long("csv-log")
                .num_args(0)
                .global(true)
                .conflicts_with("json-log")
                .action(clap::ArgAction::SetTrue)
                .display_order(18)
                .help("Change log file format to csv")
        )
        .arg(
            clap::Arg::new("json-log")
                .long("json-log")
                .num_args(0)
                .global(true)
                .conflicts_with("csv-log")
                .action(clap::ArgAction::SetTrue)
                .display_order(19)
                .help("Change log file format to json")
        )
        .arg(
            clap::Arg::new("syslog")
                .long("syslog")
                .global(true)
                .value_name("CONNECTION")
                .value_parser(clap::value_parser!(String))
                .display_order(20)
                .help("Enable logging to syslog (format: udp://192.168.1.5:514)")
        )
        .subcommand_required(true)
        .subcommand(
            clap::command!("scan")
            .about("starts a file scan, by default scan all drives with 100 MB size limit and uses 1/2 CPUs")
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
                    .help("Display all match reasons instead of only 4")
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
                    .short('P')
                    .long("power")
                    .num_args(0)
                    .action(clap::ArgAction::SetTrue)
                    .conflicts_with("threads")
                    .display_order(6)
                    .help("Power scan mode, uses all avaliable cpu")
            )
            .arg(
                clap::Arg::new("no-progress")
                    .short('q')
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
            .arg(
                clap::Arg::new("yara-path")
                    .short('y')
                    .long("yara-path")
                    .value_name("PATH")
                    .display_order(8)
                    .help("Path to yara rule files (defaults to yara next to the executable)")
            )
            .arg(
                clap::Arg::new("iocs-path")
                    .short('i')
                    .long("iocs-path")
                    .value_name("PATH")
                    .display_order(9)
                    .help("Path to iocs files (defaults to iocs next to the executable)")
            )
            .arg(
                clap::Arg::new("config-path")
                    .short('c')
                    .long("config-path")
                    .value_name("PATH")
                    .display_order(10)
                    .help("Path to config files (defaults to config next to the executable)")
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
    )
}

pub fn setup_logger() {
    use std::io::IsTerminal;
    // Check all logger related arguments and modify logger for each change
    if ARGS.get_flag("debug") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfilter(LOGLevel::Debug);
        drop(lock);
    }
    if ARGS.get_flag("trace") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfilter(LOGLevel::Trace);
        drop(lock);
    }
    if ARGS.get_flag("only-alerts") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfilter(LOGLevel::Alert);
        drop(lock);
    }
    if ARGS.get_flag("no-output") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logtoconsole(false);
        drop(lock);
    }
    if ARGS.get_flag("csv-output") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logconsoletype(OutputType::CSV);
        drop(lock);
    }
    if ARGS.get_flag("json-output") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logconsoletype(OutputType::JSON);
        drop(lock);
    }
    if let Ok(Some(file_name)) = ARGS.try_get_one::<String>("file-name") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logtofile(true,Some(file_name.to_string()));
        drop(lock);
    }
    if ARGS.get_flag("no-log") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logtofile(false,None);
        drop(lock);
    }
    if ARGS.get_flag("csv-log") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfiletype(OutputType::CSV);
        drop(lock);
    }
    if ARGS.get_flag("json-log") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfiletype(OutputType::JSON);
        drop(lock);
    }
    if ARGS.get_flag("ansi-encoding") && !std::io::stdout().is_terminal() {
        let mut lock = LOGGER.write().unwrap();
        lock.set_ansi(true);
        drop(lock);
    }
    if let Ok(Some(syslog_connection)) = ARGS.try_get_one::<String>("syslog") {
        let mut lock = LOGGER.write().unwrap();
        let mut connection_string = syslog_connection.split("://");
        if connection_string.clone().count() == 2 {
            let protocol = connection_string.next().unwrap();
            let connection = connection_string.next().unwrap();
            match lock.create_syslog(protocol,connection,1) {
                Ok(_) => {
                    crate::LOGDEBUG!("Successfully configured syslog to {}://{}",protocol,connection);
                }
                Err(e) => {
                    crate::LOGERROR!("{e}");
                }
            }
        } else {
            crate::LOGERROR!("Unable to read syslog connection string. Make sure to use either udp://IP:PORT or tcp://IP:PORT");
        }
        drop(lock);
    }
}