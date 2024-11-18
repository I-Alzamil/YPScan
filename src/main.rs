// Load modules
pub mod commands;
pub mod modules;
pub mod utils;

use std::{
    env,
    process::exit,
    io::IsTerminal
};

use owo_colors::OwoColorize;

use commands::{
    scan::initialize_scan,
    encrypt::initialize_encrypt,
    decrypt::initialize_decrypt
};

use utils::{
    logger::*,
    args::ARGS,
    constants::*,
    statics::LOGGER
};

fn header(color: bool) {
    let yara: &str;
    if cfg!(feature = "yara_x") {
        yara = "yara_x"
    } else {
        yara = "yara_c"
    }
    let mut logo = format!("");
    match color {
        true => {
            logo.push_str(format!("{}\n","-------------------------------------".bright_blue()).as_str());
            logo.push_str(format!("{}{}  {}\n","__   __".cyan().bold(),"_____".cyan().bold(),"_____".cyan()).as_str());
            logo.push_str(format!("{} {}{}\n","\\ \\ / /".cyan().bold(),"___ \\".cyan().bold(),"/  ___|".cyan()).as_str());
            logo.push_str(format!(" {}{}{}\n","\\ V /".cyan().bold(),"| |_/ /".cyan().bold(),"\\ `--.  ___ __ _ _ __".cyan()).as_str());
            logo.push_str(format!("  {} {}  {}\n","\\ /".cyan().bold(),"|  __/".cyan().bold(),"`--. \\/ __/ _` | '_ \\".cyan()).as_str());
            logo.push_str(format!("  {} {}    {}\n","| |".cyan().bold(),"| |".cyan().bold(),"/\\__/ / (_| (_| | | | |".cyan()).as_str());
            logo.push_str(format!("  {} {}    {}\n","\\_/".cyan().bold(),"\\_|".cyan().bold(),"\\____/ \\___\\__,_|_| |_|".cyan()).as_str());
            logo.push_str(format!("\n").as_str());
            logo.push_str(format!("  {} {}\n", "Version".cyan().bold(), VERSION.cyan()).as_str());
            logo.push_str(format!("  {} {}\n", "Pack w/".cyan().bold(),yara.cyan()).as_str());
            logo.push_str(format!("  {} {}\n", "Made by".cyan().bold(), "Ibrahim Alzamil".cyan()).as_str());
            logo.push_str(format!("{}\n","-------------------------------------".bright_blue()).as_str());
            println!("{logo}");
        }
        false => {
            logo.push_str("-------------------------------------\n");
            logo.push_str("__   _______  _____\n");
            logo.push_str("\\ \\ / / ___ \\/  ___|\n");
            logo.push_str(" \\ V /| |_/ /\\ `--.  ___ __ _ _ __\n");
            logo.push_str("  \\ / |  __/  `--. \\/ __/ _` | '_ \\\n");
            logo.push_str("  | | | |    /\\__/ / (_| (_| | | | |\n");
            logo.push_str("  \\_/ \\_|    \\____/ \\___\\__,_|_| |_|\n");
            logo.push_str("\n");
            logo.push_str(format!("  Version {}\n", VERSION).as_str());
            logo.push_str(format!("  Pack w/ {}\n",yara).as_str());
            logo.push_str("  Made by Ibrahim Alzamil\n");
            logo.push_str("-------------------------------------\n");
            println!("{logo}");
        }
    }
}

fn setup_display() {

    let mut show_header = true;
    let mut progress = true;
    let mut color: bool;

    // check if these arguments are set so we don't display header and color
    let args: Vec<String> = env::args().collect();

    // Try to enable ansi support
    match enable_ansi_support::enable_ansi_support() {
        Ok(_) => {
            // ANSI escape codes were successfully enabled, or this is a non-Windows platform.
            color = true;
        }
        Err(_) => {
            // The operation was unsuccessful, typically because it's running on an older
            // version of Windows. The program may choose to disable ANSI color code output in
            // this case.
            color = false;
        }
    }

    // Check if special output is selected to disable header display
    if args.contains(&"--json-output".to_string()) || args.contains(&"--no-output".to_string()) || args.contains(&"--csv-output".to_string()) {
        // return and don't display header
        show_header = false;
        color = false;
    }

    // Check if we are not in tty
    if !std::io::stdout().is_terminal() {
        // Disable color
        color = false;
        // Disable progress
        progress = false;
    }

    if args.contains(&"--no-color".to_string()) {
        color = false;
    }

    // Set logger color and progress option
    let mut lock = LOGGER.write().unwrap();
    lock.set_color(color);
    lock.set_logprogress(progress);
    drop(lock);
    
    // Display header
    if show_header {
        header(color);
    }
}

fn setup_logger() {
    // Check all logger related arguments and modify logger for each change
    if ARGS.get_flag("debug") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfilter(LevelFilter::Debug);
        drop(lock);
    }
    if ARGS.get_flag("trace") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfilter(LevelFilter::Trace);
        drop(lock);
    }
    if ARGS.get_flag("only-alerts") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logfilter(LevelFilter::Alert);
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
    if ARGS.get_flag("no-log") {
        let mut lock = LOGGER.write().unwrap();
        lock.set_logtofile(false);
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
}

fn initialize(){
    // Setup logger variables
    setup_logger();
    // Check which program is selected
    match &ARGS.subcommand_name() {
        Some("scan") => initialize_scan(),
        Some("encrypt") => initialize_encrypt(),
        Some("decrypt") => initialize_decrypt(),
        _ => {
            // Unreachable code
            LOGFATAL!("Clap failed to manage arguments");
            exit(2);
        }
    }
}

fn main() {
    // Setup display settings before displaying header
    setup_display();

    // Start clap and parse arguments
    initialize();
}