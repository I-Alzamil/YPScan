fn header(color: bool) {
    use owo_colors::OwoColorize;
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
            logo.push_str(format!("  {} {}\n", "Version".cyan().bold(), crate::utils::constants::PKG_VERSION.cyan()).as_str());
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
            logo.push_str(format!("  Version {}\n", crate::utils::constants::PKG_VERSION).as_str());
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
    let args: Vec<String> = std::env::args().collect();

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
    if args.contains(&String::from("--json-output")) || args.contains(&String::from("--no-output")) || args.contains(&String::from("--csv-output")) {
        // return and don't display header
        show_header = false;
        color = false;
    }

    // Check if we are not in tty
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        // Disable color
        color = false;
        // Disable progress
        progress = false;
    }

    if args.contains(&String::from("--no-color")) {
        color = false;
    }

    if args.contains(&String::from("--no-progress")) || args.contains(&String::from("--q")) {
        progress = false;
    }

    // Set logger color and progress option
    let mut lock = crate::utils::statics::LOGGER.write().unwrap();
    lock.set_color(color);
    if progress {
        lock.create_progress();
    }
    drop(lock);
    
    // Display header
    if show_header {
        header(color);
    }
}

pub fn enterypoint() {
    // Setup display settings before displaying header
    setup_display();
    // Setup logger variables
    crate::utils::args::setup_logger();
    // Check which command is selected
    match crate::utils::statics::ARGS.subcommand_name() {
        Some("scan") => crate::commands::scan::initialize_scan(),
        Some("encrypt") => crate::commands::encrypt::initialize_encrypt(),
        Some("decrypt") => crate::commands::decrypt::initialize_decrypt(),
        _ => {
            // Unreachable code
            crate::LOGFATAL!("Clap failed to manage arguments");
            std::process::exit(2);
        }
    }
}