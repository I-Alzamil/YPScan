use std::{
    env,
    process::exit,
    path::PathBuf,
    sync::{
    LazyLock,
    RwLock
    }
};

// Main program logger
pub static LOGGER: RwLock<super::logger::Logger> = RwLock::new(super::logger::Logger::const_default());

// Main args variable
pub static ARGS: LazyLock<clap::ArgMatches> = LazyLock::new(||{
    crate::utils::args::set_args().get_matches()
});

// Process name for logging purposes
pub static PROCESS_NAME: LazyLock<String> = LazyLock::new(|| {
    match std::env::current_exe() {
        Ok(path) => format!("{}",path.file_name().unwrap_or(std::ffi::OsStr::new("YPScan")).to_string_lossy()),
        Err(_) => format!("YPScan"),
    }
});

// Used to determine how many threads are allowed to be created
pub static MAX_THREADS: LazyLock<u8> = LazyLock::new(|| {
    // Load scan command arguments
    let args = ARGS.subcommand_matches("scan").unwrap();
    
    let max_threads: u8;
    // Determine threads count
    if let Ok(Some(threads)) = args.try_get_one::<u8>("threads") {
        max_threads = *threads;
    } else {
        // by default run using half the resources
        let mut sys = sysinfo::System::new();
        sys.refresh_cpu_all();
        if args.get_flag("power") {
            max_threads = sys.cpus().len() as u8;
        } else {
            max_threads = sys.cpus().len() as u8 / 2;
        }
    }
    max_threads
});

// Path where we load all files from and write logs to
pub static MY_PATH: LazyLock<PathBuf> = LazyLock::new(||{
    fn get_current_path() -> PathBuf {
        match env::current_dir() {
            Ok(valid_path) => valid_path,
            Err(e) => {
                crate::LOGFATAL!("Unable to get path due to {e}");
                exit(1)
            }
        }
    }
    match env::current_exe() {
        Ok(vaild_path) => vaild_path.parent().unwrap_or(get_current_path().as_path()).to_path_buf(),
        Err(_) => {
            get_current_path()
        }
    }
});

// Hostname
pub static HOSTNAME: LazyLock<String> = LazyLock::new(||{
    match sysinfo::System::host_name() {
        Some(valid_hostname) => valid_hostname,
        None => format!("N/A"),
    }
});

// Date and time at first call for filename creation
pub static DATETIME: LazyLock<String> = LazyLock::new(|| {
    format!("{}",chrono::offset::Utc::now().format("%Y-%m-%d_%H-%M-%S"))
});