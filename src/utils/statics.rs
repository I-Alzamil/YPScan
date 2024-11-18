use std::{
    env,
    process::exit,
    path::PathBuf,
    sync::{
    LazyLock,
    RwLock
    }
};

use sysinfo::System;

use crate::{
    Logger,
    LOGFATAL
};

// Set parent path of exe as this is where we load iocs and write logs to
pub static MY_PATH: LazyLock<PathBuf> = LazyLock::new(||{
    fn get_current_path() -> PathBuf {
        match env::current_dir() {
            Ok(valid_path) => valid_path,
            Err(e) => {
                LOGFATAL!("Unable to get path due to {e}");
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

// Main program logger
pub static LOGGER: LazyLock<RwLock<Logger>> = LazyLock::new(||{
    RwLock::new(Logger::default())
});

// Hostname
pub static HOSTNAME: LazyLock<String> = LazyLock::new(||{
    match System::host_name() {
        Some(valid_hostname) => valid_hostname,
        None => format!("N/A"),
    }
});

// Date and time at the start of program
// Note: it only collect time if it is called
pub static DATETIME: LazyLock<String> = LazyLock::new(|| {
    format!("{}",chrono::offset::Utc::now().format("%Y-%m-%d_%H-%M-%S"))
});