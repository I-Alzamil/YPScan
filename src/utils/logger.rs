use std::{
    cmp,
    fmt,
    io::Write,
    str::FromStr,
    time::Duration,
    fs::OpenOptions,
    sync::Mutex
};

use indicatif::{
    ProgressBar,
    ProgressStyle,
    ProgressDrawTarget
};

use rand::Rng;
use owo_colors::OwoColorize;

use crate::utils::statics::{
    LOGGER,
    MY_PATH,
    DATETIME,
    HOSTNAME,
    PROCESS_NAME
};

macro_rules! LOGTRACE {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = LOGGER.read().unwrap();
        lock.trace(format!($($arg)*),Some($kvl),None);
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = LOGGER.read().unwrap();
        lock.trace(format!($($arg)*),None,None);
        drop(lock);
    }};
}

macro_rules! LOGDEBUG {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = LOGGER.read().unwrap();
        lock.debug(format!($($arg)*),Some($kvl),None);
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = LOGGER.read().unwrap();
        lock.debug(format!($($arg)*),None,None);
        drop(lock);
    }};
}

macro_rules! LOGINFO {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = LOGGER.read().unwrap();
        lock.info(format!($($arg)*),Some($kvl),None);
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = LOGGER.read().unwrap();
        lock.info(format!($($arg)*),None,None);
        drop(lock);
    }};
}

macro_rules! LOGSUCCESS {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = LOGGER.read().unwrap();
        lock.success(format!($($arg)*),Some($kvl),None);
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = LOGGER.read().unwrap();
        lock.success(format!($($arg)*),None,None);
        drop(lock);
    }};
}

macro_rules! LOGRESULT {
    (clean: $clean:expr,kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = LOGGER.read().unwrap();
        lock.result(format!($($arg)*),Some($kvl),$clean,None);
        drop(lock);
    }};
    (clean: $clean:expr,$($arg:tt)*) => {{
        let lock = LOGGER.read().unwrap();
        lock.result(format!($($arg)*),None,$clean,None);
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = LOGGER.read().unwrap();
        lock.result(format!($($arg)*),None,true,None);
        drop(lock);
    }};
}

macro_rules! LOGNOTICE {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = LOGGER.read().unwrap();
        lock.notice(format!($($arg)*),Some($kvl),None);
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = LOGGER.read().unwrap();
        lock.notice(format!($($arg)*),None,None);
        drop(lock);
    }};
}

macro_rules! LOGWARN {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = LOGGER.read().unwrap();
        lock.warn(format!($($arg)*),Some($kvl),None);
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = LOGGER.read().unwrap();
        lock.warn(format!($($arg)*),None,None);
        drop(lock);
    }};
}

macro_rules! LOGALERT {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = LOGGER.read().unwrap();
        lock.alert(format!($($arg)*),Some($kvl),None);
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = LOGGER.read().unwrap();
        lock.alert(format!($($arg)*),None,None);
        drop(lock);
    }};
}

macro_rules! LOGERROR {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = LOGGER.read().unwrap();
        lock.error(format!($($arg)*),Some($kvl),None);
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = LOGGER.read().unwrap();
        lock.error(format!($($arg)*),None,None);
        drop(lock);
    }};
}

macro_rules! LOGFATAL {
    (kvl: $kvl:expr,$($arg:tt)+) => {{
        let lock = LOGGER.read().unwrap();
        lock.fatal(format!($($arg)*),Some($kvl),None);
        drop(lock);
    }};
    ($($arg:tt)*) => {{
        let lock = LOGGER.read().unwrap();
        lock.fatal(format!($($arg)*),None,None);
        drop(lock);
    }};
}

macro_rules! SETPROGRESS {
    ($length:expr) => {{
        let lock = LOGGER.read().unwrap();
        lock.set_progress($length);
        drop(lock);
    }};
}

macro_rules! INCLENGTHPROGRESS {
    ($length:expr) => {{
        let lock = LOGGER.read().unwrap();
        lock.inc_length_progress($length);
        drop(lock);
    }};
}

macro_rules! INCPROGRESS {
    ($length:expr) => {{
        let lock = LOGGER.read().unwrap();
        lock.inc_progress($length);
        drop(lock);
    }};
}

macro_rules! DELETEPROGRESS {
    () => {{
        let lock = LOGGER.read().unwrap();
        lock.delete_progress();
        drop(lock);
    }};
}

pub(crate) use {
    LOGTRACE,
    LOGDEBUG,
    LOGINFO,
    LOGSUCCESS,
    LOGRESULT,
    LOGNOTICE,
    LOGWARN,
    LOGALERT,
    LOGERROR,
    LOGFATAL,
    SETPROGRESS,
    INCLENGTHPROGRESS,
    INCPROGRESS,
    DELETEPROGRESS
};

/// The type returned by [`from_str`] when the string doesn't match any of the log levels.
///
/// [`from_str`]: https://doc.rust-lang.org/std/str/trait.FromStr.html#tymethod.from_str
#[allow(missing_copy_implementations)]
#[derive(Debug, PartialEq, Eq)]
pub struct ParseLevelError(());

impl fmt::Display for ParseLevelError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(LEVEL_PARSE_ERROR)
    }
}

static LEVEL_PARSE_ERROR: &str = "attempted to convert a string that doesn't match an existing log level";
static LOG_LEVEL_NAMES: [&str; 11] = ["OFF", "Fatal", "ERROR", "Alert", "WARN", "Notice", "Result", "Success", "INFO", "DEBUG", "TRACE"];

/// An enum representing the available verbosity levels of the logger.
///
/// Typical usage includes: checking if a certain `Level` is enabled with
/// [`log_enabled!`](macro.log_enabled.html), specifying the `Level` of
/// [`log!`](macro.log.html), and comparing a `Level` directly to a
/// [`LevelFilter`](enum.LevelFilter.html).
#[repr(usize)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Level {
    /// The "fatal" level.
    ///
    /// Designates terminating errors.
    Fatal = 1,
    /// The "error" level.
    ///
    /// Designates very serious errors.
    Error,
    /// The "alert" level.
    ///
    /// Designates alert information.
    Alert,
    /// The "warn" level.
    ///
    /// Designates hazardous situations.
    Warn,
    /// The "notice" level.
    ///
    /// Designates important information.
    Notice,
    /// The "result" level.
    ///
    /// Designates scan result information.
    Result,
    /// The "success" level.
    ///
    /// Designates successful operation information.
    Success,
    /// The "info" level.
    ///
    /// Designates useful information.
    Info,
    /// The "debug" level.
    ///
    /// Designates lower priority information.
    Debug,
    /// The "trace" level.
    ///
    /// Designates very low priority, often extremely verbose, information.
    Trace,
}

impl PartialEq<LevelFilter> for Level {
    #[inline]
    fn eq(&self, other: &LevelFilter) -> bool {
        *self as usize == *other as usize
    }
}

impl PartialOrd<LevelFilter> for Level {
    #[inline]
    fn partial_cmp(&self, other: &LevelFilter) -> Option<cmp::Ordering> {
        Some((*self as usize).cmp(&(*other as usize)))
    }
}

impl FromStr for Level {
    type Err = ParseLevelError;
    fn from_str(level: &str) -> Result<Level, Self::Err> {
        LOG_LEVEL_NAMES
            .iter()
            .position(|&name| name.eq_ignore_ascii_case(level))
            .into_iter()
            .filter(|&idx| idx != 0)
            .map(|idx| Level::from_usize(idx).unwrap())
            .next()
            .ok_or(ParseLevelError(()))
    }
}

impl fmt::Display for Level {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.pad(self.as_str())
    }
}

impl Level {
    fn from_usize(u: usize) -> Option<Level> {
        match u {
            1 => Some(Level::Fatal),
            2 => Some(Level::Error),
            3 => Some(Level::Alert),
            4 => Some(Level::Warn),
            5 => Some(Level::Notice),
            6 => Some(Level::Result),
            7 => Some(Level::Success),
            8 => Some(Level::Info),
            9 => Some(Level::Debug),
            10 => Some(Level::Trace),
            _ => None,
        }
    }

    /// Returns the most verbose logging level.
    #[inline]
    pub fn max() -> Level {
        Level::Trace
    }

    /// Converts the `Level` to the equivalent `LevelFilter`.
    #[inline]
    pub fn to_level_filter(&self) -> LevelFilter {
        LevelFilter::from_usize(*self as usize).unwrap()
    }

    /// Returns the string representation of the `Level`.
    ///
    /// This returns the same string as the `fmt::Display` implementation.
    pub fn as_str(&self) -> &'static str {
        LOG_LEVEL_NAMES[*self as usize]
    }

    /// Iterate through all supported logging levels.
    ///
    /// The order of iteration is from more severe to less severe log messages.
    ///
    /// # Examples
    ///
    /// ```
    /// use log::Level;
    ///
    /// let mut levels = Level::iter();
    ///
    /// assert_eq!(Some(Level::Error), levels.next());
    /// assert_eq!(Some(Level::Trace), levels.last());
    /// ```
    pub fn iter() -> impl Iterator<Item = Self> {
        (1..10).map(|i| Self::from_usize(i).unwrap())
    }
}

/// An enum representing the available verbosity level filters of the logger.
///
/// A `LevelFilter` may be compared directly to a [`Level`]. Use this type
/// to get and set the maximum log level with [`max_level()`] and [`set_max_level`].
///
/// [`Level`]: enum.Level.html
/// [`max_level()`]: fn.max_level.html
/// [`set_max_level`]: fn.set_max_level.html
#[repr(usize)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum LevelFilter {
    /// Shuts off logger.
    Off,
    /// Corresponds to the `Fatal` log level.
    Fatal,
    /// Corresponds to the `Error` log level.
    Error,
    /// Corresponds to the `Alert` log level.
    Alert,
    /// Corresponds to the `Warn` log level.
    Warn,
    /// Corresponds to the `Notice` log level.
    Notice,
    /// Corresponds to the `Result` log level.
    Result,
    /// Corresponds to the `Success` log level.
    Success,
    /// Corresponds to the `Info` log level.
    Info,
    /// Corresponds to the `Debug` log level.
    Debug,
    /// Corresponds to the `Trace` log level.
    Trace,
}

impl PartialEq<Level> for LevelFilter {
    #[inline]
    fn eq(&self, other: &Level) -> bool {
        other.eq(self)
    }
}

impl PartialOrd<Level> for LevelFilter {
    #[inline]
    fn partial_cmp(&self, other: &Level) -> Option<cmp::Ordering> {
        Some((*self as usize).cmp(&(*other as usize)))
    }
}

impl FromStr for LevelFilter {
    type Err = ParseLevelError;
    fn from_str(level: &str) -> Result<LevelFilter, Self::Err> {
        LOG_LEVEL_NAMES
            .iter()
            .position(|&name| name.eq_ignore_ascii_case(level))
            .map(|p| LevelFilter::from_usize(p).unwrap())
            .ok_or(ParseLevelError(()))
    }
}

impl fmt::Display for LevelFilter {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.pad(self.as_str())
    }
}

impl LevelFilter {
    fn from_usize(u: usize) -> Option<LevelFilter> {
        match u {
            0 => Some(LevelFilter::Off),
            1 => Some(LevelFilter::Fatal),
            2 => Some(LevelFilter::Error),
            3 => Some(LevelFilter::Alert),
            4 => Some(LevelFilter::Warn),
            5 => Some(LevelFilter::Notice),
            6 => Some(LevelFilter::Result),
            7 => Some(LevelFilter::Success),
            8 => Some(LevelFilter::Info),
            9 => Some(LevelFilter::Debug),
            10 => Some(LevelFilter::Trace),
            _ => None,
        }
    }

    /// Returns the most verbose logging level filter.
    #[inline]
    pub fn max() -> LevelFilter {
        LevelFilter::Trace
    }

    /// Converts `self` to the equivalent `Level`.
    ///
    /// Returns `None` if `self` is `LevelFilter::Off`.
    #[inline]
    pub fn to_level(&self) -> Option<Level> {
        Level::from_usize(*self as usize)
    }

    /// Returns the string representation of the `LevelFilter`.
    ///
    /// This returns the same string as the `fmt::Display` implementation.
    pub fn as_str(&self) -> &'static str {
        LOG_LEVEL_NAMES[*self as usize]
    }

    /// Iterate through all supported filtering levels.
    ///
    /// The order of iteration is from less to more verbose filtering.
    ///
    /// # Examples
    ///
    /// ```
    /// use log::LevelFilter;
    ///
    /// let mut levels = LevelFilter::iter();
    ///
    /// assert_eq!(Some(LevelFilter::Off), levels.next());
    /// assert_eq!(Some(LevelFilter::Trace), levels.last());
    /// ```
    pub fn iter() -> impl Iterator<Item = Self> {
        (0..10).map(|i| Self::from_usize(i).unwrap())
    }
}

pub enum OutputType {
    LOG,
    CSV,
    JSON,
}

pub enum LOGType {
    CONSOLE,
    FILE,
    SYSLOG,
}

pub struct Logger {
    color: bool,
    logfilter: LevelFilter,
    logtoconsole: bool,
    consoletype: OutputType,
    progress: Option<Mutex<ProgressBar>>,
    logtofile: bool,
    filelock: Mutex<()>,
    filetype: OutputType,
    ansiencoding: bool,
    syslog: Option<Mutex<String>>
}

// Sets default settings for logger.
impl Default for Logger {
    fn default() -> Logger {
        Logger {
            color: true,
            logfilter: LevelFilter::Info,
            logtoconsole: true,
            consoletype: OutputType::LOG,
            progress: None,
            logtofile: true,
            filelock: Mutex::new(()),
            filetype: OutputType::LOG,
            ansiencoding: false,
            syslog: None
        }
    }
}

impl Logger {
    fn process_log(&self,level: &Level,message: &String,kvl: &Option<&Vec<(String,String)>>,color: owo_colors::AnsiColors,exclude: Option<LOGType>){
        if self.logtoconsole && exclude.as_ref().is_none_or(|log_type| !matches!(log_type,LOGType::CONSOLE)) {
            self.logtoconsole(level,message,kvl,color);
        }
        if self.logtofile && exclude.as_ref().is_none_or(|log_type| !matches!(log_type,LOGType::FILE)) {
            self.logtofile(level,message,kvl);
        }
        if self.syslog.is_some() && exclude.as_ref().is_none_or(|log_type| !matches!(log_type,LOGType::SYSLOG)) {
            self.logtosyslog(level, message, kvl);
        }
    }
    fn logtoconsole(&self,level: &Level,message: &String,kvl: &Option<&Vec<(String,String)>>,color: owo_colors::AnsiColors){
        match self.consoletype {
            OutputType::LOG => {
                if self.color{
                    self.print_log(self.add_color(level,message,kvl,color));
                } else {
                    let level_with_message = format!("[{}] {}",level,message);
                    let full_message: String;
                    match kvl {
                        Some(list) => {
                            let mut kv_message: String = "".to_string();
                            kv_message = [kv_message,format!("-------------------------------------")].join("\n");
                            for kv in list.iter() {
                                kv_message = [kv_message,format!("{}{} {}",kv.0,":",kv.1.to_string())].join("\n");
                            }
                            kv_message = [kv_message,format!("-------------------------------------")].join("\n");
                            full_message = format!("{}{}",level_with_message,kv_message);
                        }
                        None => {
                            full_message = level_with_message;
                        }
                    }
                    self.print_log(full_message);
                }
            }
            OutputType::CSV => self.print_log(format!("{}",self.csv_format(level,message,kvl))),
            OutputType::JSON => self.print_log(format!("{}",self.json_format(level,message,kvl))),
        }
    }
    fn add_color(&self,level: &Level,message: &String,kvl: &Option<&Vec<(String,String)>>,color: owo_colors::AnsiColors) -> String {
        let level_with_message = format!("[{}] {}",level,message);
        match kvl {
            Some(list) => {
                let mut kv_message: String = "".to_string();
                kv_message = [kv_message,format!("-------------------------------------")].join("\n");
                for kv in list.iter() {
                    kv_message = [kv_message,format!("{}{} {}",kv.0.bright_white(),":".bright_white(),kv.1.to_string().color(color))].join("\n");
                }
                kv_message = [kv_message,format!("-------------------------------------")].join("\n");
                let full_message = format!("{}{}",level_with_message.color(color),kv_message);
                return full_message;
            }
            None => {
                let full_message = format!("{}",level_with_message.color(color));
                return full_message;
            }
        }
    }
    fn print_log(&self,full_message: String){
        match self.progress.as_ref() {
            Some(prog) => {
                let lock = prog.lock().unwrap();
                lock.println(full_message);
            }
            None => {
                // Check if ansiencoding is activated
                if !self.ansiencoding {
                    println!("{full_message}");
                } else {
                    self.ansi_println(full_message);
                }
            }
        }
    }
    fn ansi_println(&self,full_message: String) {
        let encoder = local_encoding::Encoding::ANSI;
        let mut valie_with_line = full_message;
        valie_with_line.push_str("\n");
        let encoded = match local_encoding::Encoder::to_bytes(&encoder, &valie_with_line) {
            Ok(valid_bytes) => valid_bytes,
            Err(_) => valie_with_line.as_bytes().to_vec(),
        };
        let mut std_out = std::io::stdout();
        std_out.write_all(&encoded).unwrap_or_default();
        std_out.flush().unwrap_or_default();
    }
    fn logtofile(&self,level: &Level,message: &String,kvl: &Option<&Vec<(String,String)>>){
        let extention = match self.filetype {
            OutputType::LOG => "log",
            OutputType::CSV => "csv",
            OutputType::JSON => "json",
        };
        let lock = self.filelock.lock().unwrap();
        let file_name = format!("YPScan_{}.{}",DATETIME.as_str(),extention);
        let file_path = MY_PATH.join(file_name);
        let mut file = OpenOptions::new().write(true).create(true).append(true).open(file_path).unwrap();
        let result = match self.filetype {
            OutputType::LOG => self.log_format(level,message,kvl),
            OutputType::CSV => self.csv_format(level,message,kvl),
            OutputType::JSON => self.json_format(level,message,kvl),
        };
        match writeln!(&mut file,"{result}") {
            Ok(_) => {}
            Err(e) => self.error(format!("Unable to write to file due to {}",e), None, Some(LOGType::FILE)),
        }
        drop(lock);
    }
    fn log_format(&self,level: &Level,message: &String,kvl: &Option<&Vec<(String,String)>>) -> String{
        let full_message = format!("{: <7} - {} - {} - {}",level,chrono::offset::Utc::now().format("%Y-%m-%d %T%.3f"),HOSTNAME.as_str(),message);
        let result: String;
        match kvl {
            Some(list) => {
                let mut kv_message: String = "".to_string();
                kv_message = [kv_message,format!("-------------------------------------")].join("\n");
                for kv in list.iter() {
                    kv_message = [kv_message,format!("{}{} {}",kv.0,":",kv.1.to_string())].join("\n");
                }
                kv_message = [kv_message,format!("-------------------------------------")].join("\n");
                result = format!("{}{}",full_message,kv_message);
            }
            None => {
                result = format!("{}",full_message);
            }
        }
        return result;
    }
    fn csv_format(&self,level: &Level,message: &String,kvl: &Option<&Vec<(String,String)>>) -> String{
        let full_message = format!("\"{}\",\"{}\",\"{}\",\"{}\"",level,chrono::offset::Utc::now().format("%Y-%m-%d_%T%.3f"),HOSTNAME.as_str(),message);
        let result: String;
        match kvl {
            Some(list) => {
                let mut kv_message: String = "".to_string();
                for kv in list.iter() {
                    kv_message = [kv_message,format!("\"{}\"",kv.1.to_string())].join(",");
                }
                result = format!("{}{}",full_message,kv_message);
            }
            None => {
                result = format!("{}",full_message);
            }
        }
        return result;
    }
    fn json_format(&self,level: &Level,message: &String,kvl: &Option<&Vec<(String,String)>>) -> String{
        let mut json = "{".to_string();
        json.push_str(&format!("\"level\":\"{}\",",level.to_string().escape_default()));
        json.push_str(&format!("\"timestamp\":\"{}\",",chrono::offset::Utc::now().format("%Y-%m-%d %T%.3f").to_string().escape_default()));
        json.push_str(&format!("\"hostname\":\"{}\",",HOSTNAME.as_str().escape_default()));
        json.push_str(&format!("\"message\":\"{}\",",message.escape_default()));
        let result: String;
        match kvl {
            Some(list) => {
                let mut iter = list.iter();
                loop {
                    let value = iter.next();

                    match value {
                        Some(v) => {
                            json.push_str("");
                            json.push_str(&format!("\"{}\":\"{}\",",v.0.escape_default(),v.1.escape_default()));
                        }
                        None => {
                            json.pop();
                            json.push_str("}");
                            break;
                        }
                    }
                }
                result = format!("{}",json);
            }
            None => {
                json.pop();
                json.push_str("}");
                result = format!("{}",json);
            }
        }
        return result;
    }
    fn logtosyslog(&self,level: &Level,message: &String,kvl: &Option<&Vec<(String,String)>>){
        let formatter = syslog::Formatter3164 {
            facility: syslog::Facility::LOG_SYSLOG,
            hostname: Some(HOSTNAME.to_string()),
            process: PROCESS_NAME.to_string(),
            pid: std::process::id(),
        };
        let mut full_message = format!("{message}");
        match kvl {
            Some(list) => {
                for kv in list.iter() {
                    full_message = [full_message,format!("{}{}\"{}\"",kv.0,":",kv.1.to_string())].join(" ");
                }
            }
            None => {}
        }
        match &self.syslog {
            Some(syslog_logger) => {
                let syslog_info = syslog_logger.lock().unwrap();
                let mut slices = syslog_info.split(",");
                if slices.clone().count() == 3 {
                    let protocol = slices.next().unwrap();
                    let address = slices.next().unwrap();
                    let local_port = slices.next().unwrap();
                    if protocol == "tcp" {
                        match syslog::tcp(formatter,address) {
                            Err(e) => {
                                drop(syslog_info);
                                LOGERROR!("Cannot to connect to tcp syslog due to {}", e);
                            }
                            Ok(mut writer) => {
                                let _ = match level {
                                    Level::Trace | Level::Debug => writer.debug(full_message),
                                    Level::Info | Level::Success | Level::Result => writer.info(full_message),
                                    Level::Notice => writer.notice(full_message),
                                    Level::Warn => writer.warning(full_message),
                                    Level::Alert => writer.alert(full_message),
                                    Level::Error => writer.err(full_message),
                                    Level::Fatal => writer.crit(full_message),
                                };
                            }
                        };
                    } else if protocol == "udp" {
                        match syslog::udp(formatter,format!("0.0.0.0:{}",local_port).as_str(),address) {
                            Err(e) => {
                                drop(syslog_info);
                                LOGERROR!("Cannot to connect to udp syslog due to {}", e);
                            }
                            Ok(mut writer) => {
                                let _ = match level {
                                    Level::Trace | Level::Debug => writer.debug(full_message),
                                    Level::Info | Level::Success | Level::Result => writer.info(full_message),
                                    Level::Notice => writer.notice(full_message),
                                    Level::Warn => writer.warning(full_message),
                                    Level::Alert => writer.alert(full_message),
                                    Level::Error => writer.err(full_message),
                                    Level::Fatal => writer.crit(full_message),
                                };
                            }
                        };
                    } else {
                        drop(syslog_info);
                        LOGERROR!("Cannot to connect to syslog due to protocal error");
                    }
                } else {
                    drop(syslog_info);
                    LOGERROR!("Cannot to connect to syslog due to internal slices error");
                }
            }
            None => {}
        }
    }
    pub fn trace(&self,message: String,kvl: Option<&Vec<(String,String)>>,exclude: Option<LOGType>){
        if Level::Trace <= self.logfilter {
            self.process_log(&Level::Trace, &message, &kvl, owo_colors::AnsiColors::Blue, exclude);
        }
    }
    pub fn debug(&self,message: String,kvl: Option<&Vec<(String,String)>>,exclude: Option<LOGType>){
        if Level::Debug <= self.logfilter {
            self.process_log(&Level::Debug, &message, &kvl, owo_colors::AnsiColors::BrightBlue, exclude);
        }
    }
    pub fn info(&self,message: String,kvl: Option<&Vec<(String,String)>>,exclude: Option<LOGType>){
        if Level::Info <= self.logfilter {
            self.process_log(&Level::Info, &message, &kvl, owo_colors::AnsiColors::Cyan, exclude);
        }
    }
    pub fn success(&self,message: String,kvl: Option<&Vec<(String,String)>>,exclude: Option<LOGType>){
        if Level::Success <= self.logfilter {
            self.process_log(&Level::Success, &message, &kvl, owo_colors::AnsiColors::Green, exclude);
        }
    }
    pub fn result(&self,message: String,kvl: Option<&Vec<(String,String)>>,clean: bool,exclude: Option<LOGType>){
        if Level::Result <= self.logfilter {
           if clean {
                self.process_log(&Level::Result, &message, &kvl, owo_colors::AnsiColors::Green, exclude);
           } else {
                self.process_log(&Level::Result, &message, &kvl, owo_colors::AnsiColors::BrightRed, exclude);
           }
        }
    }
    pub fn notice(&self,message: String,kvl: Option<&Vec<(String,String)>>,exclude: Option<LOGType>){
        if Level::Notice <= self.logfilter {
            self.process_log(&Level::Notice, &message, &kvl, owo_colors::AnsiColors::BrightCyan, exclude);
        }
    }
    pub fn warn(&self,message: String,kvl: Option<&Vec<(String,String)>>,exclude: Option<LOGType>){
        if Level::Warn <= self.logfilter {
            self.process_log(&Level::Warn, &message, &kvl, owo_colors::AnsiColors::BrightYellow, exclude);
        }
    }
    pub fn alert(&self,message: String,kvl: Option<&Vec<(String,String)>>,exclude: Option<LOGType>){
        if Level::Alert <= self.logfilter {
            self.process_log(&Level::Alert, &message, &kvl, owo_colors::AnsiColors::BrightRed, exclude);
        }
    }
    pub fn error(&self,message: String,kvl: Option<&Vec<(String,String)>>,exclude: Option<LOGType>){
        if Level::Error <= self.logfilter {
            self.process_log(&Level::Error, &message, &kvl, owo_colors::AnsiColors::Red, exclude);
        }
    }
    pub fn fatal(&self,message: String,kvl: Option<&Vec<(String,String)>>,exclude: Option<LOGType>){
        if Level::Fatal <= self.logfilter {
            self.process_log(&Level::Fatal, &message, &kvl, owo_colors::AnsiColors::BrightMagenta, exclude);
        }
    }
    pub fn set_progress(&self,length: u64) {
        if self.progress.is_some() {
            let prog = self.progress.as_ref().unwrap().lock().unwrap();
            prog.set_length(length);
            prog.enable_steady_tick(Duration::from_millis(100));
            if self.color {
                prog.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({percent}%) ").unwrap().progress_chars("#>-"))
            } else {
                prog.set_style(ProgressStyle::with_template("{spinner} [{elapsed_precise}] [{wide_bar}] {pos}/{len} ({percent}%) ").unwrap().progress_chars("#>-"))
            }
        }
    }
    pub fn inc_length_progress(&self,len_value: u64){
        if self.progress.is_some() {
            let prog = self.progress.as_ref().unwrap().lock().unwrap();
            prog.inc_length(len_value);
        }
    }
    pub fn inc_progress(&self,inc_value: u64){
        if self.progress.is_some() {
            let prog = self.progress.as_ref().unwrap().lock().unwrap();
            prog.inc(inc_value);
        }
    }
    pub fn delete_progress(&self){
        if self.progress.is_some() {
            let prog = self.progress.as_ref().unwrap().lock().unwrap();
            prog.finish_and_clear();
        }
    }
    pub fn create_progress(&mut self) {
        let mut new_progress = ProgressBar::with_draw_target(None,ProgressDrawTarget::stdout());
        new_progress = new_progress.with_style(ProgressStyle::default_spinner());
        self.progress = Some(Mutex::new(new_progress));
    }
    pub fn create_syslog(
        &mut self,
        protocol: &str,
        connection: &str,
        try_count: u8
    ) -> Result<(), String> {
        let formatter = syslog::Formatter3164 {
            facility: syslog::Facility::LOG_SYSLOG,
            hostname: Some(HOSTNAME.to_string()),
            process: PROCESS_NAME.to_string(),
            pid: std::process::id(),
        };
        if protocol.eq_ignore_ascii_case("udp") {
            let mut rng = rand::thread_rng();
            let port = rng.gen_range(49152..65535);
            match syslog::udp(formatter, format!("0.0.0.0:{}",port).as_str(),connection) {
                Ok(_) => self.syslog = Some(Mutex::new(format!("udp,{connection},{port}"))),
                Err(e) => {
                    // Try to bind to a source port 3 times before raising an error
                    if try_count >= 4 {
                        return Err(format!("Unable to configure udp syslog due to {}",e));
                    } else {
                        self.create_syslog(protocol, connection, try_count+1)?;
                    }
                }
            }
            Ok(())
        } else if protocol.eq_ignore_ascii_case("tcp") {
            match std::net::TcpStream::connect(connection) {
                Ok(_) => self.syslog = Some(Mutex::new(format!("tcp,{connection},none"))),
                Err(e) => {
                    return Err(format!("Unable to configure tcp syslog due to {}",e));
                }
            }
            Ok(())
        } else {
            return Err(format!("Unable to configure syslog due to unknown protocal"))
        }
    }
    pub fn set_logtoconsole(&mut self,logtoconsole: bool){
        self.logtoconsole = logtoconsole;
    }
    pub fn set_logconsoletype(&mut self,consoletype: OutputType){
        self.consoletype = consoletype;
    }
    pub fn set_logtofile(&mut self,logtofile: bool){
        self.logtofile = logtofile;
    }
    pub fn set_logfiletype(&mut self,filetype: OutputType){
        self.filetype = filetype;
    }
    pub fn set_logfilter(&mut self,level: LevelFilter){
        self.logfilter = level;
    }
    pub fn set_color(&mut self,color: bool){
        self.color = color;
    }
    pub fn set_ansi(&mut self,ansi: bool){
        self.ansiencoding = ansi;
    }
    pub fn get_color(&self) -> bool {
        self.color
    }
}