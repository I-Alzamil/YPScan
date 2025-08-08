const LOG_LEVEL_NAMES: [&str; 10] = ["FATAL", "ERROR", "ALERT", "WARN", "NOTICE", "RESULT", "SUCCESS", "INFO", "DEBUG", "TRACE"];

#[repr(usize)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum LOGLevel {
    /// The "fatal" level.
    ///
    /// Designates terminating errors.
    Fatal,
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

impl std::fmt::Display for LOGLevel {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.pad(self.as_str())
    }
}

impl LOGLevel {
    pub fn as_str(&self) -> &'static str {
        LOG_LEVEL_NAMES[*self as usize]
    }
}

use std::{
    io::Write,
    sync::Mutex,
    time::Duration,
    fs::OpenOptions
};

use indicatif::{
    ProgressBar,
    ProgressStyle,
    ProgressDrawTarget
};

use rand::Rng;
use owo_colors::OwoColorize;

use crate::utils::statics::{
    MY_PATH,
    DATETIME,
    HOSTNAME,
    PROCESS_NAME
};

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
    logfilter: LOGLevel,
    logtoconsole: bool,
    consoletype: OutputType,
    progress: Option<Mutex<ProgressBar>>,
    file: Option<Mutex<String>>,
    filetype: OutputType,
    ansiencoding: bool,
    syslog: Option<Mutex<String>>
}

impl Logger {
    pub const fn const_default() -> Self {
        Self {
            color: true,
            logfilter: LOGLevel::Info,
            logtoconsole: true,
            consoletype: OutputType::LOG,
            progress: None,
            file: Some(Mutex::new(String::new())),
            filetype: OutputType::LOG,
            ansiencoding: false,
            syslog: None
        }
    }
    fn process_log(&self,level: &LOGLevel,message: &String,kvl: &Option<&Vec<(String,String)>>,color: owo_colors::AnsiColors){
        if self.logtoconsole {
            self.logtoconsole(level,message,kvl,color);
        }
        if self.file.is_some() {
            self.logtofile(level,message,kvl);
        }
        if self.syslog.is_some() {
            self.logtosyslog(level, message, kvl);
        }
    }
    fn logtoconsole(&self,level: &LOGLevel,message: &String,kvl: &Option<&Vec<(String,String)>>,color: owo_colors::AnsiColors){
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
    fn add_color(&self,level: &LOGLevel,message: &String,kvl: &Option<&Vec<(String,String)>>,color: owo_colors::AnsiColors) -> String {
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
    fn logtofile(&self,level: &LOGLevel,message: &String,kvl: &Option<&Vec<(String,String)>>){
        match &self.file {
            Some(logfile) => {
                let lock = logfile.lock().unwrap();
                let file_path;
                if lock.is_empty() {
                    let extention = match self.filetype {
                        OutputType::LOG => "log",
                        OutputType::CSV => "csv",
                        OutputType::JSON => "json",
                    };
                    let pkg_name ;
                    if cfg!(feature = "yara_x") {
                        pkg_name = "YPScanX"
                    } else {
                        pkg_name = "YPScan"
                    }
                    file_path = MY_PATH.join(format!("{}_{}.{}",pkg_name,DATETIME.as_str(),extention));
                } else {
                    file_path = MY_PATH.join(lock.as_str());
                }
                let mut file = OpenOptions::new().write(true).create(true).append(true).open(file_path).unwrap();
                let result = match self.filetype {
                    OutputType::LOG => self.log_format(level,message,kvl),
                    OutputType::CSV => self.csv_format(level,message,kvl),
                    OutputType::JSON => self.json_format(level,message,kvl),
                };
                match writeln!(&mut file,"{result}") {
                    Ok(_) => {}
                    Err(e) => self.logtoconsole(&LOGLevel::Error, &format!("Unable to write to file due to {}",e), &None, owo_colors::AnsiColors::Red),
                }
                drop(lock);
            }
            None => todo!(),
        }
    }
    fn log_format(&self,level: &LOGLevel,message: &String,kvl: &Option<&Vec<(String,String)>>) -> String {
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
    fn csv_format(&self,level: &LOGLevel,message: &String,kvl: &Option<&Vec<(String,String)>>) -> String {
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
    fn json_format(&self,level: &LOGLevel,message: &String,kvl: &Option<&Vec<(String,String)>>) -> String {
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
    fn logtosyslog(&self,level: &LOGLevel,message: &String,kvl: &Option<&Vec<(String,String)>>) {
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
                                self.logtoconsole(&LOGLevel::Error, &format!("Cannot to connect to tcp syslog due to {}", e), &None, owo_colors::AnsiColors::Red);
                            }
                            Ok(mut writer) => {
                                let _ = match level {
                                    LOGLevel::Trace | LOGLevel::Debug => writer.debug(full_message),
                                    LOGLevel::Info | LOGLevel::Success | LOGLevel::Result => writer.info(full_message),
                                    LOGLevel::Notice => writer.notice(full_message),
                                    LOGLevel::Warn => writer.warning(full_message),
                                    LOGLevel::Alert => writer.alert(full_message),
                                    LOGLevel::Error => writer.err(full_message),
                                    LOGLevel::Fatal => writer.crit(full_message),
                                };
                            }
                        };
                    } else if protocol == "udp" {
                        match syslog::udp(formatter,format!("0.0.0.0:{}",local_port).as_str(),address) {
                            Err(e) => {
                                self.logtoconsole(&LOGLevel::Error, &format!("Cannot to connect to udp syslog due to {}", e), &None, owo_colors::AnsiColors::Red);
                            }
                            Ok(mut writer) => {
                                let _ = match level {
                                    LOGLevel::Trace | LOGLevel::Debug => writer.debug(full_message),
                                    LOGLevel::Info | LOGLevel::Success | LOGLevel::Result => writer.info(full_message),
                                    LOGLevel::Notice => writer.notice(full_message),
                                    LOGLevel::Warn => writer.warning(full_message),
                                    LOGLevel::Alert => writer.alert(full_message),
                                    LOGLevel::Error => writer.err(full_message),
                                    LOGLevel::Fatal => writer.crit(full_message),
                                };
                            }
                        };
                    } else {
                        self.logtoconsole(&LOGLevel::Error, &format!("Cannot to connect to syslog due to protocal error"), &None, owo_colors::AnsiColors::Red);
                    }
                } else {
                    self.logtoconsole(&LOGLevel::Error, &format!("Cannot to connect to syslog due to internal slices error"), &None, owo_colors::AnsiColors::Red);
                }
            }
            None => {}
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
            let mut rng = rand::rng();
            let port = rng.random_range(49152..65535);
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
        self.logtoconsole = logtoconsole
    }
    pub fn set_logconsoletype(&mut self,consoletype: OutputType){
        self.consoletype = consoletype
    }
    pub fn set_logtofile(&mut self,logtofile: bool,filename: Option<String>){
        if logtofile {
            match filename {
                Some(name) => self.file = Some(Mutex::new(name)),
                None => {
                    if self.file.is_none() {
                        self.file = Some(Mutex::new(String::new()))
                    }
                }
            }
        } else {
            if self.file.is_some() {
                self.file = None
            }
        }
    }
    pub fn set_logfiletype(&mut self,filetype: OutputType){
        self.filetype = filetype
    }
    pub fn set_logfilter(&mut self,level: LOGLevel){
        self.logfilter = level
    }
    pub fn set_color(&mut self,color: bool){
        self.color = color
    }
    pub fn set_ansi(&mut self,ansi: bool){
        self.ansiencoding = ansi
    }
    pub fn get_color(&self) -> bool {
        self.color
    }
    pub fn trace(&self,message: String,kvl: Option<&Vec<(String,String)>>){
        if LOGLevel::Trace <= self.logfilter {
            self.process_log(&LOGLevel::Trace, &message, &kvl, owo_colors::AnsiColors::Blue);
        }
    }
    pub fn debug(&self,message: String,kvl: Option<&Vec<(String,String)>>){
        if LOGLevel::Debug <= self.logfilter {
            self.process_log(&LOGLevel::Debug, &message, &kvl, owo_colors::AnsiColors::BrightBlue);
        }
    }
    pub fn info(&self,message: String,kvl: Option<&Vec<(String,String)>>){
        if LOGLevel::Info <= self.logfilter {
            self.process_log(&LOGLevel::Info, &message, &kvl, owo_colors::AnsiColors::Cyan);
        }
    }
    pub fn success(&self,message: String,kvl: Option<&Vec<(String,String)>>){
        if LOGLevel::Success <= self.logfilter {
            self.process_log(&LOGLevel::Success, &message, &kvl, owo_colors::AnsiColors::Green);
        }
    }
    pub fn result(&self,message: String,kvl: Option<&Vec<(String,String)>>,clean: bool){
        if LOGLevel::Result <= self.logfilter {
           if clean {
                self.process_log(&LOGLevel::Result, &message, &kvl, owo_colors::AnsiColors::Green);
           } else {
                self.process_log(&LOGLevel::Result, &message, &kvl, owo_colors::AnsiColors::BrightRed);
           }
        }
    }
    pub fn notice(&self,message: String,kvl: Option<&Vec<(String,String)>>){
        if LOGLevel::Notice <= self.logfilter {
            self.process_log(&LOGLevel::Notice, &message, &kvl, owo_colors::AnsiColors::BrightCyan);
        }
    }
    pub fn warn(&self,message: String,kvl: Option<&Vec<(String,String)>>){
        if LOGLevel::Warn <= self.logfilter {
            self.process_log(&LOGLevel::Warn, &message, &kvl, owo_colors::AnsiColors::BrightYellow);
        }
    }
    pub fn alert(&self,message: String,kvl: Option<&Vec<(String,String)>>){
        if LOGLevel::Alert <= self.logfilter {
            self.process_log(&LOGLevel::Alert, &message, &kvl, owo_colors::AnsiColors::BrightRed);
        }
    }
    pub fn error(&self,message: String,kvl: Option<&Vec<(String,String)>>){
        if LOGLevel::Error <= self.logfilter {
            self.process_log(&LOGLevel::Error, &message, &kvl, owo_colors::AnsiColors::Red);
        }
    }
    pub fn fatal(&self,message: String,kvl: Option<&Vec<(String,String)>>){
        if LOGLevel::Fatal <= self.logfilter {
            self.process_log(&LOGLevel::Fatal, &message, &kvl, owo_colors::AnsiColors::BrightMagenta);
        }
    }
    pub fn set_progress(&self,length: u64) {
        if self.progress.is_some() {
            let prog = self.progress.as_ref().unwrap().lock().unwrap();
            prog.reset();
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
}