use std::{
    time::Duration,
    path::{
        Path,
        PathBuf
    },
    sync::{
        Arc,
        Mutex,
        RwLock
    },
    thread::{
        self,
        sleep
    }
};

use sysinfo::Disks;
use walkdir::WalkDir;
use indicatif::FormattedDuration;
use regex::{
    Regex,
    RegexSet
};

use crate::utils::{
    bags::ResultBag,
    queue::QueueManager,
    fileloader::LoadFileType,
    statics::{
        ARGS,
        MAX_THREADS,
        MY_PATH
    }, 
    traits::{
        Component, Module
    }
};

pub struct FScanner {
    components: Arc<RwLock<Vec<Box<dyn Component<Path>>>>>,
    matches: Arc<Mutex<u32>>,
    excluded_paths: Option<RegexSet>
}

impl Default for FScanner {
    fn default() -> FScanner {
        // Create vec holding all components
        let mut components: Vec<Box<dyn Component<Path>>> = Vec::new();

        // Add all supported components of filescan module
        components.push(Box::new(super::components::info::FInfo::default()));
        components.push(Box::new(super::components::signature::FSignature::default()));
        components.push(Box::new(super::components::hash::FHash::default()));
        components.push(Box::new(super::components::yara::FYara::default()));
        
        FScanner {
            components: Arc::new(RwLock::new(components)),
            matches: Arc::new(Mutex::new(0)),
            excluded_paths: None
        }
    }
}

impl Module for FScanner {
    fn prepare(&mut self) {
        crate::LOGINFO!("Preparing filescan module");
        
        let args = ARGS.subcommand_matches("scan").unwrap();

        let size_message: String;

        if let Ok(Some(size)) = args.try_get_one::<u64>("size") {
            size_message = format!("File size limit set to {} KB",size);
        } else if args.get_flag("no-size") {
            size_message = format!("File size limit is removed");
        } else {
            size_message = format!("Default file size limit set to 100 MB");
        }

        if let Ok(Some(path)) = args.try_get_one::<String>("path") {
            crate::LOGINFO!("Scanning {}",path);
        } else {
            crate::LOGINFO!("Scanning all drives (Excluding removable and share)");
        }

        crate::LOGINFO!("{}",size_message);

        // Prepare all available components
        for component in self.components.write().unwrap().iter_mut() {
            component.prepare();
        }

        self.excluded_paths = load_excluded_paths();
    }

    fn run(&mut self, queue: Arc<QueueManager>) {
        // Get args for scan module
        let args = ARGS.subcommand_matches("scan").unwrap();
        
        // Setup scan paths
        // Get list of paths to scan
        let mut scan_paths: Vec<PathBuf> = Vec::new();

        // Check if user provied path argument, if not check os and use default option
        if let Ok(Some(path)) = args.try_get_one::<String>("path") {
            scan_paths.push(Path::new(path).to_path_buf());
        } else {
            if cfg!(windows) {
                let disks = Disks::new_with_refreshed_list();
                for disk in disks.list() {
                    if args.contains_id("all-drives") {
                        scan_paths.push(disk.mount_point().to_path_buf());
                    } else {
                        if !disk.is_removable() {
                            scan_paths.push(disk.mount_point().to_path_buf());
                        }
                    }
                }
            } else {
                scan_paths.push(Path::new("/").to_path_buf());
            }
        }
        
        // Spawn worker threads
        let mut handlers: Vec<(u8,thread::JoinHandle<()>)> = Vec::new();
        for thread_id in 0..*MAX_THREADS {
            let shared_components = Arc::clone(&self.components);
            let shared_matches = Arc::clone(&self.matches);
            let shared_queue = Arc::clone(&queue);
            handlers.push((thread_id+1,thread::spawn(move || {
                // Main loop
                loop {
                    // Get a file from the queue
                    let entry = match shared_queue.pop() {
                        Ok(valid_entry) => {
                            valid_entry
                        }
                        Err(concurrent_queue::PopError::Empty) => {
                            crate::LOGTRACE!("Thread {} is sleeping for 100ms due to empty queue",thread_id+1);
                            sleep(Duration::from_millis(100));
                            continue;
                        }
                        Err(concurrent_queue::PopError::Closed) => {
                            break;
                        }
                    };
                    
                    let mut result_bag = ResultBag::default();

                    result_bag.info.push((format!("Path"),entry.to_string_lossy().to_string()));

                    for component in shared_components.read().unwrap().iter() {
                        match component.scan(Path::new(&entry), &mut result_bag) {
                            Ok(_) => {}
                            Err(_) => {
                                break;
                            }
                        }
                    }

                    if result_bag.reasons > 0 {
                        *shared_matches.lock().unwrap() += 1;
                        result_bag.info.append(&mut result_bag.result);
                        crate::LOGALERT!(kvl: &result_bag.info,"MATCH FOUND");
                    } else {
                        crate::LOGTRACE!(kvl: &result_bag.info,"Finished scanning file without any match")
                    }

                    crate::INCPROGRESS!(1);
                }
            })));
        }

        let start_time = std::time::Instant::now();

        crate::SETPROGRESS!(0);

        let file_size_limit: u64;

        if let Ok(Some(size)) = args.try_get_one::<u64>("size") {
            // Get file size in KB
            file_size_limit = *size * 1000;
        } else if args.get_flag("no-size") {
            file_size_limit = 0;
        } else {
            file_size_limit = 100000000;
        }

        // Start walkdir and fetch all files to be scanned and add them to the queue
        for scan_path in scan_paths {
            for entry in WalkDir::new(scan_path)
                .into_iter()
                .filter_entry(|e| !excluded_entry(e,&self.excluded_paths))
            {
                let entry = match entry {
                    Ok(validentry) => {
                        // Skip if file is under scanner path to avoid falce positives
                        if validentry.path().starts_with(&MY_PATH.as_path()) {
                            continue;
                        }
                        validentry
                    }
                    Err(e) => {
                        crate::LOGDEBUG!("Unable to scan directory due to {}",e);
                        continue;
                    }
                };
                if entry.file_type().is_file() {
                    // Check if size is limited
                    if file_size_limit != 0 {
                        let file_size = get_file_size(entry.path());

                        if file_size >= file_size_limit {
                            crate::LOGTRACE!("File {} skiped due to file size",entry.file_name().to_str().unwrap());
                            continue;
                        }
                    }
                    
                    queue.push(entry.path().as_os_str().to_os_string());

                    crate::INCLENGTHPROGRESS!(1);
                }
            }
        }

        // Move all items from disk queue to in-memory queue
        queue.disk_to_queue();

        // Close job queue to signal to worker threads they can exit if queue is empty
        queue.close();

        // Wait for threads to finish
        for (thread_id,handle) in handlers {
            match handle.join() {
                Ok(_) => {
                    crate::LOGTRACE!("Worker thread {} successfully ended",thread_id);
                }
                Err(e) => {
                    crate::LOGERROR!("Error ending worker thread {} due to {:?}",thread_id,e);
                }
            }
        }

        let elapsed = FormattedDuration(start_time.elapsed());

        let matches = *self.matches.lock().unwrap();

        if matches != 0 {
            crate::LOGNOTICE!("Scan have completed in {} and found {} matches",elapsed,matches);
            crate::LOGRESULT!(clean: false,"Review matched files as you see fit and proceed with caution");
        } else {
            crate::LOGNOTICE!("Scan have completed in {} and found no matches",elapsed);
            crate::LOGRESULT!(clean: true,"Result is clean");
        }

        // Delete progress if it is active
        crate::DELETEPROGRESS!();
    }
}

fn load_excluded_paths() -> Option<RegexSet> {

    match crate::utils::fileloader::load_single_file("path-exclusions", LoadFileType::CONFIG, None) {
        Ok(file_content) => {
            // Read hash file line by line
            let mut counter = 0;
            let mut patterns: Vec<&str> = Vec::new();
            for line in file_content.lines() {
                // Parse hashes
                if line.starts_with("#") || line.is_empty() {
                    continue;
                }
                match Regex::new(line) {
                    Ok(_) => {
                        patterns.push(line);
                        counter += 1;
                    }
                    Err(e) => {
                        crate::LOGERROR!("Unable to compile regex '{}' due to {}",line,e);
                    }
                }
            }
            if counter != 0 {
                crate::LOGINFO!("Successfully loaded {} excluded paths",counter);
                match RegexSet::new(patterns) {
                    Ok(set) => {
                        return Some(set);
                    }
                    Err(e) => {
                        crate::LOGERROR!("Unable to read regex exclusions due to {}",e);
                        return None;
                    }
                }
            } else {
                crate::LOGDEBUG!("No path was excluded");
                return None;
            }
        }
        Err(_) => {
            crate::LOGNOTICE!("Path exclusion config file was not found");
            return None;
        }
    }
}

// --------------------------
// Windows specific functions
// --------------------------

#[cfg(target_os = "windows")]
fn excluded_entry(
    entry: &walkdir::DirEntry,
    regex_set: &Option<RegexSet>
) -> bool {
    let excluded = match regex_set {
        Some(set) => {
            entry.path()
                .to_str()
                .map(|s| set.is_match(s))
                .unwrap_or(false)
        }
        None => return false,
    };
    if excluded {
        crate::LOGDEBUG!("Skipping {} due to a match in path exclusions",entry.path().display());
    }
    return excluded;
}

#[cfg(target_os = "windows")]
pub fn get_file_size(
    entry: &Path
) -> u64 {
    use std::os::windows::fs::MetadataExt;
    return match entry.metadata() {
        Ok(valid_metadata) => valid_metadata.file_size(),
        Err(_) => 0,
    };
}

// ------------------------------
// Non-Windows specific functions
// ------------------------------

#[cfg(not(target_os = "windows"))]
const LINUX_EXCLUSIONS: [&str;2] = ["/proc","/sys"];

#[cfg(not(target_os = "windows"))]
fn excluded_entry(
    entry: &walkdir::DirEntry,
    regex_set: &Option<RegexSet>
) -> bool {
    if entry.file_type().is_dir() {
        let excluded = entry.path()
            .to_str()
            .map(|s| LINUX_EXCLUSIONS.contains(&s))
            .unwrap_or(false);
        if excluded {
            return true;
        }
    }
    let excluded = match regex_set {
        Some(set) => {
            entry.path()
                .to_str()
                .map(|s| set.is_match(s))
                .unwrap_or(false)
        }
        None => return false,
    };
    if excluded {
        crate::LOGDEBUG!("Skipping {} due to a match in path exclusions",entry.path().display());
    }
    return excluded;
}

#[cfg(not(target_os = "windows"))]
pub fn get_file_size(
    entry: &Path
) -> u64 {
    use std::os::linux::fs::MetadataExt;
    return match entry.metadata() {
        Ok(valid_metadata) => valid_metadata.st_size(),
        Err(_) => 0,
    };
}