use std::{
    ffi::OsString,
    process::exit,
    sync::Mutex
};

use queue_file::QueueFile;
use concurrent_queue::ConcurrentQueue;

pub struct QueueManager {
    memory_queue: ConcurrentQueue<OsString>,
    disk_queue: Mutex<QueueFile>,
    temp_file: std::path::PathBuf
}

impl Default for QueueManager {
    fn default() -> QueueManager {
        // Setup disk queue which is used incase in-memory queue gets full
        let tempfile = std::env::temp_dir().join(format!("ypsqueue_{:06x}.db",rand::random::<u32>()));
        // Check if file already exists
        if tempfile.exists() {
            crate::LOGFATAL!("Temp file queue creation failed");
            exit(1000);
        }
        let mut disk_queue = match QueueFile::open(tempfile.as_path()) {
            Ok(valid_queue) => valid_queue,
            Err(e) => {
                crate::LOGFATAL!("Failed to create disk queue due to {e}");
                exit(1001)
            }
        };
        disk_queue.set_sync_writes(false);
        // Create queuemanager
        QueueManager {
            memory_queue: ConcurrentQueue::bounded(1000),
            disk_queue: Mutex::new(disk_queue),
            temp_file: tempfile
        }
    }
}

impl QueueManager {
    pub fn push(&self,item: std::ffi::OsString) {
        match self.memory_queue.push(item.clone()) {
            Ok(_) => {} // This means we are below 1000 items in the queue.
            Err(_) => {
                // Put path to the disk queue instead.
                let mut lock = self.disk_queue.lock().unwrap();
                match lock.add(item.as_encoded_bytes()) {
                    Ok(_) => {}
                    Err(e) => {
                        crate::LOGFATAL!("Unable to add to disk queue file due to {}, program will exit now",e);
                        exit(1002);
                    }
                }
            }
        }
    }

    pub fn pop(&self) -> Result<std::ffi::OsString, concurrent_queue::PopError> {
        match self.memory_queue.pop() {
            Ok(value) => Ok(value),
            Err(error) => return Err(error),
        }
    }

    pub fn close(&self) {
        self.memory_queue.close();
    }

    pub fn is_empty(&self) -> bool {
        self.memory_queue.is_empty()
    }

    pub fn is_closed(&self) -> bool {
        self.memory_queue.is_closed()
    }

    pub fn disk_to_queue(&self) {
        let mut lock = self.disk_queue.lock().unwrap();
        loop {
            match lock.peek() {
                Err(e) => {
                    crate::LOGFATAL!("Unable to read disk queue file due to {}, scan will abort now",e);
                    exit(1003);
                }
                Ok(item) => {
                    match item {
                        None => {
                            break;
                        }
                        Some(bytes) => {
                            let path = unsafe {
                                OsString::from_encoded_bytes_unchecked(bytes.to_vec())
                            };
                            match self.memory_queue.push(path) {
                                Ok(_) => {
                                    // This means we are below 1000 items in the queue and have successfully pushed to it
                                    // Remove item from queue since we already pushed to job_queue
                                    match lock.remove() {
                                        Ok(_) => {}
                                        Err(e) => {
                                            crate::LOGFATAL!("Unable to remove from disk queue file due to {}, scan will abort now",e);
                                            exit(1004);
                                        }
                                    }
                                }
                                Err(concurrent_queue::PushError::Full(_)) => {
                                    // Wait for worker thread to consume more work
                                    crate::LOGTRACE!("Job queue is full, Waiting for worker threads to consume more items");
                                    std::thread::sleep(std::time::Duration::from_millis(100));
                                }
                                Err(concurrent_queue::PushError::Closed(_)) => {
                                    // This shouldn't happen
                                    crate::LOGFATAL!("Queue closed before emptying it to the ram, scan will abort now");
                                    exit(1005);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Drop for QueueManager {
    fn drop(&mut self) {
        match std::fs::remove_file(self.temp_file.as_path()) {
            Ok(_) => {}
            Err(e) => crate::LOGERROR!("Unable to clean up temp file due to {}",e),
        }
    }
}