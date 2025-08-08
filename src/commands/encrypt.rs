use std::{
    ffi::OsStr,
    process::exit,
    path::{
        Path,
        PathBuf
    }
};

use crate::utils::{
    statics::ARGS,
    crypto::encrypt_file_to_file_buffered
};

use walkdir::WalkDir;

pub fn initialize_encrypt(){
    
    let args = ARGS.subcommand_matches("encrypt").unwrap();

    if let Ok(Some(path)) = args.try_get_one::<String>("file") {
        let mut counter = 0;
        for entry in WalkDir::new(path).max_depth(1) {
            // Make sure target file/folder is available
            let entry = match entry {
                Ok(valid_entry) => {
                    valid_entry
                }
                Err(e) => {
                    crate::LOGFATAL!("Fatal error encrypting path due to {}",e);
                    exit(2000);
                }
            };
            // Only encrypt if entry is a file
            if entry.file_type().is_file() {
                // Gather metadata about the file
                let filename = entry.file_name().to_str().unwrap_or("N/A");
                let extention = entry.path().extension().unwrap_or(OsStr::new("N/A"));
                // Check if user provided output flag
                let mut new_path: PathBuf;
                if let Ok(Some(path)) = args.try_get_one::<String>("output-path") {
                    let tmp_path = Path::new(path);
                    new_path = tmp_path.join(entry.file_name());
                } else {
                    new_path = entry.clone().into_path();
                }
                // Check if file is yar or ioc or cfg file
                if extention == "yara" || extention == "yar" {
                    new_path.set_extension("eyar");
                } else if extention == "ioc" {
                    new_path.set_extension("eioc");
                } else if extention == "cfg" {
                    new_path.set_extension("ecfg");
                } else {
                    crate::LOGDEBUG!("File {} not recognized",filename);
                    continue;
                }
                // Read file and try to encrypt it
                match encrypt_file_to_file_buffered(entry.path(),new_path.as_path()) {
                    Ok(_) => {
                        crate::LOGSUCCESS!("Encrypted file {}",filename);
                        counter += 1;
                    }
                    Err(e) => {
                        crate::LOGERROR!("Unable to encrypt file {} due to {}",filename,e);
                    }
                }
            }
        }
        if counter == 0 {
            crate::LOGFATAL!("Unable to find a valid yara or ioc or config file to encrypt");
            exit(2001);
        } else {
            crate::LOGSUCCESS!("Successfully encrypted {} files",counter);
        }
    } else {
        crate::LOGFATAL!("No path was provided");
        exit(2002);
    }
}