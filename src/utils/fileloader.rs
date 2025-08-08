pub enum LoadFileType {
    CONFIG,
    IOC,
    YARA
}

pub fn load_single_file(
    file_name: &str,
    file_type: LoadFileType,
    override_ext: Option<&str>
) -> Result<String,Box<dyn std::error::Error>> {
    
    let file_path = get_file_path(&file_type);

    let file_extension = get_file_ext(&file_type,override_ext);

    let encrypted_file_extension = format!("e{}",file_extension);

    let path = file_path.join(format!("{}.{}",file_name,file_extension));

    if path.exists() {
        return Ok(std::fs::read_to_string(path)?)
    }

    // Handel when yara is selected to cover files ending in .yara instead of .yar
    if override_ext.is_none() {
        match file_type {
            LoadFileType::YARA => {
                let mut yara_path = path;
                yara_path.set_extension("yara");
                if yara_path.exists() {
                    return Ok(super::crypto::decrypt_file_to_string_buffered(&yara_path)?)
                }
            }
            _ => {}
        }
    }

    let path = file_path.join(format!("{}.{}",file_name,encrypted_file_extension));

    if path.exists() {
        return Ok(super::crypto::decrypt_file_to_string_buffered(&path)?)
    }
    
    return Err("file doesn't exists".into())
}

pub fn preload_paths(
    file_type: LoadFileType,
    override_ext: Option<&str>
) -> Result<Vec<(std::path::PathBuf,bool)>,Box<dyn std::error::Error>> {
    let mut all_preloaded_paths: Vec<(std::path::PathBuf,bool)> = Vec::new();

    let file_path = get_file_path(&file_type);

    let file_extension = get_file_ext(&file_type,override_ext);

    let encrypted_file_extension = format!("e{}",file_extension);

    for entry in walkdir::WalkDir::new(file_path).max_depth(1) {

        let dir_entry = entry?;

        if dir_entry.file_type().is_file() {
            // Extract extension
            let extention = match dir_entry.path().extension() {
                Some(valid_extention) => valid_extention.to_str().unwrap_or(""),
                None => "",
            };
            // Map if file is encrypted or not
            if extention.eq_ignore_ascii_case(&file_extension) {
                all_preloaded_paths.push((dir_entry.into_path(),false));
                continue
            }
            if extention.eq_ignore_ascii_case(&encrypted_file_extension) {
                all_preloaded_paths.push((dir_entry.into_path(),true));
                continue
            }
            // Handel when yara is selected to cover files ending in .yara instead of .yar
            if override_ext.is_none() {
                match file_type {
                    LoadFileType::YARA => {
                        if extention.eq_ignore_ascii_case("yara") {
                            all_preloaded_paths.push((dir_entry.into_path(),false));
                            continue
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(all_preloaded_paths)
}

pub fn load_preloaded_file(
    file_path: &std::path::Path,
    encrypted: bool
) -> Result<String,Box<dyn std::error::Error>> {

    if encrypted {
        return Ok(super::crypto::decrypt_file_to_string_buffered(file_path)?)
    } else {
        return Ok(std::fs::read_to_string(file_path)?)
    }

}

fn get_file_path(
    file_type: &LoadFileType
) -> std::path::PathBuf {
    match file_type {
        LoadFileType::CONFIG => {
            // Check if user provied path argument for config, if not use default path
            if let Ok(Some(path)) = super::statics::ARGS.try_get_one::<String>("config-path") {
                std::path::Path::new(path).to_path_buf()
            } else {
                super::statics::MY_PATH.join("config")
            }
        }
        LoadFileType::IOC => {
            // Check if user provied path argument for ioc, if not use default path
            if let Ok(Some(path)) = super::statics::ARGS.try_get_one::<String>("iocs-path") {
                std::path::Path::new(path).to_path_buf()
            } else {
                super::statics::MY_PATH.join("iocs")
            }
        }
        LoadFileType::YARA => {
            // Check if user provied path argument for yara, if not use default path
            if let Ok(Some(path)) = super::statics::ARGS.try_get_one::<String>("yara-path") {
                std::path::Path::new(path).to_path_buf()
            } else {
                super::statics::MY_PATH.join("yara")
            }
        }
    }
}

fn get_file_ext(
    file_type: &LoadFileType,
    override_ext: Option<&str>
) -> String {
    match override_ext {
        Some(ext) => ext.to_string(),
        None => {
            match file_type {
                LoadFileType::CONFIG => "cfg".to_string(),
                LoadFileType::IOC => "ioc".to_string(),
                LoadFileType::YARA => "yar".to_string(),
            }
        }
    }
}