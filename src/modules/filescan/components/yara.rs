use std::path::Path;

use crate::utils::{
    statics::ARGS,
    bags::ResultBag,
    traits::Component,
    fileloader::{
        LoadFileType,
        preload_paths,
        load_preloaded_file
    }
};

#[cfg(feature = "yara_c")]
use yara::{
    Compiler,
    Rules
};

#[cfg(feature = "yara_x")]
use yara_x::{
    Compiler,
    Rules,
    Scanner
};

pub struct FYara {
    active: bool,
    rules: Option<Rules>
}

impl Default for FYara {
    fn default() -> FYara {
        FYara {
            active: false,
            rules: None
        }
    }
}

impl Component<Path> for FYara {
    fn prepare(&mut self) {

        self.rules = load_yara_files();

        if self.rules.is_some() {
            self.active = true;
        }

    }
    #[cfg(feature = "yara_c")]
    fn scan(
        &self,
        file: &Path,
        bag: &mut ResultBag
    ) -> Result<(),()> {
        match self.active {
            true => {
                // Load scan command arguments
                let args = ARGS.subcommand_matches("scan").unwrap();
                
                // Create scanner
                let mut scanner;
                match self.rules {
                    Some(ref rules) => scanner = rules.scanner().unwrap(),
                    None => {
                        crate::LOGERROR!("Unable to create yara scanner due to invalid rules");
                        return Err(())
                    }
                }
                
                // Get file type
                let file_type = match bag.info.get(1) {
                    Some(info_vec) => {
                        if info_vec.0 == format!("Type") {
                            info_vec.1.as_str()
                        } else {
                            "N/A"
                        }
                    }
                    None => "N/A",
                };
            
                // Add additional fields to scanner
                let _ = scanner.define_variable("filename", file.file_name().unwrap_or_default().to_str().unwrap_or("N/A"));
                let _ = scanner.define_variable("filepath", file.to_str().unwrap_or("N/A"));
                let _ = scanner.define_variable("filetype", file_type);
                let _ = scanner.define_variable("extension", file.extension().unwrap_or_default().to_str().unwrap_or("N/A"));

                // Scan the file using yara rules and get results
                match scanner.scan_file(file) {
                    Ok(yara_result) => {
                        for rule_match in yara_result {
                            if bag.reasons >= 4 && !args.get_flag("all-reasons") {
                                break;
                            }
                            bag.reasons += 1;
                            bag.result.push((format!("MatchReason_{}",bag.reasons),format!("Yara Match")));
                            bag.result.push((format!("MatchName_{}",bag.reasons),rule_match.identifier.to_string()));
                            let metadata = rule_match.metadatas;
                            let mut description = format!("N/A");
                            let mut has_author = false;
                            let mut author = format!("N/A");
                            for data in metadata {
                                if data.identifier.eq_ignore_ascii_case("description") {
                                    description = match data.value {
                                        yara::MetadataValue::Integer(value) => format!("{value}"),
                                        yara::MetadataValue::String(value) => format!("{value}"),
                                        yara::MetadataValue::Boolean(value) => format!("{value}"),
                                    }
                                }
                                if data.identifier.eq_ignore_ascii_case("author") {
                                    author = match data.value {
                                        yara::MetadataValue::Integer(value) => format!("{value}"),
                                        yara::MetadataValue::String(value) => format!("{value}"),
                                        yara::MetadataValue::Boolean(value) => format!("{value}"),
                                    };
                                    has_author = true;
                                }
                            }
                            if has_author {
                                bag.result.push((format!("MatchDesc_{}",bag.reasons),format!("{}. Made by {}.",description,author)));
                            } else {
                                bag.result.push((format!("MatchDesc_{}",bag.reasons),description));
                            }
                        }
                    }
                    Err(e) => {
                        crate::LOGDEBUG!("Unable to scan file {} due to {}",file.display(),e);
                        return Err(())
                    }
                }
            }
            false => {
                // Do nothing
            }
        }
        Ok(())
    }
    #[cfg(feature = "yara_x")]
    fn scan(
        &self,
        file: &Path,
        bag: &mut ResultBag
    ) -> Result<(),()> {
        match self.active {
            true => {
                // Load scan command arguments
                let args = ARGS.subcommand_matches("scan").unwrap();
                
                // Create scanner
                let mut scanner;

                match self.rules {
                    Some(ref rules) => scanner = Scanner::new(rules),
                    None => {
                        crate::LOGERROR!("Unable to create yara scanner due to invalid rules");
                        return Err(())
                    }
                }
                
                // Get file type
                let file_type = match bag.info.get(1) {
                    Some(info_vec) => {
                        if info_vec.0 == format!("Type") {
                            info_vec.1.as_str()
                        } else {
                            "N/A"
                        }
                    }
                    None => "N/A",
                };
            
                // Add additional fields to scanner
                let _ = scanner.set_global("filename", file.file_name().unwrap_or_default().to_str().unwrap_or("N/A"));
                let _ = scanner.set_global("filepath", file.to_str().unwrap_or("N/A"));
                let _ = scanner.set_global("filetype", file_type);
                let _ = scanner.set_global("extension", file.extension().unwrap_or_default().to_str().unwrap_or("N/A"));

                // Scan the file using yara rules and get results
                match scanner.scan_file(file) {
                    Ok(yara_result) => {
                        for rule_match in yara_result.matching_rules() {
                            if bag.reasons >= 4 && !args.get_flag("all-reasons") {
                                break;
                            }
                            bag.reasons += 1;
                            bag.result.push((format!("MatchReason_{}",bag.reasons),format!("Yara Match")));
                            bag.result.push((format!("MatchName_{}",bag.reasons),rule_match.identifier().to_string()));
                            let metadata: yara_x::Metadata<'_, '_> = rule_match.metadata();
                            let mut description = format!("N/A");
                            let mut has_author = false;
                            let mut author = format!("N/A");
                            for data in metadata {
                                if data.0.to_lowercase() == "description" {
                                    description = match data.1 {
                                        yara_x::MetaValue::Integer(value) => format!("{value}"),
                                        yara_x::MetaValue::Float(value) => format!("{value}"),
                                        yara_x::MetaValue::Bool(value) => format!("{value}"),
                                        yara_x::MetaValue::String(value) => format!("{value}"),
                                        yara_x::MetaValue::Bytes(value) => format!("{value}"),
                                    }
                                }
                                if data.0.to_lowercase() == "author" {
                                    author = match data.1 {
                                        yara_x::MetaValue::Integer(value) => format!("{value}"),
                                        yara_x::MetaValue::Float(value) => format!("{value}"),
                                        yara_x::MetaValue::Bool(value) => format!("{value}"),
                                        yara_x::MetaValue::String(value) => format!("{value}"),
                                        yara_x::MetaValue::Bytes(value) => format!("{value}"),
                                    };
                                    has_author = true;
                                }
                            }
                            if has_author {
                                bag.result.push((format!("MatchDesc_{}",bag.reasons),format!("{}. Made by {}.",description,author)));
                            } else {
                                bag.result.push((format!("MatchDesc_{}",bag.reasons),description));
                            }
                        }
                    }
                    Err(e) => {
                        crate::LOGDEBUG!("Unable to scan file {} due to {}",file.display(),e);
                        return Err(())
                    }
                }
            }
            false => {
                // Do nothing
            }
        }
        Ok(())
    }
}

#[cfg(feature = "yara_c")]
fn load_yara_files() -> Option<Rules> {
    
    fn test_compile_yara_rule(rule: &str) -> Result<(), yara::Error> {
        let mut testcompiler = Compiler::new()?;
        let _ = testcompiler.define_variable("filename", "");
        let _ = testcompiler.define_variable("filepath", "");
        let _ = testcompiler.define_variable("filetype", "");
        let _ = testcompiler.define_variable("extension", "");
        let _ = testcompiler.define_variable("owner", "");
        testcompiler.add_rules_str(rule)?;
        Ok(())
    }

    let mut compiler = yara::Compiler::new().unwrap();
    let _ = compiler.define_variable("filename", "");
    let _ = compiler.define_variable("filepath", "");
    let _ = compiler.define_variable("filetype", "");
    let _ = compiler.define_variable("extension", "");
    let _ = compiler.define_variable("owner", "");

    let mut counter = 0;

    let files = match preload_paths(LoadFileType::YARA, None) {
        Ok(files_vec) => files_vec,
        Err(_) => {
            crate::LOGWARN!("Unable to locate yara directory, yara scan is disabled");
            return None;
        }
    };

    for file in files {
        match load_preloaded_file(&file.0,file.1) {
            Err(e) => {
                crate::LOGERROR!("Unable to load a file {} due to {}",file.0.display(),e);
                continue;
            }
            Ok(file_content) => {
                // Make sure yara folder is available
                match test_compile_yara_rule(file_content.as_str()) {
                    Ok(_) => {
                        compiler = compiler.add_rules_str(file_content.as_str()).unwrap();
                        crate::LOGDEBUG!("Successfully loaded {}",file.0.display());
                        counter += 1;
                    }
                    Err(e) => {
                        crate::LOGERROR!("Error loading yara rule {} due to {}",file.0.display(),e);
                    }
                }
            }
        }
    }

    if counter != 0 {
        crate::LOGINFO!("Successfully parsed {} yara rule files",counter);
        let rules = compiler.compile_rules().unwrap();
        crate::LOGINFO!("Successfully loaded {} yara rules",rules.get_rules().len());
        return Some(rules);
    } else {
        crate::LOGWARN!("No yara file was loaded, yara scan is disabled");
        return None;
    }
}

#[cfg(feature = "yara_x")]
fn load_yara_files() -> Option<Rules> {

    let mut compiler = Compiler::new();
    let _ = compiler.define_global("filename", "");
    let _ = compiler.define_global("filepath", "");
    let _ = compiler.define_global("filetype", "");
    let _ = compiler.define_global("extension", "");
    let _ = compiler.define_global("owner", "");

    let mut counter = 0;

    let files = match preload_paths(LoadFileType::YARA, None) {
        Ok(files_vec) => files_vec,
        Err(_) => {
            crate::LOGWARN!("Unable to locate yara directory, yara scan is disabled");
            return None;
        }
    };

    for file in files {
        match load_preloaded_file(&file.0,file.1) {
            Err(e) => {
                crate::LOGERROR!("Unable to load a file {} due to {}",file.0.display(),e);
                continue;
            }
            Ok(file_content) => {
                // Make sure yara folder is available
                match compiler.add_source(file_content.as_bytes()){
                    Ok(_) => {
                        crate::LOGDEBUG!("Successfully loaded {}",file.0.display());
                        counter += 1;
                    }
                    Err(e) => {
                        crate::LOGERROR!("Error loading yara rule {} due to {}",file.0.display(),e);
                    }
                }
            }
        }
    }

    if counter != 0 {
        crate::LOGINFO!("Successfully parsed {} yara rule files",counter);
        let rules = compiler.build();
        crate::LOGINFO!("Successfully loaded {} yara rules",rules.iter().count());
        return Some(rules);
    } else {
        crate::LOGWARN!("No yara file was loaded, yara scan is disabled");
        return None;
    }
}