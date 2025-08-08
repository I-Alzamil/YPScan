use std::{
    path::Path,
    collections::HashSet
};

use regex::Regex;

use crate::utils::{
    bags::ResultBag,
    traits::Component,
    fileloader::LoadFileType,
    fileloader::load_single_file
};

pub struct FHash {
    active: bool,
    malware_hashes: Option<HashSet<String>>,
    excluded_hashes: Option<HashSet<String>>
}

impl Default for FHash {
    fn default() -> FHash {
        FHash {
            active: false,
            malware_hashes: None,
            excluded_hashes: None
        }
    }
}

impl Component<Path> for FHash {
    fn prepare(&mut self) {

        self.malware_hashes = load_malware_hashes();

        self.excluded_hashes = load_excluded_hashes();

        if self.malware_hashes.is_some() || self.excluded_hashes.is_some() {
            self.active = true;
        }

    }
    fn scan(
        &self,
        target: &Path,
        bag: &mut ResultBag
    ) -> Result<(),()> {
        match self.active {
            true => {
                match hash_all(target) {
                    Ok(valid_hashes) => {
                        // Push hashes to info vec
                        bag.info.push((format!("MD5"),format!("{}",&valid_hashes[0])));
                        bag.info.push((format!("SHA1"),format!("{}",&valid_hashes[1])));
                        bag.info.push((format!("SHA256"),format!("{}",&valid_hashes[2])));
                        // Check if hash is excluded
                        match self.excluded_hashes {
                            Some(ref excluded_hashes) => {
                                if excluded_hashes.contains(&valid_hashes[0]) || excluded_hashes.contains(&valid_hashes[1]) || excluded_hashes.contains(&valid_hashes[2]) {
                                    crate::LOGDEBUG!("Skipping file {} due to a match in hash exclusions",target.display());
                                    return Err(())
                                }
                            }
                            None => {}
                        }
                        // Check if hash matches an IOC
                        match self.malware_hashes {
                            Some(ref malware_hashes) => {
                                if malware_hashes.contains(&valid_hashes[0]) {
                                    bag.reasons += 1;
                                    bag.result.push((format!("MatchReason_{}",bag.reasons),format!("Hash Match")));
                                    bag.result.push((format!("MatchName_{}",bag.reasons),format!("MD5")));
                                    bag.result.push((format!("MatchDesc_{}",bag.reasons),format!("Matched {}",&valid_hashes[0])));
                                }
                                if malware_hashes.contains(&valid_hashes[1]) {
                                    bag.reasons += 1;
                                    bag.result.push((format!("MatchReason_{}",bag.reasons),format!("Hash Match")));
                                    bag.result.push((format!("MatchName_{}",bag.reasons),format!("SHA1")));
                                    bag.result.push((format!("MatchDesc_{}",bag.reasons),format!("Matched {}",&valid_hashes[1])));
                                }
                                if malware_hashes.contains(&valid_hashes[2]) {
                                    bag.reasons += 1;
                                    bag.result.push((format!("MatchReason_{}",bag.reasons),format!("Hash Match")));
                                    bag.result.push((format!("MatchName_{}",bag.reasons),format!("SHA256")));
                                    bag.result.push((format!("MatchDesc_{}",bag.reasons),format!("Matched {}",&valid_hashes[2])));
                                }
                            }
                            None => {}
                        }
                    }
                    Err(e) => {
                        crate::LOGDEBUG!("Unable to scan file {} due to {}",target.display(),e);
                        return Err(())
                    }
                }
            }
            false => {
                // Push empty fields to maintain same format
                bag.info.push((format!("MD5"),format!("N/A")));
                bag.info.push((format!("SHA1"),format!("N/A")));
                bag.info.push((format!("SHA256"),format!("N/A")));
            }
        }
        Ok(())
    }
}

fn load_malware_hashes() -> Option<HashSet<String>> {

    let mut hashes: HashSet<String> = HashSet::new();
    
    let mut counter = 0;

    let valid_md5 = Regex::new(r"^[a-fA-F0-9]{32}$").unwrap();
    let valid_sha1 = Regex::new(r"^[a-fA-F0-9]{40}$").unwrap();
    let valid_sha256 = Regex::new(r"^[a-fA-F0-9]{64}$").unwrap();

    match load_single_file("hashes", LoadFileType::IOC, None) {
        Ok(file_content) => {
            // Read hash file line by line
            for line in file_content.lines() {
                // Parse hashes
                if line.starts_with("#") || line.is_empty() {
                    continue;
                }
                let mut parsed = line.split(";");
                let hash = parsed.next().unwrap();

                // Check if hash is invalid
                if !valid_md5.is_match(hash) && !valid_sha1.is_match(hash) && !valid_sha256.is_match(hash) {
                    crate::LOGERROR!("Hash '{}' failed to load due to invalid hash format",hash);
                    continue;
                }

                hashes.insert(hash.to_string());
                counter += 1;
            }
        }
        Err(_) => {
            crate::LOGWARN!("Unable to locate 'hashes.ioc', hash scan is disabled");
            return None;
        }
    };

    if counter != 0 {
        crate::LOGINFO!("Successfully loaded {} malware hashes",counter);
        return Some(hashes);
    } else {
        crate::LOGWARN!("No malware hash was loaded, hash scan is disabled");
        return None;
    }
}

fn load_excluded_hashes() -> Option<HashSet<String>> {

    let mut hashes: HashSet<String> = HashSet::new();

    let mut counter = 0;

    let valid_md5 = Regex::new(r"^[a-fA-F0-9]{32}$").unwrap();
    let valid_sha1 = Regex::new(r"^[a-fA-F0-9]{40}$").unwrap();
    let valid_sha256 = Regex::new(r"^[a-fA-F0-9]{64}$").unwrap();

    match load_single_file("hash-exclusions", LoadFileType::CONFIG, None) {
        Ok(file_content) => {
            // Read hash file line by line
            for line in file_content.lines() {
                // Parse hashes
                if line.starts_with("#") || line.is_empty() {
                    continue;
                }
                let mut parsed = line.split(";");
                let hash = parsed.next().unwrap();

                // Check if hash is invalid
                if !valid_md5.is_match(hash) && !valid_sha1.is_match(hash) && !valid_sha256.is_match(hash) {
                    crate::LOGERROR!("Hash '{}' failed to load due to invalid hash format",hash);
                    continue;
                }
                
                hashes.insert(hash.to_string());
                counter += 1;
            }
            if counter != 0 {
                crate::LOGINFO!("Successfully loaded {} excluded hashes",counter);
                return Some(hashes);
            } else {
                crate::LOGDEBUG!("No hash was excluded");
                return None;
            }
        }
        Err(_) => {
            crate::LOGNOTICE!("Hash exclusion config file was not found");
            return None;
        }
    }
}

use std::{
    fs,
    io::Read
};

use sha2::Digest;

pub fn hash_all(
    file: &Path
) -> Result<[String;3], Box<dyn std::error::Error>> {
    // Open the file
    let mut file = fs::File::open(file)?;

    // Create hashers
    let mut md5_hasher = md5::Context::new();
    let mut sha1_hasher = sha1::Sha1::new();
    let mut sha256_hasher = sha2::Sha256::new();

    // Read the file in 4KB chunks and feed them to the hashers
    let mut buffer = [0; 4096];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        md5_hasher.consume(&buffer[..bytes_read]);
        sha1_hasher.update(&buffer[..bytes_read]);
        sha256_hasher.update(&buffer[..bytes_read]);
    }

    // Finalize the hash and get the result as an array of strings
    Ok([ format!("{:x}",md5_hasher.finalize()) , format!("{:x}",sha1_hasher.finalize()) , format!("{:x}",sha256_hasher.finalize()) ])
}