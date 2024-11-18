use std::{
    fs,io::Read, 
    path::Path
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
    Ok([ format!("{:x}",md5_hasher.compute()) , format!("{:x}",sha1_hasher.finalize()) , format!("{:x}",sha256_hasher.finalize()) ])
}