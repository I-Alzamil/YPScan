use std::{
    fs::File,
    path::Path,
    io::{
        Read,
        Write,
        BufRead,
        BufReader,
        BufWriter,
    }
};

use super::constants::KEY;

pub fn encrypt_file_to_file_buffered(
    in_file: &Path,
    out_file: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(in_file)?);
    let mut writer = BufWriter::new(File::create(out_file)?);
    let fernet = fernet::Fernet::new(KEY).unwrap();
    let mut buffer = vec![0; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        writer.write_all(fernet.encrypt(&buffer[0..n]).as_bytes())?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

pub fn decrypt_file_to_file_buffered(
    in_file: &Path,
    out_file: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(in_file)?);
    let mut writer = BufWriter::new(File::create(out_file)?);
    let fernet = fernet::Fernet::new(KEY).unwrap();
    let mut buffer = String::new();
    loop {
        let n = reader.read_line(&mut buffer)?;
        if n == 0 {
            break;
        }
        buffer = buffer.trim_end().to_string(); // to remove the new line
        writer.write_all(&fernet.decrypt(&buffer)?)?;
        buffer.clear();
    }
    writer.flush()?;
    Ok(())
}

pub fn decrypt_file_to_string_buffered(
    in_file: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(in_file)?);
    let mut writer = BufWriter::new(Vec::new());
    let fernet = fernet::Fernet::new(KEY).unwrap();
    let mut buffer = String::new();
    loop {
        let n = reader.read_line(&mut buffer)?;
        if n == 0 {
            break;
        }
        buffer = buffer.trim_end().to_string(); // to remove the new line
        writer.write_all(&fernet.decrypt(&buffer)?)?;
        buffer.clear();
    }
    writer.flush()?;
    let bytes = writer.into_inner()?;
    let result_string = String::from_utf8(bytes)?;
    Ok(result_string)
}