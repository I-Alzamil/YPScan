use std::path::Path;

use chrono::DateTime;

use crate::modules::filescan::implementation::get_file_size;

use crate::utils::{
    bags::ResultBag,
    traits::Component
};

pub struct FInfo {
    active: bool
}

impl Default for FInfo {
    fn default() -> FInfo {
        FInfo {
            active: false
        }
    }
}

impl Component<Path> for FInfo {
    fn prepare(&mut self) {
        // Nothing need to be prepared here, so we just activate the module.
        // TO DO: Add args to disable file info
        self.active = true;
    }
    fn scan(
        &self,
        file: &Path,
        bag: &mut ResultBag
    ) -> Result<(),()> {
        match self.active {
            true => {
                // Gather info about the file
                let file_type = match file_format::FileFormat::from_file(file) {
                    Ok(format) => format.name().to_string(),
                    Err(e) => {
                        crate::LOGDEBUG!("Unable to get file type due to {}",e);
                        format!("N/A")
                    }
                };

                let file_size = get_file_size(file);

                let created_timestame: String;
                let modified_timestame: String;
                let accessed_timestame: String;

                match file.metadata() {
                    Ok(metadata) => {
                        created_timestame = match metadata.created() {
                            Ok(valid_timestamp) => DateTime::<chrono::Utc>::from(valid_timestamp).format("%d/%m/%Y %T").to_string(),
                            Err(_) => format!("N/A"),
                        };
                        modified_timestame = match metadata.modified() {
                            Ok(valid_timestamp) => DateTime::<chrono::Utc>::from(valid_timestamp).format("%d/%m/%Y %T").to_string(),
                            Err(_) => format!("N/A"),
                        };
                        accessed_timestame = match metadata.accessed() {
                            Ok(valid_timestamp) => DateTime::<chrono::Utc>::from(valid_timestamp).format("%d/%m/%Y %T").to_string(),
                            Err(_) => format!("N/A"),
                        };
                    }
                    Err(e) => {
                        crate::LOGDEBUG!("Unable to get metadata due to {}",e);
                        created_timestame = format!("N/A");
                        modified_timestame = format!("N/A");
                        accessed_timestame = format!("N/A");
                    }
                };
                // Push info to tracker
                bag.info.push((format!("Type"),file_type.clone()));
                bag.info.push((format!("Size"),file_size.to_string()));
                bag.info.push((format!("Created"),created_timestame));
                bag.info.push((format!("Modified"),modified_timestame));
                bag.info.push((format!("Accessed"),accessed_timestame));
            }
            false => {
                // Push empty fields to maintain same format
                bag.info.push((format!("Type"),format!("N/A")));
                bag.info.push((format!("Size"),format!("N/A")));
                bag.info.push((format!("Created"),format!("N/A")));
                bag.info.push((format!("Modified"),format!("N/A")));
                bag.info.push((format!("Accessed"),format!("N/A")));
            }
        }
        Ok(())
    }
}