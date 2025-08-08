use std::path::Path;

use crate::utils::{
    bags::ResultBag,
    traits::Component
};

pub struct FSignature {
    active: bool
}

impl Default for FSignature {
    fn default() -> FSignature {
        FSignature {
            active: false
        }
    }
}

impl Component<Path> for FSignature {
    fn prepare(&mut self) {
        // Nothing need to be prepared here, so we just activate the module.
        // TO DO: Add args to disable digital signature scanning
        self.active = true;
    }
    fn scan(
        &self,
        file: &Path,
        bag: &mut ResultBag
    ) -> Result<(),()> {
        match self.active {
            true => {
                bag.info.push((format!("Signature"),get_file_signature(file)));
            }
            false => {
                bag.info.push((format!("Signature"),format!("N/A")));
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn get_file_signature(
    entry: &Path
) -> String {
    return match verifysign::CodeSignVerifier::for_file(&entry) {
        Ok(valid_verfiy) => {
            match valid_verfiy.verify() {
                Ok(valid_context) => format!("{} ({})",valid_context.subject_name().common_name.unwrap_or("N/A".to_string()),valid_context.sha1_thumbprint()),
                Err(verifysign::Error::Unsigned) => {
                    format!("Unsigned")
                }
                Err(e) => {
                    crate::LOGDEBUG!("Failed to get certificate for {} due to {:?}",entry.display(),e);
                    format!("Unsigned")
                }
            }
        }
        Err(e) => {
            crate::LOGDEBUG!("Failed to get certificate for {} due to {:?}",entry.display(),e);
            format!("Unsigned")
        }
    };
}

#[cfg(not(target_os = "windows"))]
fn get_file_signature(
    _entry: &Path
) -> String {
    return format!("N/A");
}