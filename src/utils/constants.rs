// Gather build details in built_info module
include!(concat!(env!("OUT_DIR"), "/built.rs"));

// Used to encrypt and decrypt YARA and IOC files to avoid AV detection
pub const KEY: &str = "BOf1xLKvghT_5im6ZWGVKmM0HnL82oYDy5TaU7Ce_ps=";

// Styling and colors for clap
pub const CLAP_STYLING: clap::builder::styling::Styles = clap::builder::styling::Styles::styled()
    .header(clap_cargo::style::HEADER)
    .usage(clap_cargo::style::USAGE)
    .literal(clap_cargo::style::LITERAL)
    .placeholder(clap_cargo::style::PLACEHOLDER)
    .error(clap_cargo::style::ERROR)
    .valid(clap_cargo::style::VALID)
    .invalid(clap_cargo::style::INVALID);