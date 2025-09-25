mod install;

use install::{log, create_jwt_secret, Color, constants};

fn main() {
    // Test logging with different colors
    log(Color::Cyan, "Initializing Open vAIR installer...");
    log(Color::Green, "System information loaded successfully");
    
    // Display constants
    println!();
    log(Color::Cyan, "Configuration:");

    println!("  User: {}", constants::USER);
    println!("  Project: {}", constants::PROJECT_NAME);
    println!("  OS: {}", &*constants::OS);
    println!("  Architecture: {}", &*constants::ARCH);
    println!("  Processor: {}", constants::get_proc());
    println!("  User Path: {}", &*constants::USER_PATH);
    println!("  Project Path: {}", &*constants::PROJECT_PATH);
    println!("  Config File: {}", &*constants::PROJECT_CONFIG_FILE);
    println!("  Log File: {}", &*constants::LOG_FILE);
    
    // Test JWT secret creation (only if config file exists)
    println!();
    match std::path::Path::new(&*constants::PROJECT_CONFIG_FILE).exists() {
        true => {
            log(Color::Cyan, "Testing JWT secret creation...");
            match create_jwt_secret() {
                Ok(()) => log(Color::Green, "JWT secret creation test passed"),
                Err(e) => log(Color::Red, &format!("JWT secret creation failed: {}", e)),
            }
        }
        false => {
            log(Color::Cyan, "Skipping JWT secret test (config file doesn't exist)");
            log(Color::Cyan, &format!("Expected config file at: {}", &*constants::PROJECT_CONFIG_FILE));
        }
    }
    
    println!();
    log(Color::Green, "Open vAIR installer module test completed successfully!");
}
