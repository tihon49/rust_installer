use openvair_installer::{log, create_jwt_secret, Color};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    log(Color::Cyan, "JWT Secret Generation Example");
    
    // Create JWT secret (requires project_config.toml to exist)
    match create_jwt_secret() {
        Ok(()) => {
            log(Color::Green, "JWT secret has been successfully created and saved to project_config.toml");
        }
        Err(e) => {
            log(Color::Red, &format!("Failed to create JWT secret: {}", e));
            return Err(e.into());
        }
    }
    
    Ok(())
}