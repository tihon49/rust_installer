#!/usr/bin/env cargo script

//! Пример базового использования модуля install
//! 
//! Запуск: `cargo run --example basic_usage`

use openvair_installer::install::{log, execute, Color, constants};
use anyhow::Result;

fn main() -> Result<()> {
    // Начальное логирование
    log(Color::Cyan, "=== Open vAIR Installer Example ===");
    
    // Показать системную информацию
    log(Color::Cyan, "Detecting system information...");
    println!("  OS: {}", &*constants::OS);
    println!("  Architecture: {} ({})", &*constants::ARCH, constants::get_proc());
    log(Color::Green, "System detection completed");
    
    // Показать пути конфигурации
    println!();
    log(Color::Cyan, "Configuration paths:");
    println!("  User: {}", constants::USER);
    println!("  User Path: {}", &*constants::USER_PATH);
    println!("  Project Path: {}", &*constants::PROJECT_PATH);
    println!("  Config File: {}", &*constants::PROJECT_CONFIG_FILE);
    println!("  Log File: {}", &*constants::LOG_FILE);
    
    // Выполнить несколько тестовых команд
    println!();
    log(Color::Cyan, "Testing command execution...");
    
    execute("echo 'Testing basic echo'", "Basic echo test")?;
    execute("whoami", "Get current user")?;
    execute("pwd", "Show current directory")?;
    execute("date", "Show current date and time")?;
    
    // Завершение
    println!();
    log(Color::Green, "All tests completed successfully!");
    log(Color::Cyan, &format!("Check the log file at: {}", &*constants::LOG_FILE));
    
    Ok(())
}
