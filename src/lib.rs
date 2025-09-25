//! # OpenVAir Installer
//! 
//! Rust аналог функций установки OpenVAir, портированный из bash скрипта.
//! 
//! Предоставляет функции для цветного логирования, выполнения shell команд
//! и константы конфигурации, совместимые с оригинальным bash скриптом.
//! 
//! ## Основное использование
//! 
//! ```rust
//! use openvair_installer::install::{log, execute, Color, constants};
//! 
//! // Логирование с цветами
//! log(Color::Cyan, "Инициализация установщика...");
//! log(Color::Green, "Система готова к установке");
//! 
//! // Выполнение команд  
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! execute("echo 'Hello World'", "Print hello message")?;
//! 
//! // Доступ к константам
//! println!("Пользователь: {}", constants::USER);
//! println!("Проект: {}", constants::PROJECT_NAME);
//! # Ok(())
//! # }
//! ```

pub mod install;

// Re-export commonly used items
pub use install::{log, execute, stop_script, create_jwt_secret, Color, colors, constants};
