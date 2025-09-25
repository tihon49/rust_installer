# OpenVAir Installer

Rust аналог функций установки OpenVAir, портированный из bash скрипта `install.sh`.

## Особенности

- ✅ Цветное логирование с автоматическими временными метками
- ✅ Выполнение shell команд с логированием результатов  
- ✅ Автоматическое определение ОС и архитектуры
- ✅ Константы конфигурации, совместимые с оригинальным bash скриптом
- ✅ Потокобезопасная запись в лог файл
- ✅ Обработка ошибок и автоматическая остановка при неудаче
- ✅ Создание JWT секретов с обновлением конфигурации

## Зависимости

```toml
[dependencies]
chrono = "0.4"
anyhow = "1.0"
once_cell = "1.19"
serde = { version = "1.0", features = ["derive"] }
toml = "0.8"
regex = "1.0"
```

## Использование

### Основные функции

```rust
use openvair_installer::install::{log, execute, create_jwt_secret, Color, constants};

fn main() {
    // Логирование с цветами
    log(Color::Cyan, "Инициализация установщика...");
    log(Color::Green, "Система готова к установке");
    log(Color::Red, "Критическая ошибка");

    // Выполнение команд
    execute("apt-get update", "Обновление списка пакетов").unwrap();
    execute("mkdir -p /tmp/test", "Создание временной директории").unwrap();
    
    // Создание JWT секрета
    create_jwt_secret().unwrap();
    
    // Доступ к константам
    println!("Пользователь: {}", constants::USER);
    println!("Проект: {}", constants::PROJECT_NAME);
    println!("Путь проекта: {}", &*constants::PROJECT_PATH);
    println!("Архитектура: {}", constants::get_proc());
}
```

### Константы

Модуль предоставляет все константы из оригинального bash скрипта:

```rust
// Основные константы
constants::USER                 // "aero"
constants::PROJECT_NAME         // "openvair"  
constants::DATABASE_NAME        // "openvair"
constants::DOCKER_CONTAINER_NAME // "postgres"

// Автоматически определяемые значения
&*constants::OS                 // "ubuntu" (определяется через lsb_release)
&*constants::ARCH               // "x86_64" (определяется через uname -m)  
constants::get_proc()           // "amd64" или "arm64"

// Пути
&*constants::USER_PATH          // "/opt/aero"
&*constants::PROJECT_PATH       // "/opt/aero/openvair"
&*constants::PROJECT_CONFIG_FILE // "/opt/aero/openvair/project_config.toml"
&*constants::LOG_FILE           // "/opt/aero/openvair/install.log"
```

### Цвета

```rust
use openvair_installer::install::{Color, colors};

// Через enum (рекомендуется)
log(Color::Red, "Ошибка");
log(Color::Green, "Успех"); 
log(Color::Cyan, "Информация");

// Прямое использование ANSI кодов
println!("{}Красный текст{}", colors::RED, colors::NC);
```

### Обработка ошибок

```rust
use anyhow::Result;

fn install_package() -> Result<()> {
    execute("apt-get install -y htop", "Установка htop")?;
    log(Color::Green, "Пакет установлен успешно");
    Ok(())
}

// При ошибке выполнения команды автоматически вызывается stop_script()
// который логирует ошибку и завершает программу с кодом 1
```

### Создание JWT секретов

```rust
use openvair_installer::create_jwt_secret;
use anyhow::Result;

fn setup_jwt() -> Result<()> {
    // Создает случайный 32-байтный секрет и обновляет project_config.toml
    create_jwt_secret()?;
    log(Color::Green, "JWT секрет создан успешно");
    Ok(())
}

// Пример содержимого project_config.toml после выполнения:
// [database]
// host = "127.0.0.1"
// port = 5432
// 
// [jwt]
// secret="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
```

## Установка и настройка

### Предварительные требования

- Rust 1.70+ (рекомендуется последняя стабильная версия)
- Системные утилиты: `lsb_release`, `uname`
- Linux/Unix система (протестировано на Ubuntu)

### Клонирование и сборка

```bash
# Клонировать репозиторий (если еще не клонирован)
cd /home/tihon49/work/ov-installer-tui/openvair_installer

# Установить зависимости и собрать проект
cargo build
```

## Запуск проекта

### Основной исполняемый файл

```bash
# Запуск основного приложения (демо с тестами функций)
cargo run
```

### Примеры использования

```bash
# Запуск базового примера
cargo run --example basic_usage

# Посмотреть список доступных примеров
ls examples/
```

### Использование как библиотеки

В вашем `Cargo.toml`:

```toml
[dependencies]
openvair_installer = { path = "../openvair_installer" }
```

В коде:

```rust
use openvair_installer::{log, execute, Color, constants};

fn main() {
    log(Color::Cyan, "Hello from OpenVAir installer!");
    execute("echo test", "Test command").unwrap();
}
```

## Тестирование

### Запуск всех тестов

```bash
# Запустить все unit тесты
cargo test

# Запустить тесты с подробным выводом
cargo test -- --nocapture

# Запустить конкретный тест
cargo test test_color_display
```

### Тесты документации

```bash
# Запустить doctests (примеры в документации)
cargo test --doc

# Запустить все тесты включая примеры
cargo test --all-targets
```

### Проверка кода

```bash
# Проверка без сборки (быстрая проверка ошибок)
cargo check

# Форматирование кода
cargo fmt

# Анализ кода (если установлен clippy)
cargo clippy
```

## Сборка

### Отладочная сборка

```bash
# Сборка с отладочной информацией (по умолчанию)
cargo build
```

### Релизная сборка

```bash
# Оптимизированная сборка для продакшена
cargo build --release

# Исполняемый файл будет в target/release/
./target/release/openvair_installer
```

### Генерация документации

```bash
# Генерация HTML документации
cargo doc --no-deps

# Открыть документацию в браузере
cargo doc --no-deps --open
```

## Пример вывода

```
[2025-09-25 18:38:09] Initializing OpenVAir installer...
[2025-09-25 18:38:09] System information loaded successfully

[2025-09-25 18:38:09] Configuration:
  User: aero
  Project: openvair
  OS: ubuntu
  Architecture: x86_64
  Processor: amd64
  User Path: /opt/aero
  Project Path: /opt/aero/openvair
  Config File: /opt/aero/openvair/project_config.toml
  Log File: /opt/aero/openvair/install.log

[2025-09-25 18:38:09] Start to execute: Test echo command
Testing command execution
[2025-09-25 18:38:09] Successfully executed: Test echo command
[2025-09-25 18:38:09] OpenVAir installer module test completed successfully!
```

## Архитектура

- **`colors`** - модуль с ANSI цветовыми константами
- **`Color`** - enum для типобезопасной работы с цветами
- **`constants`** - модуль со всеми константами конфигурации
- **`log()`** - функция цветного логирования с записью в файл
- **`execute()`** - функция выполнения shell команд
- **`stop_script()`** - функция аварийного завершения программы
- **`create_jwt_secret()`** - функция создания JWT секрета и обновления конфигурации

## Отличия от bash версии

1. **Типобезопасность** - Rust compiler проверяет типы на этапе компиляции
2. **Обработка ошибок** - Использование `Result<T, E>` для явной обработки ошибок
3. **Потокобезопасность** - Логирование в файл защищено Mutex
4. **Ленивая инициализация** - Системные константы вычисляются только при первом обращении
5. **Модульность** - Четкое разделение на модули и пространства имен

## Структура проекта

```
openvair_installer/
├── Cargo.toml           # Конфигурация проекта и зависимости
├── README.md           # Эта документация
├── src/
│   ├── lib.rs          # Экспорт библиотечного API
│   ├── main.rs         # Основной исполняемый файл (демо)
│   └── install.rs      # Основной модуль с функциями
├── examples/
│   ├── basic_usage.rs  # Базовый пример использования
│   └── jwt_example.rs  # Пример создания JWT секрета
└── target/             # Каталог сборки (создается автоматически)
    ├── debug/          # Отладочные сборки
    └── release/        # Релизные сборки
```

## Возможные проблемы и их решения

### Ошибки системных команд

```bash
# Если отсутствует lsb_release
sudo apt-get install lsb-release

# Если отсутствует uname (маловероятно на Unix-системах)
# Обычно входит в состав coreutils
```

### Права доступа для создания файлов логирования

```bash
# Создать необходимые директории заранее
sudo mkdir -p /opt/aero/openvair
sudo chown $USER:$USER /opt/aero/openvair

# Или изменить константы в коде на пути в home директории
```

### Тестирование без sudo привилегий

В тестовом окружении можно изменить константы путей на локальные:

```rust
// В src/install.rs, строки 59-64 - можно изменить на:
pub static USER_PATH: Lazy<String> = Lazy::new(|| {
    std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
});
```

## Совместимость

Все константы и поведение функций максимально совместимы с оригинальным bash скриптом для упрощения портирования существующей логики установки.

### Поддерживаемые ОС

- ✅ Ubuntu 20.04+
- ✅ Debian 10+
- ✅ Другие Linux дистрибутивы с `lsb_release`
- ❓ macOS (не тестировался, может потребовать адаптации)
- ❌ Windows (не поддерживается из-за зависимости от Unix команд)
