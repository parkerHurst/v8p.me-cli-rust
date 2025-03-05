use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, Nonce};
use anyhow::{Context, Result, anyhow};
use clap::{Parser, ArgAction};
use copypasta::{ClipboardContext, ClipboardProvider};
use indicatif::{ProgressBar, ProgressStyle};
use mime_guess::from_path;
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use regex::Regex;
use sha2::Sha256;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::str::FromStr;

// Encryption parameters
const ITERATIONS: u32 = 100_000;
const CHUNK_SIZE: usize = 1_000_000; // 1MB per chunk
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TMP_FILE: &str = "v8p.me-cli.tmp";

#[derive(Parser)]
#[command(name = "v8p")]
#[command(about = "A CLI tool for encrypting and uploading files to v8p.me")]
#[command(version)]
struct Config {
    /// Set custom server instead of default (https://v8p.me)
    #[arg(short, long, default_value = "https://v8p.me")]
    server: String,

    /// Automatically copy returned URL to clipboard
    #[arg(short, long, action = ArgAction::SetTrue)]
    copy: bool,

    /// Enable encryption and set password
    #[arg(short, long)]
    password: Option<String>,

    /// Set expiry date of file (e.g., -e 1d, -e "5 minutes")
    #[arg(short, long, default_value = "0m")]
    expires: String,

    /// Override filename sent to server
    #[arg(short, long)]
    filename: Option<String>,

    /// Skip upload and save encrypted file to disk as specified filename
    #[arg(short, long)]
    dry: Option<String>,

    /// Suppress all output except the URL
    #[arg(short, long, action = ArgAction::SetTrue)]
    quiet: bool,

    /// File to upload
    file_path: String,
}

fn main() -> Result<()> {
    let config = Config::parse();
    
    // Set up quiet mode if requested
    let quiet = config.quiet;
    
    let mut to_upload_file = TMP_FILE.to_string();
    if let Some(dry_filename) = &config.dry {
        to_upload_file = dry_filename.clone();
    }
    
    // Parse expiry time
    let expires = parse_expiry(&config.expires)
        .context("Failed to parse expiry time")?;
    
    // Check if file exists
    let file_metadata = fs::metadata(&config.file_path)
        .context("Failed to access file")?;
    
    // Determine server filename
    let server_filename = match &config.filename {
        Some(name) => name.clone(),
        None => Path::new(&config.file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    };
    
    // Determine if we're encrypting
    let is_encrypting = config.password.is_some();
    
    if is_encrypting {
        // Set up progress bar for encryption
        let bar = if !quiet {
            let pb = ProgressBar::new(file_metadata.len());
            pb.set_style(ProgressStyle::default_bar()
                .template("[cyan][1/2][reset] encrypting file... {bar:40.cyan/blue} {bytes}/{total_bytes} ({eta})")
                .unwrap());
            Some(pb)
        } else {
            None
        };
        
        // Encrypt the file
        encrypt_file(
            &config.file_path,
            &to_upload_file,
            config.password.as_ref().unwrap(),
            bar.as_ref(),
        ).context("Failed to encrypt file")?;
        
        if !quiet {
            println!();
        }
        
        // If dry run, we're done
        if config.dry.is_some() {
            if !quiet {
                println!("encryption complete!");
            }
            return Ok(());
        }
        
        if !quiet {
            println!("encryption complete! initializing upload...");
        }
    } else {
        // No encryption, just upload the original file
        to_upload_file = config.file_path.clone();
    }
    
    // Get file metadata for the file we're uploading
    let upload_metadata = fs::metadata(&to_upload_file)
        .context("Failed to access file to upload")?;
    
    // Set up progress bar for upload
    let option_str = if is_encrypting { "[2/2]" } else { "[1/1]" };
    
    let bar = if !quiet {
        let pb = ProgressBar::new(upload_metadata.len());
        pb.set_style(ProgressStyle::default_bar()
            .template(&format!("[cyan]{}[reset] uploading file... {{bar:40.cyan/blue}} {{bytes}}/{{total_bytes}} ({{eta}})", option_str))
            .unwrap());
        Some(pb)
    } else {
        None
    };
    
    // Upload the file
    let api_url = format!("{}/api", config.server);
    let alias = stream_file_upload(
        &to_upload_file,
        &api_url,
        &file_metadata,
        &server_filename,
        is_encrypting,
        expires as i64,
        bar.as_ref(),
    ).context("Failed to upload file")?;
    
    if !quiet {
        println!();
        println!();
        println!("upload complete!");
    }
    
    // Construct the final URL
    let file_url = format!("{}/{}", config.server, alias);
    
    // Copy to clipboard if requested
    if config.copy {
        let mut ctx = ClipboardContext::new().unwrap();
        if let Err(e) = ctx.set_contents(file_url.clone()) {
            if !quiet {
                eprintln!("error copying to clipboard: {}", e);
            }
        } else if !quiet {
            println!("(wrote to clipboard)");
        }
    }
    
    // Print the URL
    println!("\x1B[1m{}\x1B[0m", file_url);
    
    // Clean up temporary file if we encrypted
    if is_encrypting && config.dry.is_none() {
        if let Err(e) = fs::remove_file(&to_upload_file) {
            if !quiet {
                eprintln!("error while deleting file: {}", e);
            }
        }
    }
    
    Ok(())
}

fn encrypt_file(
    filename: &str,
    encrypted_output: &str,
    password: &str,
    progress_bar: Option<&ProgressBar>,
) -> Result<()> {
    let mut file = File::open(filename)
        .context("Failed to open input file")?;
    
    let mut out_file = File::create(encrypted_output)
        .context("Failed to create output file")?;
    
    // Generate and write salt
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    out_file.write_all(&salt)
        .context("Failed to write salt")?;
    
    // Derive key from password and salt
    let mut key = [0u8; 32]; // 256 bits
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, ITERATIONS, &mut key);
    
    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Failed to create cipher: {:?}", e))?;
    
    // Process file in chunks
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf)
            .context("Failed to read from file")?;
        
        if n == 0 {
            break;
        }
        
        // Update progress bar
        if let Some(bar) = progress_bar {
            bar.inc(n as u64);
        }
        
        let plaintext = &buf[..n];
        
        // Generate nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);
        
        // Encrypt chunk
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;
        
        // Write nonce and ciphertext
        out_file.write_all(&nonce_bytes)
            .context("Failed to write nonce")?;
        out_file.write_all(&ciphertext)
            .context("Failed to write ciphertext")?;
    }
    
    Ok(())
}

fn stream_file_upload(
    file_path: &str,
    api_path: &str,
    og_file_info: &fs::Metadata,
    server_filename: &str,
    encrypted: bool,
    expires: i64,
    progress_bar: Option<&ProgressBar>,
) -> Result<String> {
    // Implementation using reqwest's blocking client
    // for HTTP requests with progress reporting
    
    let file = File::open(file_path)
        .context("Failed to open file for upload")?;
    
    let file_size = file.metadata()?.len();
    
    // Create a buffer that reports progress
    let mut file_data = Vec::new();
    let mut reader = io::BufReader::new(file);
    reader.read_to_end(&mut file_data)?;
    
    // Update progress bar with total read
    if let Some(bar) = progress_bar {
        bar.inc(file_size);
    }
    
    // Create a client
    let client = Client::new();
    
    // Set headers
    let mut headers = HeaderMap::new();
    
    let file_type = from_path(server_filename)
        .first_or_octet_stream()
        .to_string();
    
    let encrypted_str = if encrypted { "1" } else { "0" };
    
    headers.insert(
        HeaderName::from_str("X-File-Name").unwrap(), 
        HeaderValue::from_str(&urlencoding::encode(server_filename)).unwrap()
    );
    headers.insert(
        HeaderName::from_str("X-File-Type").unwrap(), 
        HeaderValue::from_str(&file_type).unwrap()
    );
    headers.insert(
        HeaderName::from_str("X-File-Size").unwrap(), 
        HeaderValue::from_str(&og_file_info.len().to_string()).unwrap()
    );
    headers.insert(
        HeaderName::from_str("X-Encrypted").unwrap(), 
        HeaderValue::from_str(encrypted_str).unwrap()
    );
    headers.insert(
        HeaderName::from_str("Content-Length").unwrap(), 
        HeaderValue::from_str(&file_size.to_string()).unwrap()
    );
    headers.insert(
        HeaderName::from_str("Content-Type").unwrap(), 
        HeaderValue::from_str("application/octet-stream").unwrap()
    );
    
    if expires > 0 {
        let expiration_date = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64 + expires;
        
        headers.insert(
            HeaderName::from_str("X-Expiration-Date").unwrap(), 
            HeaderValue::from_str(&expiration_date.to_string()).unwrap()
        );
    }
    
    // Send request
    let response = client.post(api_path)
        .headers(headers)
        .body(file_data)
        .send()
        .context("Failed to send request")?;
    
    if !response.status().is_success() {
        return Err(anyhow!("Unexpected error: {}", response.status()));
    }
    
    let response_text = response.text()?;
    Ok(urlencoding::encode(&response_text).into_owned())
}

fn parse_expiry(expiry_str: &str) -> Result<u64> {
    let re = Regex::new(r"^([\d.]+)\s*([a-zA-Z]+)$")?;
    
    let captures = re.captures(expiry_str.trim())
        .ok_or_else(|| anyhow!("Could not parse expiry string: {}", expiry_str))?;
    
    let value: f64 = captures[1].parse()
        .context("Failed to parse expiry value")?;
    
    let unit = captures[2].to_lowercase();
    
    let multiplier = match unit.as_str() {
        "m" | "min" | "mins" | "minute" | "minutes" => 60.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3600.0,
        "d" | "day" | "days" => 86400.0,
        "w" | "week" | "weeks" => 604800.0,
        "mo" | "month" | "months" => 2629800.0,
        "y" | "yr" | "year" | "years" => 31557600.0,
        _ => return Err(anyhow!("Unknown time unit: {}", unit)),
    };
    
    Ok((value * multiplier) as u64)
}
