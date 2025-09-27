use serde::{Serialize, Deserialize};
use std::{fs::File, io::{Read, Write, self}};
use anyhow::Result;
use bincode;
use std::path::Path;
use sha2::{Sha256, Digest};
use flate2::{Compression, write::ZlibEncoder};
use std::io::prelude::*;
use rand::{SeedableRng};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use chrono::{DateTime, Utc, Duration, Local, TimeZone, NaiveDateTime};

#[derive(Serialize, Deserialize, Debug)]
enum PexVersion {
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
    V7,
    V8,
}

#[derive(Serialize, Deserialize, Debug)]
enum PayloadType {
    Executable,
    Library { entry_point: String },
}

#[derive(Serialize, Deserialize, Debug)]
struct ExpirationConfig {
    creation_timestamp: i64,
    expiration_timestamp: i64,
    grace_period_hours: u32,
}

#[derive(Serialize, Deserialize)]
struct PexFileV1 {
    filename: String,
    obfuscated_data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct PexFileV2 {
    version: PexVersion,
    filename: String,
    obfuscated_data: Vec<u8>,
    sort_map: Vec<usize>,
}

#[derive(Serialize, Deserialize)]
struct PexFileV3 {
    version: PexVersion,
    filename: String,
    obfuscated_data: Vec<u8>,
    sort_map: Vec<usize>,
    integrity_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct PexFileV4 {
    version: PexVersion,
    filename: String,
    obfuscated_data: Vec<u8>,
    sort_map: Vec<usize>,
    integrity_hash: Vec<u8>,
    original_size: u64,
    compressed_size: u64,
}

#[derive(Serialize, Deserialize)]
struct PexFileV5 {
    version: PexVersion,
    filename: String,
    obfuscated_data: Vec<u8>,
    sort_map: Vec<usize>,
    integrity_hash: Vec<u8>,
    original_size: u64,
    compressed_size: u64,
    sort_salt: u64,
}

#[derive(Serialize, Deserialize)]
struct PexFileV6 {
    version: PexVersion,
    filename: String,
    obfuscated_data: Vec<u8>,
    encrypted_sort_map: Vec<u8>,
    integrity_hash: Vec<u8>,
    original_size: u64,
    compressed_size: u64,
    sort_salt: u64,
    map_key_salt: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct PexFileV7 {
    version: PexVersion,
    filename: String,
    payload_type: PayloadType,
    obfuscated_data: Vec<u8>,
    encrypted_sort_map: Vec<u8>,
    integrity_hash: Vec<u8>,
    original_size: u64,
    compressed_size: u64,
    sort_salt: u64,
    map_key_salt: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct PexFileV8 {
    version: PexVersion,
    filename: String,
    payload_type: PayloadType,
    obfuscated_data: Vec<u8>,
    encrypted_sort_map: Vec<u8>,
    integrity_hash: Vec<u8>,
    original_size: u64,
    compressed_size: u64,
    sort_salt: u64,
    map_key_salt: Vec<u8>,
    encrypted_expiration: Vec<u8>,
    time_key_salt: Vec<u8>,
}

// Helper functions (same as previous version, but adapted for V8)
fn xor_obfuscate(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

fn generate_file_salt(data: &[u8]) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update(b"PEX_V6_SALT");
    let hash = hasher.finalize();
    u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
    ])
}

fn generate_map_key_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut salt = vec![0u8; 32];
    rng.fill_bytes(&mut salt);
    salt
}

fn generate_time_key_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut salt = vec![0u8; 32];
    rng.fill_bytes(&mut salt);
    salt
}

fn derive_map_key(obfuscated_data: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(obfuscated_data);
    hasher.update(salt);
    hasher.update(b"PEX_V6_MAP_KEY_DERIVATION");
    hasher.finalize().to_vec()
}

fn derive_time_key(obfuscated_data: &[u8], time_salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(obfuscated_data);
    hasher.update(time_salt);
    hasher.update(b"PEX_V8_TIME_KEY_DERIVATION");
    hasher.finalize().to_vec()
}

fn encrypt_sort_map(sort_map: &[usize], key: &[u8]) -> Result<Vec<u8>> {
    let serialized_map = bincode::serialize(sort_map)?;
    let encrypted = xor_obfuscate(&serialized_map, key);
    Ok(encrypted)
}

fn encrypt_expiration_config(config: &ExpirationConfig, key: &[u8]) -> Result<Vec<u8>> {
    let serialized_config = bincode::serialize(config)?;
    let encrypted = xor_obfuscate(&serialized_config, key);
    Ok(encrypted)
}

fn conditional_sort_binary_with_map(data: &[u8], salt: u64) -> (Vec<u8>, Vec<usize>) {
    let mut indexed_data: Vec<(u8, usize)> = data.iter()
        .enumerate()
        .map(|(i, &byte)| (byte, i))
        .collect();
    indexed_data.sort_by_key(|(byte, _)| *byte);
    let mut rng = StdRng::seed_from_u64(salt);
    let mut current_byte = None;
    let mut group_start = 0;
    for i in 0..=indexed_data.len() {
        let byte_changed = i == indexed_data.len() ||
            current_byte.map_or(true, |b| b != indexed_data[i].0);
        if byte_changed && current_byte.is_some() {
            let group = &mut indexed_data[group_start..i];
            if group.len() > 1 {
                group.shuffle(&mut rng);
            }
            group_start = i;
        }
        if i < indexed_data.len() {
            current_byte = Some(indexed_data[i].0);
        }
    }
    let sorted_data: Vec<u8> = indexed_data.iter().map(|(byte, _)| *byte).collect();
    let sort_map: Vec<usize> = indexed_data.iter().map(|(_, orig_index)| *orig_index).collect();
    (sorted_data, sort_map)
}

fn sort_binary_with_map(data: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let mut indexed_data: Vec<(u8, usize)> = data.iter()
        .enumerate()
        .map(|(i, &byte)| (byte, i))
        .collect();
    indexed_data.sort_by_key(|(byte, _)| *byte);
    let sorted_data: Vec<u8> = indexed_data.iter().map(|(byte, _)| *byte).collect();
    let sort_map: Vec<usize> = indexed_data.iter().map(|(_, orig_index)| *orig_index).collect();
    (sorted_data, sort_map)
}

fn calculate_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data)?;
    let compressed = encoder.finish()?;
    Ok(compressed)
}

fn detect_file_type(path: &str) -> Result<PayloadType> {
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_lowercase());
    match extension.as_deref() {
        Some("exe") => Ok(PayloadType::Executable),
        Some("dll") => {
            println!("DLL detected! Please specify the entry point function name:");
            print!("Function name (case-sensitive): ");
            io::stdout().flush()?;
            let mut func_name = String::new();
            io::stdin().read_line(&mut func_name)?;
            let func_name = func_name.trim().to_string();
            if func_name.is_empty() {
                return Err(anyhow::anyhow!("Function name cannot be empty"));
            }
            println!("Entry point set to: {}", func_name);
            Ok(PayloadType::Library { entry_point: func_name })
        },
        _ => {
            println!("Unknown file type. Treating as executable...");
            Ok(PayloadType::Executable)
        }
    }
}

fn get_expiration_settings() -> Result<ExpirationConfig> {
    println!("=== Time-Based Expiration Configuration ===");
    println!("Current local time: {}", Local::now().format("%Y-%m-%d %H:%M:%S"));
    println!("Current UTC time: {}", Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    println!();
    println!("1. Set expiration date (local time)");
    println!("2. Set expiration in X days from now");
    println!("3. No expiration (permanent)");
    
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    
    let now = Utc::now();
    let creation_timestamp = now.timestamp();
    
    match choice.trim() {
        "1" => {
            println!("Enter expiration date and time in your LOCAL timezone:");
            println!("Format: YYYY-MM-DD HH:MM");
            println!("Example: 2024-12-25 14:30");
            println!();
            print!("Expiration date/time: ");
            io::stdout().flush()?;
            
            let mut date_input = String::new();
            io::stdin().read_line(&mut date_input)?;
            let date_input = date_input.trim();
            
            // Parse as naive datetime first
            let naive_dt = NaiveDateTime::parse_from_str(date_input, "%Y-%m-%d %H:%M")
                .map_err(|e| anyhow::anyhow!("Invalid date format. Use YYYY-MM-DD HH:MM. Error: {}", e))?;
            
            // Convert from local timezone to UTC
            let local_dt = Local.from_local_datetime(&naive_dt).single()
                .ok_or_else(|| anyhow::anyhow!("Ambiguous local time (likely during DST transition)"))?;
            let utc_dt = local_dt.with_timezone(&Utc);
            
            println!("Parsed as local time: {}", local_dt.format("%Y-%m-%d %H:%M:%S %Z"));
            println!("Converted to UTC: {}", utc_dt.format("%Y-%m-%d %H:%M:%S UTC"));
            
            println!();
            println!("Enter grace period in hours after expiration (0-168):");
            print!("Grace period hours: ");
            io::stdout().flush()?;
            
            let mut grace_input = String::new();
            io::stdin().read_line(&mut grace_input)?;
            let grace_period_hours: u32 = grace_input.trim().parse()
                .map_err(|_| anyhow::anyhow!("Invalid number for grace period"))?;
            
            if grace_period_hours > 168 {
                return Err(anyhow::anyhow!("Grace period cannot exceed 168 hours (1 week)"));
            }
            
            Ok(ExpirationConfig {
                creation_timestamp,
                expiration_timestamp: utc_dt.timestamp(),
                grace_period_hours,
            })
        },
        "2" => {
            println!("Enter number of days until expiration (1-365):");
            print!("Days: ");
            io::stdout().flush()?;
            
            let mut days_input = String::new();
            io::stdin().read_line(&mut days_input)?;
            let days: i64 = days_input.trim().parse()
                .map_err(|_| anyhow::anyhow!("Invalid number for days"))?;
            
            if days < 1 || days > 365 {
                return Err(anyhow::anyhow!("Days must be between 1 and 365"));
            }
            
            let expiration_dt = now + Duration::days(days);
            
            println!("Will expire on: {} (UTC)", expiration_dt.format("%Y-%m-%d %H:%M:%S"));
            println!("Local time: {}", expiration_dt.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S %Z"));
            
            println!();
            println!("Enter grace period in hours after expiration (0-168):");
            print!("Grace period hours: ");
            io::stdout().flush()?;
            
            let mut grace_input = String::new();
            io::stdin().read_line(&mut grace_input)?;
            let grace_period_hours: u32 = grace_input.trim().parse()
                .map_err(|_| anyhow::anyhow!("Invalid number for grace period"))?;
            
            if grace_period_hours > 168 {
                return Err(anyhow::anyhow!("Grace period cannot exceed 168 hours (1 week)"));
            }
            
            Ok(ExpirationConfig {
                creation_timestamp,
                expiration_timestamp: expiration_dt.timestamp(),
                grace_period_hours,
            })
        },
        "3" => {
            println!("Setting as permanent (no expiration)");
            // Set expiration far in the future (year 2099)
            let far_future = Utc::now() + Duration::days(365 * 75); // ~75 years
            
            Ok(ExpirationConfig {
                creation_timestamp,
                expiration_timestamp: far_future.timestamp(),
                grace_period_hours: 0,
            })
        },
        _ => {
            println!("Invalid choice, defaulting to 30 days from now with 24 hour grace period");
            let expiration_dt = now + Duration::days(30);
            
            Ok(ExpirationConfig {
                creation_timestamp,
                expiration_timestamp: expiration_dt.timestamp(),
                grace_period_hours: 24,
            })
        }
    }
}

// --- PACKER FUNCTIONS FOR EACH VERSION ---
// V8
fn pack_v8(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}.pex", file_name_only);
    let expiration_config = get_expiration_settings()?;
    let creation_dt = DateTime::from_timestamp(expiration_config.creation_timestamp, 0)
        .unwrap_or_else(|| Utc::now());
    let expiration_dt = DateTime::from_timestamp(expiration_config.expiration_timestamp, 0)
        .unwrap_or_else(|| Utc::now() + Duration::days(30));
    println!("Expiration configuration:");
    println!("  Created: {}", creation_dt.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Expires: {}", expiration_dt.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Grace period: {} hours", expiration_config.grace_period_hours);

    let payload_type = detect_file_type(input_path)?;
    println!("Payload type: {:?}", payload_type);

    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    let original_size = buffer.len() as u64;
    println!("Original file size: {} bytes", original_size);

    let sort_salt = generate_file_salt(&buffer);
    println!("Generated sort salt: 0x{:016x}", sort_salt);
    let integrity_hash = calculate_sha256(&buffer);
    println!("Calculated integrity hash: {}", hex::encode(&integrity_hash));

    let compressed_data = compress_data(&buffer)?;
    let compressed_size = compressed_data.len() as u64;
    let compression_ratio = (original_size - compressed_size) as f64 / original_size as f64 * 100.0;
    println!("Compressed size: {} bytes ({:.1}% reduction)", compressed_size, compression_ratio);

    println!("  Applying conditional binary sorting...");
    let (sorted_data, sort_map) = conditional_sort_binary_with_map(&compressed_data, sort_salt);
    println!("Generated sort map with {} entries", sort_map.len());

    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V8";
    let obfuscated_data = xor_obfuscate(&sorted_data, key);

    let map_key_salt = generate_map_key_salt();
    let time_key_salt = generate_time_key_salt();
    println!("Generated map key salt: {}", hex::encode(&map_key_salt));
    println!("Generated time key salt: {}", hex::encode(&time_key_salt));

    let map_key = derive_map_key(&obfuscated_data, &map_key_salt);
    let time_key = derive_time_key(&obfuscated_data, &time_key_salt);
    println!("Derived encryption keys from payload");

    let encrypted_sort_map = encrypt_sort_map(&sort_map, &map_key)?;
    let encrypted_expiration = encrypt_expiration_config(&expiration_config, &time_key)?;
    println!("Encrypted sort map ({} bytes)", encrypted_sort_map.len());
    println!("Encrypted expiration config ({} bytes)", encrypted_expiration.len());

    let pex_v8 = PexFileV8 {
        version: PexVersion::V8,
        filename: file_name_only.clone(),
        payload_type,
        obfuscated_data,
        encrypted_sort_map,
        integrity_hash,
        original_size,
        compressed_size,
        sort_salt,
        map_key_salt,
        encrypted_expiration,
        time_key_salt,
    };

    let encoded = bincode::serialize(&pex_v8)?;
    let mut out = File::create(&output_path)?;
    out.write_all(&encoded)?;

    let final_size = encoded.len();
    println!("Final .pex file size: {} bytes", final_size);
    println!("Packed (V8) with time-based expiration {} -> {}", input_path, output_path);
    println!("V8 features: Time-based expiration + DLL Support + PDMO + Conditional sorting + Compression + SHA-256 integrity");
    Ok(())
}

// V7
fn pack_v7(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}.pex", file_name_only);

    let payload_type = detect_file_type(input_path)?;
    println!("Payload type: {:?}", payload_type);

    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    let original_size = buffer.len() as u64;
    println!("Original file size: {} bytes", original_size);

    let sort_salt = generate_file_salt(&buffer);
    println!("Generated sort salt: 0x{:016x}", sort_salt);

    let integrity_hash = calculate_sha256(&buffer);
    println!("Calculated integrity hash: {}", hex::encode(&integrity_hash));

    let compressed_data = compress_data(&buffer)?;
    let compressed_size = compressed_data.len() as u64;
    let compression_ratio = (original_size - compressed_size) as f64 / original_size as f64 * 100.0;
    println!("Compressed size: {} bytes ({:.1}% reduction)", compressed_size, compression_ratio);

    println!("  Applying conditional binary sorting...");
    let (sorted_data, sort_map) = conditional_sort_binary_with_map(&compressed_data, sort_salt);
    println!("Generated sort map with {} entries", sort_map.len());

    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V7";
    let obfuscated_data = xor_obfuscate(&sorted_data, key);

    let map_key_salt = generate_map_key_salt();
    println!("Generated map key salt: {}", hex::encode(&map_key_salt));

    let map_key = derive_map_key(&obfuscated_data, &map_key_salt);
    println!("Derived map encryption key from payload");

    let encrypted_sort_map = encrypt_sort_map(&sort_map, &map_key)?;
    println!("Encrypted sort map ({} bytes)", encrypted_sort_map.len());

    let pex_v7 = PexFileV7 {
        version: PexVersion::V7,
        filename: file_name_only.clone(),
        payload_type,
        obfuscated_data,
        encrypted_sort_map,
        integrity_hash,
        original_size,
        compressed_size,
        sort_salt,
        map_key_salt,
    };

    let encoded = bincode::serialize(&pex_v7)?;
    let mut out = File::create(&output_path)?;
    out.write_all(&encoded)?;

    let final_size = encoded.len();
    println!("Final .pex file size: {} bytes", final_size);
    println!("Packed (V7) with DLL support {} -> {}", input_path, output_path);
    println!("V7 features: DLL Support + PDMO + Conditional sorting + Compression + SHA-256 integrity");
    Ok(())
}

// V6
fn pack_v6(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}.pex", file_name_only);

    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    let original_size = buffer.len() as u64;
    println!("Original file size: {} bytes", original_size);

    let sort_salt = generate_file_salt(&buffer);
    println!("Generated sort salt: 0x{:016x}", sort_salt);

    let integrity_hash = calculate_sha256(&buffer);
    println!("Calculated integrity hash: {}", hex::encode(&integrity_hash));

    let compressed_data = compress_data(&buffer)?;
    let compressed_size = compressed_data.len() as u64;
    let compression_ratio = (original_size - compressed_size) as f64 / original_size as f64 * 100.0;
    println!("Compressed size: {} bytes ({:.1}% reduction)", compressed_size, compression_ratio);

    println!("  Applying conditional binary sorting...");
    let (sorted_data, sort_map) = conditional_sort_binary_with_map(&compressed_data, sort_salt);
    println!("Generated sort map with {} entries", sort_map.len());

    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V6";
    let obfuscated_data = xor_obfuscate(&sorted_data, key);

    let map_key_salt = generate_map_key_salt();
    println!("Generated map key salt: {}", hex::encode(&map_key_salt));

    let map_key = derive_map_key(&obfuscated_data, &map_key_salt);
    println!("Derived map encryption key from payload");

    let encrypted_sort_map = encrypt_sort_map(&sort_map, &map_key)?;
    println!("Encrypted sort map ({} bytes)", encrypted_sort_map.len());

    let pex_v6 = PexFileV6 {
        version: PexVersion::V6,
        filename: file_name_only.clone(),
        obfuscated_data,
        encrypted_sort_map,
        integrity_hash,
        original_size,
        compressed_size,
        sort_salt,
        map_key_salt,
    };

    let encoded = bincode::serialize(&pex_v6)?;
    let mut out = File::create(&output_path)?;
    out.write_all(&encoded)?;

    let final_size = encoded.len();
    println!("Final .pex file size: {} bytes", final_size);
    println!("Packed (V6) with PDMO {} -> {}", input_path, output_path);
    println!("V6 features: Payload-Derived Map Obfuscation + Conditional sorting + Compression + SHA-256 integrity");
    Ok(())
}

// V5
fn pack_v5(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}_v5.pex", file_name_only);

    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    let original_size = buffer.len() as u64;
    println!("Original file size: {} bytes", original_size);

    let sort_salt = generate_file_salt(&buffer);
    println!("Generated sort salt: 0x{:016x}", sort_salt);

    let integrity_hash = calculate_sha256(&buffer);
    println!("Calculated integrity hash: {}", hex::encode(&integrity_hash));

    let compressed_data = compress_data(&buffer)?;
    let compressed_size = compressed_data.len() as u64;
    let compression_ratio = (original_size - compressed_size) as f64 / original_size as f64 * 100.0;
    println!("Compressed size: {} bytes ({:.1}% reduction)", compressed_size, compression_ratio);

    println!("  Applying conditional binary sorting...");
    let (sorted_data, sort_map) = conditional_sort_binary_with_map(&compressed_data, sort_salt);
    println!("Generated sort map with {} entries", sort_map.len());

    let unique_bytes: std::collections::HashSet<u8> = sorted_data.iter().cloned().collect();
    println!("Unique byte values in compressed data: {}", unique_bytes.len());

    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V5";
    let obfuscated_data = xor_obfuscate(&sorted_data, key);

    let pex_v5 = PexFileV5 {
        version: PexVersion::V5,
        filename: file_name_only.clone(),
        obfuscated_data,
        sort_map,
        integrity_hash,
        original_size,
        compressed_size,
        sort_salt,
    };

    let encoded = bincode::serialize(&pex_v5)?;
    let mut out = File::create(&output_path)?;
    out.write_all(&encoded)?;

    let final_size = encoded.len();
    println!("Final .pex file size: {} bytes", final_size);
    println!("Packed (V5) with conditional sorting {} -> {}", input_path, output_path);
    println!("V5 features: Conditional sorting + Compression + SHA-256 integrity verification");
    Ok(())
}

// V4
fn pack_v4(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}_v4.pex", file_name_only);

    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    let original_size = buffer.len() as u64;
    println!("Original file size: {} bytes", original_size);

    let integrity_hash = calculate_sha256(&buffer);
    println!("Calculated integrity hash: {}", hex::encode(&integrity_hash));

    let compressed_data = compress_data(&buffer)?;
    let compressed_size = compressed_data.len() as u64;
    let compression_ratio = (original_size - compressed_size) as f64 / original_size as f64 * 100.0;
    println!("Compressed size: {} bytes ({:.1}% reduction)", compressed_size, compression_ratio);

    let (sorted_data, sort_map) = sort_binary_with_map(&compressed_data);
    println!("Generated sort map with {} entries", sort_map.len());

    let unique_bytes: std::collections::HashSet<u8> = sorted_data.iter().cloned().collect();
    println!("Unique byte values in compressed data: {}", unique_bytes.len());

    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V4";
    let obfuscated_data = xor_obfuscate(&sorted_data, key);

    let pex_v4 = PexFileV4 {
        version: PexVersion::V4,
        filename: file_name_only.clone(),
        obfuscated_data,
        sort_map,
        integrity_hash,
        original_size,
        compressed_size,
    };

    let encoded = bincode::serialize(&pex_v4)?;
    let mut out = File::create(&output_path)?;
    out.write_all(&encoded)?;

    let final_size = encoded.len();
    println!("Final .pex file size: {} bytes", final_size);
    println!("Packed (V4) with compression + integrity verification {} -> {}", input_path, output_path);
    println!("V4 features: Compression + Binary sorting + SHA-256 integrity verification");
    Ok(())
}

// V3
fn pack_v3(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}_v3.pex", file_name_only);

    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    println!("Original file size: {} bytes", buffer.len());

    let integrity_hash = calculate_sha256(&buffer);
    println!("Calculated integrity hash: {}", hex::encode(&integrity_hash));

    let (sorted_data, sort_map) = sort_binary_with_map(&buffer);
    println!("Generated sort map with {} entries", sort_map.len());

    let unique_bytes: std::collections::HashSet<u8> = sorted_data.iter().cloned().collect();
    println!("Unique byte values in file: {}", unique_bytes.len());

    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V3";
    let obfuscated_data = xor_obfuscate(&sorted_data, key);

    let pex_v3 = PexFileV3 {
        version: PexVersion::V3,
        filename: file_name_only.clone(),
        obfuscated_data,
        sort_map,
        integrity_hash,
    };

    let encoded = bincode::serialize(&pex_v3)?;
    let mut out = File::create(&output_path)?;
    out.write_all(&encoded)?;

    println!("Packed (V3) with integrity verification {} -> {}", input_path, output_path);
    println!("V3 features: Binary sorting + SHA-256 integrity verification");
    Ok(())
}

// V2
fn pack_v2(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}_v2.pex", file_name_only);

    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    println!("Original file size: {} bytes", buffer.len());

    let (sorted_data, sort_map) = sort_binary_with_map(&buffer);
    println!("Generated sort map with {} entries", sort_map.len());

    let unique_bytes: std::collections::HashSet<u8> = sorted_data.iter().cloned().collect();
    println!("Unique byte values in file: {}", unique_bytes.len());

    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V2";
    let obfuscated_data = xor_obfuscate(&sorted_data, key);

    let pex_v2 = PexFileV2 {
        version: PexVersion::V2,
        filename: file_name_only.clone(),
        obfuscated_data,
        sort_map,
    };

    let encoded = bincode::serialize(&pex_v2)?;
    let mut out = File::create(&output_path)?;
    out.write_all(&encoded)?;

    println!("Packed (V2) and obfuscated {} -> {}", input_path, output_path);
    println!("V2 features: Binary sorted before obfuscation for enhanced protection");
    Ok(())
}

// V1
fn pack_v1_legacy(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}_v1.pex", file_name_only);

    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit";
    let obfuscated_data = xor_obfuscate(&buffer, key);

    let pex_v1 = PexFileV1 {
        filename: file_name_only,
        obfuscated_data,
    };

    let encoded = bincode::serialize(&pex_v1)?;
    let mut out = File::create(&output_path)?;
    out.write_all(&encoded)?;

    println!("Packed (V1 Legacy) {} -> {}", input_path, output_path);
    Ok(())
}

// ---- Main ----
fn main() -> Result<()> {
    println!("PEX Packer V8 - Now with time-based expiration!");
    println!("Supports both EXE and DLL files with expiration dates");
    println!("Drag an EXE or DLL file into this window and press Enter:");

    let mut input_path = String::new();
    io::stdin().read_line(&mut input_path)?;
    let input_path = input_path.trim().trim_matches('"');

    if input_path.is_empty() {
        eprintln!("No file path provided. Exiting.");
        pause();
        return Ok(());
    }

    println!("Choose packing method:");
    println!("1. V8 (with time-based expiration + DLL support + PDMO)");
    println!("2. V7 (with DLL support + payload-derived map obfuscation)");
    println!("3. V6 (with payload-derived map obfuscation)");
    println!("4. V5 (with conditional binary sorting)");
    println!("5. V4 (with compression + integrity verification)");
    println!("6. V3 (with integrity verification)");
    println!("7. V2 (with binary sorting)");
    println!("8. V1 (legacy compatibility)");
    println!("9. All versions");

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;

    match choice.trim() {
        "1" => pack_v8(input_path)?,
        "2" => pack_v7(input_path)?,
        "3" => pack_v6(input_path)?,
        "4" => pack_v5(input_path)?,
        "5" => pack_v4(input_path)?,
        "6" => pack_v3(input_path)?,
        "7" => pack_v2(input_path)?,
        "8" => pack_v1_legacy(input_path)?,
        "9" => {
            let payload_type = detect_file_type(input_path)?;
            match payload_type {
                PayloadType::Library { .. } => {
                    println!("DLL detected - only packing as V8 and V7 (previous versions don't support DLLs)");
                    pack_v8(input_path)?;
                    pack_v7(input_path)?;
                },
                PayloadType::Executable => {
                    pack_v8(input_path)?;
                    pack_v7(input_path)?;
                    pack_v6(input_path)?;
                    pack_v5(input_path)?;
                    pack_v4(input_path)?;
                    pack_v3(input_path)?;
                    pack_v2(input_path)?;
                    pack_v1_legacy(input_path)?;
                }
            }
        },
        _ => {
            println!("Invalid choice, defaulting to V8");
            pack_v8(input_path)?;
        }
    }

    pause();
    Ok(())
}

fn pause() {
    println!("Press Enter to exit...");
    let _ = io::stdout().flush();
    let mut buffer = String::new();
    let _ = io::stdin().read_line(&mut buffer);
}