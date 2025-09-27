use serde::{Serialize, Deserialize};
use std::{fs, fs::File, io::Read, process::Command};
use tempfile::NamedTempFile;
use anyhow::Result;
use bincode;
use std::path::Path;
use sha2::{Sha256, Digest};
use flate2::read::ZlibDecoder;
use std::io::prelude::*;
use chrono::{DateTime, Utc};
use rand::{Rng, thread_rng};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};

#[cfg(target_os = "windows")]
use libloading::{Library, Symbol};

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

// XOR obfuscation with embedded key
fn xor_obfuscate(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

// Derive encryption key for sort map from obfuscated payload
fn derive_map_key(obfuscated_data: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(obfuscated_data);
    hasher.update(salt);
    hasher.update(b"PEX_V6_MAP_KEY_DERIVATION"); // V7/V8 uses the same derivation as V6
    hasher.finalize().to_vec()
}

// Derive time encryption key from payload and time salt
fn derive_time_key(obfuscated_data: &[u8], time_salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(obfuscated_data);
    hasher.update(time_salt);
    hasher.update(b"PEX_V8_TIME_KEY_DERIVATION");
    hasher.finalize().to_vec()
}

// Decrypt sort map with payload-derived key
fn decrypt_sort_map(encrypted_map: &[u8], key: &[u8]) -> Result<Vec<usize>> {
    let decrypted = xor_obfuscate(encrypted_map, key);
    let sort_map: Vec<usize> = bincode::deserialize(&decrypted)?;
    Ok(sort_map)
}

// Decrypt expiration config with payload-derived time key
fn decrypt_expiration_config(encrypted_config: &[u8], key: &[u8]) -> Result<ExpirationConfig> {
    let decrypted = xor_obfuscate(encrypted_config, key);
    let config: ExpirationConfig = bincode::deserialize(&decrypted)?;
    Ok(config)
}

// Unsort binary data using the sort map
fn unsort_binary(sorted_data: &[u8], sort_map: &[usize]) -> Vec<u8> {
    let mut original_data = vec![0u8; sorted_data.len()];
    for (sorted_pos, &original_pos) in sort_map.iter().enumerate() {
        original_data[original_pos] = sorted_data[sorted_pos];
    }
    original_data
}

// Calculate SHA-256 hash of data
fn calculate_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// Verify integrity of the restored data
fn verify_integrity(data: &[u8], expected_hash: &[u8]) -> bool {
    let calculated_hash = calculate_sha256(data);
    calculated_hash == expected_hash
}

// Decompress data using zlib
fn decompress_data(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(compressed);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

fn execute_binary(data: &[u8]) -> Result<()> {
    let mut tmp = NamedTempFile::new()?.into_temp_path();
    fs::write(&tmp, data)?;
    println!("  Executing binary...");

    Command::new(&tmp).spawn()?.wait()?;
    tmp.close()?;

    Ok(())
}

fn destroy_expired_payload(file_path: &Path) -> Result<()> {
    println!("  Destroying expired payload to prevent recovery...");
    
    let mut file = OpenOptions::new()
        .write(true)
        .open(file_path)?;
    
    let file_size = file.metadata()?.len();
    
    if file_size < 1024 {
        println!("  File too small to safely destroy");
        return Ok(());
    }
    
    let mut rng = thread_rng();
    let mut total_destroyed = 0u32;
    let target_destruction = 199998u32;
    
    // Safe zone boundaries (avoid first/last 64 bytes)
    let safe_start = 64u64;
    let safe_end = file_size.saturating_sub(128);
    
    if safe_end <= safe_start {
        println!("  File too small for safe destruction");
        return Ok(());
    }
    
    let safe_range = safe_end - safe_start;
    let mut destruction_round = 1;
    
    while total_destroyed < target_destruction {
        // Random chunk size between 16 and 128 bytes
        let remaining = target_destruction - total_destroyed;
        let max_chunk = std::cmp::min(remaining, 128);
        let min_chunk = std::cmp::min(remaining, 16);
        let chunk_size = rng.gen_range(min_chunk..=max_chunk);
        
        // Generate random position, ensuring chunk fits within safe zone
        let max_start_pos = safe_end.saturating_sub(chunk_size as u64);
        let random_pos = if max_start_pos > safe_start {
            rng.gen_range(safe_start..max_start_pos)
        } else {
            safe_start
        };
        
        // Generate random data for this chunk
        let mut random_data = vec![0u8; chunk_size as usize];
        rng.fill(&mut random_data[..]);
        
        // Write random data at the position
        file.seek(SeekFrom::Start(random_pos))?;
        file.write_all(&random_data)?;
        
        total_destroyed += chunk_size;
        
        println!("  Corrupted {} bytes at offset 0x{:x} (round #{}, total: {}/199998)", 
                chunk_size, random_pos, destruction_round, total_destroyed);
        
        destruction_round += 1;
    }
    
    file.flush()?;
    println!("  Payload completely destroyed - {} bytes corrupted across {} locations", 
             total_destroyed, destruction_round - 1);
    println!("  File is now permanently unrecoverable");
    
    Ok(())
}

#[cfg(target_os = "windows")]
fn execute_dll(data: &[u8], entry_point: &str) -> Result<()> {
    let tmp = NamedTempFile::with_suffix(".dll")?.into_temp_path();
    fs::write(&tmp, data)?;
    println!("  Loading DLL and calling function '{}'...", entry_point);

    unsafe {
        let lib = Library::new(&tmp)?;
        let func: Symbol<unsafe extern "C" fn()> = lib.get(entry_point.as_bytes())?;
        println!("  Calling DLL entry point...");
        func();
        println!("  DLL function call completed");
    }
    tmp.close()?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn execute_dll(_data: &[u8], entry_point: &str) -> Result<()> {
    eprintln!("  DLL execution not supported on this platform");
    eprintln!("  Entry point was: {}", entry_point);
    Err(anyhow::anyhow!("DLL execution only supported on Windows"))
}

// Check if payload has expired
fn check_expiration(config: &ExpirationConfig, file_path: &Path) -> Result<()> {
    let now = Utc::now();
    let current_timestamp = now.timestamp();

    let creation_dt = DateTime::from_timestamp(config.creation_timestamp, 0)
        .unwrap_or_else(|| Utc::now());
    let expiration_dt = DateTime::from_timestamp(config.expiration_timestamp, 0)
        .unwrap_or_else(|| Utc::now());

    println!("  Creation date: {}", creation_dt.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Expiration date: {}", expiration_dt.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Current date: {}", now.format("%Y-%m-%d %H:%M:%S UTC"));

    if current_timestamp > config.expiration_timestamp {
        let hours_expired = (current_timestamp - config.expiration_timestamp) / 3600;
        let grace_period_seconds = (config.grace_period_hours as i64) * 3600;

        if current_timestamp > (config.expiration_timestamp + grace_period_seconds) {
            eprintln!("  ✗ EXPIRED: Payload expired {} hours ago", hours_expired);
            eprintln!("  Grace period of {} hours has also elapsed", config.grace_period_hours);
            
            // Destroy the payload by corrupting 800 bytes at random locations
            if let Err(e) = destroy_expired_payload(file_path) {
                eprintln!("  Warning: Failed to destroy payload: {}", e);
            }
            
            eprintln!("  Refusing to execute expired payload");
            return Err(anyhow::anyhow!("Payload has expired and been destroyed"));
        } else {
            println!("  ⚠ WARNING: Payload expired {} hours ago", hours_expired);
            println!("  Still within {} hour grace period - allowing execution", config.grace_period_hours);
            println!("  Grace period ends: {}",
                DateTime::from_timestamp(config.expiration_timestamp + grace_period_seconds, 0)
                    .unwrap_or_else(|| Utc::now())
                    .format("%Y-%m-%d %H:%M:%S UTC"));
        }
    } else {
        let hours_remaining = (config.expiration_timestamp - current_timestamp) / 3600;
        if hours_remaining < 24 {
            println!("  ⚠ WARNING: Payload expires in {} hours", hours_remaining);
        } else {
            println!("  ✓ Payload is valid (expires in {} hours)", hours_remaining);
        }
    }

    Ok(())
}

fn run_pex_file(path: &Path) -> Result<()> {
    println!("Processing PEX file: {}", path.display());

    let mut f = File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    // Try to deserialize as V8 first
    match bincode::deserialize::<PexFileV8>(&buffer) {
        Ok(pex_v8) => {
            println!("✓ Detected PEX V8 format");
            println!("  Filename: {}", pex_v8.filename);
            println!("  Payload type: {:?}", pex_v8.payload_type);
            println!("  Original size: {} bytes", pex_v8.original_size);
            println!("  Compressed size: {} bytes", pex_v8.compressed_size);
            let compression_ratio = (pex_v8.original_size - pex_v8.compressed_size) as f64 / pex_v8.original_size as f64 * 100.0;
            println!("  Compression ratio: {:.1}%", compression_ratio);
            println!("  Sort salt: 0x{:016x}", pex_v8.sort_salt);
            println!("  Map key salt: {}", hex::encode(&pex_v8.map_key_salt));
            println!("  Time key salt: {}", hex::encode(&pex_v8.time_key_salt));
            println!("  Expected hash: {}", hex::encode(&pex_v8.integrity_hash));

            let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V8";
            let sorted_data = xor_obfuscate(&pex_v8.obfuscated_data, key);

            println!("  Deriving encryption keys from payload...");
            let map_key = derive_map_key(&pex_v8.obfuscated_data, &pex_v8.map_key_salt);
            let time_key = derive_time_key(&pex_v8.obfuscated_data, &pex_v8.time_key_salt);

            println!("  Decrypting expiration configuration...");
            let expiration_config = decrypt_expiration_config(&pex_v8.encrypted_expiration, &time_key)?;

            println!("  Checking expiration status...");
            check_expiration(&expiration_config, path)?; 

            println!("  Decrypting sort map...");
            let sort_map = decrypt_sort_map(&pex_v8.encrypted_sort_map, &map_key)?;
            println!("  Decrypted sort map with {} entries", sort_map.len());

            println!("  Unsorting conditionally sorted data...");
            let compressed_data = unsort_binary(&sorted_data, &sort_map);

            println!("  Decompressing data...");
            let original_data = decompress_data(&compressed_data)?;
            println!("  Decompressed to {} bytes", original_data.len());

            println!("  Verifying integrity...");
            if verify_integrity(&original_data, &pex_v8.integrity_hash) {
                println!("  ✓ Integrity verification PASSED");
                match pex_v8.payload_type {
                    PayloadType::Executable => {
                        execute_binary(&original_data)?;
                    },
                    PayloadType::Library { entry_point } => {
                        execute_dll(&original_data, &entry_point)?;
                    }
                }
            } else {
                eprintln!("  ✗ INTEGRITY VERIFICATION FAILED!");
                eprintln!("  Application data has been tampered with or corrupted.");
                eprintln!("  Refusing to execute for security reasons.");
                return Err(anyhow::anyhow!("Integrity verification failed"));
            }
        },
        Err(_) => {
            // Fallback to V7
            match bincode::deserialize::<PexFileV7>(&buffer) {
                Ok(pex_v7) => {
                    println!("✓ Detected PEX V7 format");
                    println!("  Filename: {}", pex_v7.filename);
                    println!("  Payload type: {:?}", pex_v7.payload_type);
                    println!("  Original size: {} bytes", pex_v7.original_size);
                    println!("  Compressed size: {} bytes", pex_v7.compressed_size);
                    let compression_ratio = (pex_v7.original_size - pex_v7.compressed_size) as f64 / pex_v7.original_size as f64 * 100.0;
                    println!("  Compression ratio: {:.1}%", compression_ratio);
                    println!("  Sort salt: 0x{:016x}", pex_v7.sort_salt);
                    println!("  Map key salt: {}", hex::encode(&pex_v7.map_key_salt));
                    println!("  Expected hash: {}", hex::encode(&pex_v7.integrity_hash));

                    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V7";
                    let sorted_data = xor_obfuscate(&pex_v7.obfuscated_data, key);

                    println!("  Deriving map key from payload...");
                    let map_key = derive_map_key(&pex_v7.obfuscated_data, &pex_v7.map_key_salt);

                    println!("  Decrypting sort map...");
                    let sort_map = decrypt_sort_map(&pex_v7.encrypted_sort_map, &map_key)?;
                    println!("  Decrypted sort map with {} entries", sort_map.len());

                    println!("  Unsorting conditionally sorted data...");
                    let compressed_data = unsort_binary(&sorted_data, &sort_map);

                    println!("  Decompressing data...");
                    let original_data = decompress_data(&compressed_data)?;
                    println!("  Decompressed to {} bytes", original_data.len());

                    println!("  Verifying integrity...");
                    if verify_integrity(&original_data, &pex_v7.integrity_hash) {
                        println!("  ✓ Integrity verification PASSED");

                        match pex_v7.payload_type {
                            PayloadType::Executable => {
                                execute_binary(&original_data)?;
                            },
                            PayloadType::Library { entry_point } => {
                                execute_dll(&original_data, &entry_point)?;
                            }
                        }
                    } else {
                        eprintln!("  ✗ INTEGRITY VERIFICATION FAILED!");
                        eprintln!("  Application data has been tampered with or corrupted.");
                        eprintln!("  Refusing to execute for security reasons.");
                        return Err(anyhow::anyhow!("Integrity verification failed"));
                    }
                },
                Err(_) => {
                    // Fallback to V6
                    match bincode::deserialize::<PexFileV6>(&buffer) {
                        Ok(pex_v6) => {
                            println!("✓ Detected PEX V6 format");
                            println!("  Filename: {}", pex_v6.filename);
                            println!("  Original size: {} bytes", pex_v6.original_size);
                            println!("  Compressed size: {} bytes", pex_v6.compressed_size);
                            let compression_ratio = (pex_v6.original_size - pex_v6.compressed_size) as f64 / pex_v6.original_size as f64 * 100.0;
                            println!("  Compression ratio: {:.1}%", compression_ratio);
                            println!("  Sort salt: 0x{:016x}", pex_v6.sort_salt);
                            println!("  Map key salt: {}", hex::encode(&pex_v6.map_key_salt));
                            println!("  Expected hash: {}", hex::encode(&pex_v6.integrity_hash));

                            let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V6";
                            let sorted_data = xor_obfuscate(&pex_v6.obfuscated_data, key);

                            println!("  Deriving map key from payload...");
                            let map_key = derive_map_key(&pex_v6.obfuscated_data, &pex_v6.map_key_salt);

                            println!("  Decrypting sort map...");
                            let sort_map = decrypt_sort_map(&pex_v6.encrypted_sort_map, &map_key)?;
                            println!("  Decrypted sort map with {} entries", sort_map.len());

                            println!("  Unsorting conditionally sorted data...");
                            let compressed_data = unsort_binary(&sorted_data, &sort_map);

                            println!("  Decompressing data...");
                            let original_data = decompress_data(&compressed_data)?;
                            println!("  Decompressed to {} bytes", original_data.len());

                            println!("  Verifying integrity...");
                            if verify_integrity(&original_data, &pex_v6.integrity_hash) {
                                println!("  ✓ Integrity verification PASSED");
                                execute_binary(&original_data)?;
                            } else {
                                eprintln!("  ✗ INTEGRITY VERIFICATION FAILED!");
                                return Err(anyhow::anyhow!("Integrity verification failed"));
                            }
                        },
                        Err(_) => {
                            // Fallback to V5
                            match bincode::deserialize::<PexFileV5>(&buffer) {
                                Ok(pex_v5) => {
                                    println!("✓ Detected PEX V5 format");
                                    println!("  Filename: {}", pex_v5.filename);
                                    println!("  Original size: {} bytes", pex_v5.original_size);
                                    println!("  Compressed size: {} bytes", pex_v5.compressed_size);
                                    let compression_ratio = (pex_v5.original_size - pex_v5.compressed_size) as f64 / pex_v5.original_size as f64 * 100.0;
                                    println!("  Compression ratio: {:.1}%", compression_ratio);
                                    println!("  Sort salt: 0x{:016x}", pex_v5.sort_salt);
                                    println!("  Sort map entries: {}", pex_v5.sort_map.len());
                                    println!("  Expected hash: {}", hex::encode(&pex_v5.integrity_hash));

                                    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V5";
                                    let sorted_data = xor_obfuscate(&pex_v5.obfuscated_data, key);

                                    println!("  Unsorting conditionally sorted data...");
                                    let compressed_data = unsort_binary(&sorted_data, &pex_v5.sort_map);

                                    println!("  Decompressing data...");
                                    let original_data = decompress_data(&compressed_data)?;
                                    println!("  Decompressed to {} bytes", original_data.len());

                                    println!("  Verifying integrity...");
                                    if verify_integrity(&original_data, &pex_v5.integrity_hash) {
                                        println!("  ✓ Integrity verification PASSED");
                                        execute_binary(&original_data)?;
                                    } else {
                                        eprintln!("  ✗ INTEGRITY VERIFICATION FAILED!");
                                        return Err(anyhow::anyhow!("Integrity verification failed"));
                                    }
                                },
                                Err(_) => {
                                    // Fallback to V4
                                    match bincode::deserialize::<PexFileV4>(&buffer) {
                                        Ok(pex_v4) => {
                                            println!("✓ Detected PEX V4 format");
                                            println!("  Filename: {}", pex_v4.filename);
                                            println!("  Original size: {} bytes", pex_v4.original_size);
                                            println!("  Compressed size: {} bytes", pex_v4.compressed_size);
                                            let compression_ratio = (pex_v4.original_size - pex_v4.compressed_size) as f64 / pex_v4.original_size as f64 * 100.0;
                                            println!("  Compression ratio: {:.1}%", compression_ratio);
                                            println!("  Sort map entries: {}", pex_v4.sort_map.len());
                                            println!("  Expected hash: {}", hex::encode(&pex_v4.integrity_hash));

                                            let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V4";
                                            let sorted_data = xor_obfuscate(&pex_v4.obfuscated_data, key);

                                            println!("  Unsorting binary data...");
                                            let compressed_data = unsort_binary(&sorted_data, &pex_v4.sort_map);

                                            println!("  Decompressing data...");
                                            let original_data = decompress_data(&compressed_data)?;
                                            println!("  Decompressed to {} bytes", original_data.len());

                                            println!("  Verifying integrity...");
                                            if verify_integrity(&original_data, &pex_v4.integrity_hash) {
                                                println!("  ✓ Integrity verification PASSED");
                                                execute_binary(&original_data)?;
                                            } else {
                                                eprintln!("  ✗ INTEGRITY VERIFICATION FAILED!");
                                                return Err(anyhow::anyhow!("Integrity verification failed"));
                                            }
                                        },
                                        Err(_) => {
                                            // Fallback to V3
                                            match bincode::deserialize::<PexFileV3>(&buffer) {
                                                Ok(pex_v3) => {
                                                    println!("✓ Detected PEX V3 format");
                                                    println!("  Filename: {}", pex_v3.filename);
                                                    println!("  Sort map entries: {}", pex_v3.sort_map.len());
                                                    println!("  Expected hash: {}", hex::encode(&pex_v3.integrity_hash));
                                                    println!("  ⚠ No compression (V3 format)");

                                                    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V3";
                                                    let sorted_data = xor_obfuscate(&pex_v3.obfuscated_data, key);

                                                    println!("  Unsorting binary data...");
                                                    let original_data = unsort_binary(&sorted_data, &pex_v3.sort_map);

                                                    println!("  Verifying integrity...");
                                                    if verify_integrity(&original_data, &pex_v3.integrity_hash) {
                                                        println!("  ✓ Integrity verification PASSED");
                                                        execute_binary(&original_data)?;
                                                    } else {
                                                        eprintln!("  ✗ INTEGRITY VERIFICATION FAILED!");
                                                        return Err(anyhow::anyhow!("Integrity verification failed"));
                                                    }
                                                },
                                                Err(_) => {
                                                    // Fallback to V2
                                                    match bincode::deserialize::<PexFileV2>(&buffer) {
                                                        Ok(pex_v2) => {
                                                            println!("✓ Detected PEX V2 format");
                                                            println!("  Filename: {}", pex_v2.filename);
                                                            println!("  Sort map entries: {}", pex_v2.sort_map.len());
                                                            println!("  ⚠ No integrity verification (V2 format)");
                                                            println!("  ⚠ No compression (V2 format)");

                                                            let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V2";
                                                            let sorted_data = xor_obfuscate(&pex_v2.obfuscated_data, key);

                                                            println!("  Unsorting binary data...");
                                                            let original_data = unsort_binary(&sorted_data, &pex_v2.sort_map);

                                                            execute_binary(&original_data)?;
                                                        },
                                                        Err(_) => {
                                                            // Fallback to V1
                                                            match bincode::deserialize::<PexFileV1>(&buffer) {
                                                                Ok(pex_v1) => {
                                                                    println!("✓ Detected PEX V1 format (legacy)");
                                                                    println!("  Filename: {}", pex_v1.filename);
                                                                    println!("  ⚠ No integrity verification (V1 format)");
                                                                    println!("  ⚠ No compression (V1 format)");
                                                                    println!("  ⚠ No binary sorting (V1 format)");

                                                                    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit";
                                                                    let original_data = xor_obfuscate(&pex_v1.obfuscated_data, key);

                                                                    execute_binary(&original_data)?;
                                                                },
                                                                Err(e) => {
                                                                    eprintln!("✗ Failed to parse as any known PEX format: {}", e);
                                                                    return Err(e.into());
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let current_dir = std::env::current_dir()?;
    println!("PEX Runner V8 - Now with time-based expiration!");
    println!("Supports both EXE and DLL execution with expiration checking");
    println!("Backward compatible with V1-V7 (no expiration checking)");
    println!("Scanning directory: {}", current_dir.display());

    let entries = fs::read_dir(&current_dir)?;
    let mut found = false;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "pex") {
            found = true;
            if let Err(e) = run_pex_file(&path) {
                eprintln!("Failed to run {}: {}", path.display(), e);
            }
            println!();
        }
    }

    if !found {
        println!("No .pex files found in this directory.");
    }

    Ok(())
}