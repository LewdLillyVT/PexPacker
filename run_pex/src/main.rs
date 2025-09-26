use serde::{Serialize, Deserialize};
use std::{fs, fs::File, io::Read, process::Command};
use tempfile::NamedTempFile;
use anyhow::Result;
use bincode;
use std::path::Path;
use sha2::{Sha256, Digest};
use flate2::read::ZlibDecoder;
use std::io::prelude::*;

#[derive(Serialize, Deserialize, Debug)]
enum PexVersion {
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
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
    sort_map: Vec<usize>, // Maps sorted position -> original position
}

#[derive(Serialize, Deserialize)]
struct PexFileV3 {
    version: PexVersion,
    filename: String,
    obfuscated_data: Vec<u8>,
    sort_map: Vec<usize>, // Maps sorted position -> original position
    integrity_hash: Vec<u8>, // SHA-256 hash of original unprotected data
}

#[derive(Serialize, Deserialize)]
struct PexFileV4 {
    version: PexVersion,
    filename: String,
    obfuscated_data: Vec<u8>,
    sort_map: Vec<usize>, // Maps sorted position -> original position
    integrity_hash: Vec<u8>, // SHA-256 hash of original unprotected data
    original_size: u64, // Size before compression
    compressed_size: u64, // Size after compression
}

#[derive(Serialize, Deserialize)]
struct PexFileV5 {
    version: PexVersion,
    filename: String,
    obfuscated_data: Vec<u8>,
    sort_map: Vec<usize>, // Maps sorted position -> original position
    integrity_hash: Vec<u8>, // SHA-256 hash of original unprotected data
    original_size: u64, // Size before compression
    compressed_size: u64, // Size after compression
    sort_salt: u64, // Salt used for randomizing same-value byte order
}

#[derive(Serialize, Deserialize)]
struct PexFileV6 {
    version: PexVersion,
    filename: String,
    obfuscated_data: Vec<u8>,
    encrypted_sort_map: Vec<u8>, // Encrypted with payload-derived key
    integrity_hash: Vec<u8>,
    original_size: u64,
    compressed_size: u64,
    sort_salt: u64,
    map_key_salt: Vec<u8>, // Salt for deriving map encryption key from payload
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
    hasher.update(b"PEX_V6_MAP_KEY_DERIVATION");
    hasher.finalize().to_vec()
}

// Decrypt sort map with payload-derived key
fn decrypt_sort_map(encrypted_map: &[u8], key: &[u8]) -> Result<Vec<usize>> {
    let decrypted = xor_obfuscate(encrypted_map, key);
    let sort_map: Vec<usize> = bincode::deserialize(&decrypted)?;
    Ok(sort_map)
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

fn run_pex_file(path: &Path) -> Result<()> {
    println!("Processing PEX file: {}", path.display());
    
    let mut f = File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    
    // Try to deserialize as V6 first
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
            
            // Deobfuscate with V6 key
            let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V6";
            let sorted_data = xor_obfuscate(&pex_v6.obfuscated_data, key);
            
            // V6: Derive map decryption key from obfuscated payload
            println!("  Deriving map key from payload...");
            let map_key = derive_map_key(&pex_v6.obfuscated_data, &pex_v6.map_key_salt);
            
            // V6: Decrypt sort map using payload-derived key
            println!("  Decrypting sort map...");
            let sort_map = decrypt_sort_map(&pex_v6.encrypted_sort_map, &map_key)?;
            println!("  Decrypted sort map with {} entries", sort_map.len());
            
            // Unsort the binary to restore compressed structure
            println!("  Unsorting conditionally sorted data...");
            let compressed_data = unsort_binary(&sorted_data, &sort_map);
            
            // Decompress the data
            println!("  Decompressing data...");
            let original_data = decompress_data(&compressed_data)?;
            println!("  Decompressed to {} bytes", original_data.len());
            
            // INTEGRITY VERIFICATION
            println!("  Verifying integrity...");
            if verify_integrity(&original_data, &pex_v6.integrity_hash) {
                println!("  ✓ Integrity verification PASSED");
                execute_binary(&original_data)?;
            } else {
                eprintln!("  ✗ INTEGRITY VERIFICATION FAILED!");
                eprintln!("  Application data has been tampered with or corrupted.");
                eprintln!("  Refusing to execute for security reasons.");
                return Err(anyhow::anyhow!("Integrity verification failed"));
            }
        },
        Err(_) => {
            // Try to deserialize as V5 first
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
                    
                    // Deobfuscate with V5 key
                    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V5";
                    let sorted_data = xor_obfuscate(&pex_v5.obfuscated_data, key);
                    
                    // Unsort the binary to restore compressed structure
                    println!("  Unsorting conditionally sorted data...");
                    let compressed_data = unsort_binary(&sorted_data, &pex_v5.sort_map);
                    
                    // Decompress the data
                    println!("  Decompressing data...");
                    let original_data = decompress_data(&compressed_data)?;
                    println!("  Decompressed to {} bytes", original_data.len());
                    
                    // INTEGRITY VERIFICATION
                    println!("  Verifying integrity...");
                    if verify_integrity(&original_data, &pex_v5.integrity_hash) {
                        println!("  ✓ Integrity verification PASSED");
                        execute_binary(&original_data)?;
                    } else {
                        eprintln!("  ✗ INTEGRITY VERIFICATION FAILED!");
                        eprintln!("  Application data has been tampered with or corrupted.");
                        eprintln!("  Refusing to execute for security reasons.");
                        return Err(anyhow::anyhow!("Integrity verification failed"));
                    }
                },
                Err(_) => {
                    // Try V4 format
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
                            
                            // Deobfuscate with V4 key
                            let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V4";
                            let sorted_data = xor_obfuscate(&pex_v4.obfuscated_data, key);
                            
                            // Unsort the binary to restore compressed structure
                            println!("  Unsorting binary data...");
                            let compressed_data = unsort_binary(&sorted_data, &pex_v4.sort_map);
                            
                            // Decompress the data
                            println!("  Decompressing data...");
                            let original_data = decompress_data(&compressed_data)?;
                            println!("  Decompressed to {} bytes", original_data.len());
                            
                            // INTEGRITY VERIFICATION
                            println!("  Verifying integrity...");
                            if verify_integrity(&original_data, &pex_v4.integrity_hash) {
                                println!("  ✓ Integrity verification PASSED");
                                execute_binary(&original_data)?;
                           } else {
                                eprintln!("  ✗ INTEGRITY VERIFICATION FAILED!");
                                eprintln!("  Application data has been tampered with or corrupted.");
                                eprintln!("  Refusing to execute for security reasons.");
                                return Err(anyhow::anyhow!("Integrity verification failed"));
                            }
                        },
                        Err(_) => {
                            // Try V3 format
                            match bincode::deserialize::<PexFileV3>(&buffer) {
                                Ok(pex_v3) => {
                                    println!("✓ Detected PEX V3 format");
                                    println!("  Filename: {}", pex_v3.filename);
                                    println!("  Sort map entries: {}", pex_v3.sort_map.len());
                                    println!("  Expected hash: {}", hex::encode(&pex_v3.integrity_hash));
                                    println!("  ⚠ No compression (V3 format)");
                                    
                                    // Deobfuscate with V3 key
                                    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V3";
                                    let sorted_data = xor_obfuscate(&pex_v3.obfuscated_data, key);
                                    
                                    // Unsort the binary to restore original structure
                                    println!("  Unsorting binary data...");
                                    let original_data = unsort_binary(&sorted_data, &pex_v3.sort_map);
                                    
                                    // INTEGRITY VERIFICATION
                                    println!("  Verifying integrity...");
                                    if verify_integrity(&original_data, &pex_v3.integrity_hash) {
                                        println!("  ✓ Integrity verification PASSED");
                                        execute_binary(&original_data)?;
                                    } else {
                                        eprintln!("  ✗ INTEGRITY VERIFICATION FAILED!");
                                        eprintln!("  Application data has been tampered with or corrupted.");
                                        eprintln!("  Refusing to execute for security reasons.");
                                        return Err(anyhow::anyhow!("Integrity verification failed"));
                                    }
                                },
                                Err(_) => {
                                    // Try V2 format
                                    match bincode::deserialize::<PexFileV2>(&buffer) {
                                        Ok(pex_v2) => {
                                            println!("✓ Detected PEX V2 format");
                                            println!("  Filename: {}", pex_v2.filename);
                                            println!("  Sort map entries: {}", pex_v2.sort_map.len());
                                            println!("  ⚠ No integrity verification (V2 format)");
                                            println!("  ⚠ No compression (V2 format)");
                                            
                                            // Deobfuscate with V2 key
                                            let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V2";
                                            let sorted_data = xor_obfuscate(&pex_v2.obfuscated_data, key);
                                            
                                            // Unsort the binary to restore original structure
                                            println!("  Unsorting binary data...");
                                            let original_data = unsort_binary(&sorted_data, &pex_v2.sort_map);
                                            
                                            execute_binary(&original_data)?;
                                        },
                                        Err(_) => {
                                            // Fall back to V1 format
                                            match bincode::deserialize::<PexFileV1>(&buffer) {
                                                Ok(pex_v1) => {
                                                    println!("✓ Detected PEX V1 format (legacy)");
                                                    println!("  Filename: {}", pex_v1.filename);
                                                    println!("  ⚠ No integrity verification (V1 format)");
                                                    println!("  ⚠ No compression (V1 format)");
                                                    println!("  ⚠ No binary sorting (V1 format)");
                                                    
                                                    // Deobfuscate with V1 key
                                                    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit";
                                                    let original_data = xor_obfuscate(&pex_v1.obfuscated_data, key);
                                                    
                                                    execute_binary(&original_data)?;
                                                },
                                                Err(e) => {
                                                    eprintln!("✗ Failed to parse as V1, V2, V3, V4, or V5 format: {}", e);
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
    
    Ok(())
}

fn execute_binary(data: &[u8]) -> Result<()> {
    let mut tmp = NamedTempFile::new()?.into_temp_path();
    fs::write(&tmp, data)?;
    println!("  Executing verified binary...");

    Command::new(&tmp).spawn()?.wait()?;
    tmp.close()?;
    
    Ok(())
}

fn main() -> Result<()> {
    let current_dir = std::env::current_dir()?;
    println!("PEX Runner V6 - Now with Payload-Derived Map Obfuscation!");
    println!("Backward compatible with V1-V5");
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
            println!(); // Add spacing between files
        }
    }

    if !found {
        println!("No .pex files found in this directory.");
    }
    
    Ok(())
}
