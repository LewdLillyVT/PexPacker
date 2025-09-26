
use serde::{Serialize, Deserialize};
use std::{fs::File, io::{Read, Write, self}};
use anyhow::Result;
use bincode;
use std::path::Path;
use sha2::{Sha256, Digest};
use flate2::{Compression, write::ZlibEncoder, read::ZlibDecoder};
use std::io::prelude::*;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use rand::seq::SliceRandom;

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

// Generate a salt from the file data for deterministic but unique randomization
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

// Generate random salt for map key derivation
fn generate_map_key_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut salt = vec![0u8; 32];
    rng.fill_bytes(&mut salt);
    salt
}

// Derive encryption key for sort map from obfuscated payload
fn derive_map_key(obfuscated_data: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(obfuscated_data);
    hasher.update(salt);
    hasher.update(b"PEX_V6_MAP_KEY_DERIVATION");
    hasher.finalize().to_vec()
}

// Encrypt sort map with payload-derived key
fn encrypt_sort_map(sort_map: &[usize], key: &[u8]) -> Result<Vec<u8>> {
    let serialized_map = bincode::serialize(sort_map)?;
    let encrypted = xor_obfuscate(&serialized_map, key);
    Ok(encrypted)
}

// Decrypt sort map with payload-derived key
fn decrypt_sort_map(encrypted_map: &[u8], key: &[u8]) -> Result<Vec<usize>> {
    let decrypted = xor_obfuscate(encrypted_map, key);
    let sort_map: Vec<usize> = bincode::deserialize(&decrypted)?;
    Ok(sort_map)
}

// V6: Conditional Binary Sorting with randomized order for same-value bytes
fn conditional_sort_binary_with_map(data: &[u8], salt: u64) -> (Vec<u8>, Vec<usize>) {
    let mut indexed_data: Vec<(u8, usize)> = data.iter()
        .enumerate()
        .map(|(i, &byte)| (byte, i))
        .collect();
    
    // First, group by byte value
    indexed_data.sort_by_key(|(byte, _)| *byte);
    
    // Now, for each group of same-value bytes, randomize their order using the salt
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
                println!("    Randomized {} bytes with value 0x{:02x}", group.len(), current_byte.unwrap());
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

// Regular V2-V4 sorting (stable)
fn sort_binary_with_map(data: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let mut indexed_data: Vec<(u8, usize)> = data.iter()
        .enumerate()
        .map(|(i, &byte)| (byte, i))
        .collect();
    
    // Sort by byte value (stable sort to maintain relative order for equal bytes)
    indexed_data.sort_by_key(|(byte, _)| *byte);
    
    let sorted_data: Vec<u8> = indexed_data.iter().map(|(byte, _)| *byte).collect();
    let sort_map: Vec<usize> = indexed_data.iter().map(|(_, orig_index)| *orig_index).collect();
    
    (sorted_data, sort_map)
}

// Calculate SHA-256 hash of data
fn calculate_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// Compress data using zlib
fn compress_data(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data)?;
    let compressed = encoder.finish()?;
    Ok(compressed)
}

fn pack_v6(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}.pex", file_name_only);

    // Read original file
    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    
    let original_size = buffer.len() as u64;
    println!("Original file size: {} bytes", original_size);
    
    // Generate salt from file content for deterministic but unique randomization
    let sort_salt = generate_file_salt(&buffer);
    println!("Generated sort salt: 0x{:016x}", sort_salt);
    
    // Calculate integrity hash of original data BEFORE any processing
    let integrity_hash = calculate_sha256(&buffer);
    println!("Calculated integrity hash: {}", hex::encode(&integrity_hash));
    
    // Compress the data FIRST
    let compressed_data = compress_data(&buffer)?;
    let compressed_size = compressed_data.len() as u64;
    let compression_ratio = (original_size - compressed_size) as f64 / original_size as f64 * 100.0;
    println!("Compressed size: {} bytes ({:.1}% reduction)", compressed_size, compression_ratio);
    
    // V6: Conditional sort with randomized same-value byte order
    println!("  Applying conditional binary sorting...");
    let (sorted_data, sort_map) = conditional_sort_binary_with_map(&compressed_data, sort_salt);
    println!("Generated sort map with {} entries", sort_map.len());
    
    // Obfuscate the sorted compressed data
    let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit_V6";
    let obfuscated_data = xor_obfuscate(&sorted_data, key);
    
    // V6: Generate salt for map key derivation
    let map_key_salt = generate_map_key_salt();
    println!("Generated map key salt: {}", hex::encode(&map_key_salt));
    
    // V6: Derive encryption key from obfuscated payload
    let map_key = derive_map_key(&obfuscated_data, &map_key_salt);
    println!("Derived map encryption key from payload");
    
    // V6: Encrypt sort map with payload-derived key
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

fn pack_v5(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}_v5.pex", file_name_only);

    // Read original file
    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    
    let original_size = buffer.len() as u64;
    println!("Original file size: {} bytes", original_size);
    
    // Generate salt from file content for deterministic but unique randomization
    let sort_salt = generate_file_salt(&buffer);
    println!("Generated sort salt: 0x{:016x}", sort_salt);
    
    // Calculate integrity hash of original data BEFORE any processing
    let integrity_hash = calculate_sha256(&buffer);
    println!("Calculated integrity hash: {}", hex::encode(&integrity_hash));
    
    // Compress the data FIRST
    let compressed_data = compress_data(&buffer)?;
    let compressed_size = compressed_data.len() as u64;
    let compression_ratio = (original_size - compressed_size) as f64 / original_size as f64 * 100.0;
    println!("Compressed size: {} bytes ({:.1}% reduction)", compressed_size, compression_ratio);
    
    // V5: Conditional sort with randomized same-value byte order
    println!("  Applying conditional binary sorting...");
    let (sorted_data, sort_map) = conditional_sort_binary_with_map(&compressed_data, sort_salt);
    println!("Generated sort map with {} entries", sort_map.len());
    
    // Show some statistics about the sorting
    let unique_bytes: std::collections::HashSet<u8> = sorted_data.iter().cloned().collect();
    println!("Unique byte values in compressed data: {}", unique_bytes.len());

    // Obfuscate the sorted compressed data
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

fn pack_v4(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}_v4.pex", file_name_only);

    // Read original file
    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    
    let original_size = buffer.len() as u64;
    println!("Original file size: {} bytes", original_size);
    
    // Calculate integrity hash of original data BEFORE any processing
    let integrity_hash = calculate_sha256(&buffer);
    println!("Calculated integrity hash: {}", hex::encode(&integrity_hash));
    
    // Compress the data FIRST
    let compressed_data = compress_data(&buffer)?;
    let compressed_size = compressed_data.len() as u64;
    let compression_ratio = (original_size - compressed_size) as f64 / original_size as f64 * 100.0;
    println!("Compressed size: {} bytes ({:.1}% reduction)", compressed_size, compression_ratio);
    
    // Sort the compressed data and get the sort map
    let (sorted_data, sort_map) = sort_binary_with_map(&compressed_data);
    println!("Generated sort map with {} entries", sort_map.len());
    
    // Show some statistics about the sorting
    let unique_bytes: std::collections::HashSet<u8> = sorted_data.iter().cloned().collect();
    println!("Unique byte values in compressed data: {}", unique_bytes.len());

    // Obfuscate the sorted compressed data
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

fn pack_v3(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}_v3.pex", file_name_only);

    // Read original file
    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    
    println!("Original file size: {} bytes", buffer.len());
    
    // Calculate integrity hash of original data BEFORE any processing
    let integrity_hash = calculate_sha256(&buffer);
    println!("Calculated integrity hash: {}", hex::encode(&integrity_hash));
    
    // Sort the binary and get the sort map
    let (sorted_data, sort_map) = sort_binary_with_map(&buffer);
    println!("Generated sort map with {} entries", sort_map.len());
    
    // Show some statistics about the sorting
    let unique_bytes: std::collections::HashSet<u8> = sorted_data.iter().cloned().collect();
    println!("Unique byte values in file: {}", unique_bytes.len());

    // Obfuscate the sorted data
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

fn pack_v2(input_path: &str) -> Result<()> {
    let file_name_only = Path::new(input_path)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let output_path = format!("{}_v2.pex", file_name_only);

    // Read original file
    let mut f = File::open(input_path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    
    println!("Original file size: {} bytes", buffer.len());
    
    // Sort the binary and get the sort map
    let (sorted_data, sort_map) = sort_binary_with_map(&buffer);
    println!("Generated sort map with {} entries", sort_map.len());
    
    // Show some statistics about the sorting
    let unique_bytes: std::collections::HashSet<u8> = sorted_data.iter().cloned().collect();
    println!("Unique byte values in file: {}", unique_bytes.len());

    // Obfuscate the sorted data
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

fn main() -> Result<()> {
    println!("PEX Packer V6 - Now with Payload-Derived Map Obfuscation!");
    println!("Drag an EXE file into this window and press Enter:");

    let mut input_path = String::new();
    io::stdin().read_line(&mut input_path)?;
    let input_path = input_path.trim().trim_matches('"');

    if input_path.is_empty() {
        eprintln!("No file path provided. Exiting.");
        pause();
        return Ok(());
    }

    println!("Choose packing method:");
    println!("1. V6 (with payload-derived map obfuscation)");
    println!("2. V5 (with conditional binary sorting)");
    println!("3. V4 (with compression + integrity verification)");
    println!("4. V3 (with integrity verification)");
    println!("5. V2 (with binary sorting)");
    println!("6. V1 (legacy compatibility)");
    println!("7. All versions");
    
    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    
    match choice.trim() {
        "1" => pack_v6(input_path)?,
        "2" => pack_v5(input_path)?,
        "3" => pack_v4(input_path)?,
        "4" => pack_v3(input_path)?,
        "5" => pack_v2(input_path)?,
        "6" => pack_v1_legacy(input_path)?,
        "7" => {
            pack_v6(input_path)?;
            pack_v5(input_path)?;
            pack_v4(input_path)?;
            pack_v3(input_path)?;
            pack_v2(input_path)?;
            pack_v1_legacy(input_path)?;
        },
        _ => {
            println!("Invalid choice, defaulting to V6");
            pack_v6(input_path)?;
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
