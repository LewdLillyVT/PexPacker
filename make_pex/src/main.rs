use serde::{Serialize, Deserialize};
use std::{fs, fs::File, io::Read, process::Command};
use tempfile::NamedTempFile;
use anyhow::Result;
use bincode;
use std::path::Path;
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize, Debug)]
enum PexVersion {
    V1,
    V2,
    V3,
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

// XOR obfuscation with embedded key
fn xor_obfuscate(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
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

fn run_pex_file(path: &Path) -> Result<()> {
    println!("Processing PEX file: {}", path.display());
    
    let mut f = File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;
    
    // Try to deserialize as V3 first
    match bincode::deserialize::<PexFileV3>(&buffer) {
        Ok(pex_v3) => {
            println!("✓ Detected PEX V3 format");
            println!("  Filename: {}", pex_v3.filename);
            println!("  Sort map entries: {}", pex_v3.sort_map.len());
            println!("  Expected hash: {}", hex::encode(&pex_v3.integrity_hash));
            
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
                            
                            // Deobfuscate with V1 key
                            let key = b"pexstandsforpackagedexecutableandisanewfiletypethatsecurelypackagesexecutablefilesitallowsforanxorkeyofanlengthtosecurethebinarydataitsbackwardscompatibilityallowsforseamlessversionchangesandtoitsopensourcenatureeverybodycanmakeuseofit";
                            let original_data = xor_obfuscate(&pex_v1.obfuscated_data, key);
                            
                            execute_binary(&original_data)?;
                        },
                        Err(e) => {
                            eprintln!("✗ Failed to parse as V1, V2, or V3 format: {}", e);
                            return Err(e.into());
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
    println!("PEX Runner V3 - Now with integrity verification!");
    println!("Backward compatible with V1 and V2");
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