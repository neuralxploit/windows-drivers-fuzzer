// CLFS (Common Log File System) File-Based Fuzzer
// Targets: CVE-2025-29824 style vulnerabilities (UAF in CLFS driver)
// Attack surface: Malformed .blf (Base Log File) structures

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use rand::Rng;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

// Windows API bindings for CLFS
#[link(name = "clfsw32")]
extern "system" {
    fn CreateLogFile(
        pszLogFileName: *const u16,
        fDesiredAccess: u32,
        dwShareMode: u32,
        pSecurityAttributes: *mut std::ffi::c_void,
        fCreateDisposition: u32,
        fFlagsAndAttributes: u32,
    ) -> isize;
    
    fn CloseHandle(hObject: isize) -> i32;
    
    fn DeleteLogFile(
        pszLogFileName: *const u16,
        pvReserved: *mut std::ffi::c_void,
    ) -> i32;
}

// CLFS constants
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const INVALID_HANDLE_VALUE: isize = -1;

// BLF layout constants (based on public CLFS structures)
const CLFS_BASE_SIGNATURE: u32 = 0x19930520;
const CLFS_BLOCK_SIGNATURE: u32 = 0x19930522;
const CLFS_SECTOR_SIZE: usize = 0x200;
const CLFS_BLOCK_SIZE: u32 = 0x800;
const BLF_MIN_SIZE: usize = 0x10000; // 64KB

// Control record offsets (within sector 0)
const CR_SIGNATURE: usize = 0x00;
const CR_VERSION: usize = 0x04;
const CR_ESTATE: usize = 0x08;
const CR_CONTAINER_SIZE: usize = 0x10;
const CR_BLOCK_SIZE: usize = 0x18;
const CR_SECTOR_SIZE: usize = 0x1C;
const CR_CONTAINER_COUNT: usize = 0x20;
const CR_CLIENT_COUNT: usize = 0x24;
const CR_SYMBOL_ZONE: usize = 0x28;
const CR_BASE_RECORD_OFF: usize = 0x30;
const CR_CRC: usize = 0x1FC;

// Base record header (offset 0x800)
const BR_SIGNATURE: usize = 0x800;
const BR_BLOCK_SIZE: usize = 0x808;
const BR_RECORD_COUNT: usize = 0x810;

pub struct ClfsFuzzer {
    work_dir: PathBuf,
    crash_dir: PathBuf,
    iteration: u64,
    crashes_found: u64,
    mutations: Vec<String>,
}

impl ClfsFuzzer {
    pub fn new(output_dir: &str) -> Self {
        let work_dir = PathBuf::from(output_dir).join("clfs_work");
        let crash_dir = PathBuf::from(output_dir).join("clfs_crashes");
        
        fs::create_dir_all(&work_dir).ok();
        fs::create_dir_all(&crash_dir).ok();
        
        ClfsFuzzer {
            work_dir,
            crash_dir,
            iteration: 0,
            crashes_found: 0,
            mutations: vec![
                "corrupt_signature".to_string(),
                "control_record_mismatch".to_string(),
                "huge_container_count".to_string(),
                "client_count_overflow".to_string(),
                "invalid_block_size".to_string(),
                "zero_sector_size".to_string(),
                "base_record_oob".to_string(),
                "negative_symbol_zone".to_string(),
                "container_size_overflow".to_string(),
                "block_signature_invalid".to_string(),
                "symbol_zone_oob".to_string(),
                "symbol_zone_overflow".to_string(),
                "corrupt_checksum".to_string(),
            ],
        }
    }
    
    fn write_u32(buf: &mut [u8], off: usize, val: u32) {
        if off + 4 <= buf.len() {
            buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
    }

    fn write_u64(buf: &mut [u8], off: usize, val: u64) {
        if off + 8 <= buf.len() {
            buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
        }
    }

    fn write_i64(buf: &mut [u8], off: usize, val: i64) {
        if off + 8 <= buf.len() {
            buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
        }
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFFFFFF;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB88320u32 & mask);
            }
        }
        !crc
    }

    fn update_control_record_crc(&self, buf: &mut [u8], sector_off: usize) {
        if sector_off + CLFS_SECTOR_SIZE <= buf.len() {
            let crc = Self::crc32(&buf[sector_off..sector_off + CR_CRC]);
            Self::write_u32(buf, sector_off + CR_CRC, crc);
        }
    }

    // Build a realistic CLFS BLF structure (control record + shadow + base record)
    fn build_valid_blf(&self) -> Vec<u8> {
        let mut blf = vec![0u8; BLF_MIN_SIZE];

        // Control record (sector 0)
        Self::write_u32(&mut blf, CR_SIGNATURE, CLFS_BASE_SIGNATURE);
        Self::write_u32(&mut blf, CR_VERSION, 1);           // Version
        Self::write_u32(&mut blf, CR_ESTATE, 0);            // Clean state
        Self::write_u64(&mut blf, CR_CONTAINER_SIZE, BLF_MIN_SIZE as u64);
        Self::write_u32(&mut blf, CR_BLOCK_SIZE, CLFS_BLOCK_SIZE);
        Self::write_u32(&mut blf, CR_SECTOR_SIZE, CLFS_SECTOR_SIZE as u32);
        Self::write_u32(&mut blf, CR_CONTAINER_COUNT, 1);
        Self::write_u32(&mut blf, CR_CLIENT_COUNT, 1);
        Self::write_u64(&mut blf, CR_SYMBOL_ZONE, 0);
        Self::write_u64(&mut blf, CR_BASE_RECORD_OFF, 0x800);

        // Shadow control record (sector 1)
        let (first, rest) = blf.split_at_mut(CLFS_SECTOR_SIZE);
        let (shadow, _) = rest.split_at_mut(CLFS_SECTOR_SIZE);
        shadow.copy_from_slice(first);

        // Base record header at 0x800
        Self::write_u32(&mut blf, BR_SIGNATURE, CLFS_BLOCK_SIGNATURE);
        Self::write_u64(&mut blf, BR_BLOCK_SIZE, CLFS_BLOCK_SIZE as u64);
        Self::write_u32(&mut blf, BR_RECORD_COUNT, 0);

        // Compute CRCs for control record and shadow
        self.update_control_record_crc(&mut blf, 0);
        self.update_control_record_crc(&mut blf, CLFS_SECTOR_SIZE);

        blf
    }
    
    // Apply specific mutations to trigger different bug classes
    fn apply_mutation(&self, data: &mut Vec<u8>, mutation_type: &str) {
        let mut rng = rand::thread_rng();
        
        match mutation_type {
            "corrupt_signature" => {
                Self::write_u32(data, CR_SIGNATURE, rng.gen());
            }
            "control_record_mismatch" => {
                // Mismatch primary and shadow control records
                Self::write_u32(data, CR_CONTAINER_COUNT, 0xFF);
                Self::write_u32(data, CLFS_SECTOR_SIZE + CR_CONTAINER_COUNT, 1);
            }
            "huge_container_count" => {
                Self::write_u32(data, CR_CONTAINER_COUNT, 0x7FFFFFFF);
                Self::write_u32(data, CLFS_SECTOR_SIZE + CR_CONTAINER_COUNT, 0x7FFFFFFF);
            }
            "client_count_overflow" => {
                Self::write_u32(data, CR_CLIENT_COUNT, 0xFFFFFFFF);
                Self::write_u32(data, CLFS_SECTOR_SIZE + CR_CLIENT_COUNT, 0xFFFFFFFF);
            }
            "invalid_block_size" => {
                Self::write_u32(data, CR_BLOCK_SIZE, 0x17);
                Self::write_u32(data, CLFS_SECTOR_SIZE + CR_BLOCK_SIZE, 0x17);
            }
            "zero_sector_size" => {
                Self::write_u32(data, CR_SECTOR_SIZE, 0);
                Self::write_u32(data, CLFS_SECTOR_SIZE + CR_SECTOR_SIZE, 0);
            }
            "base_record_oob" => {
                Self::write_u64(data, CR_BASE_RECORD_OFF, 0xFFFFFFFFFFFFFFFF);
                Self::write_u64(data, CLFS_SECTOR_SIZE + CR_BASE_RECORD_OFF, 0xFFFFFFFFFFFFFFFF);
            }
            "negative_symbol_zone" => {
                Self::write_i64(data, CR_SYMBOL_ZONE, -1);
                Self::write_i64(data, CLFS_SECTOR_SIZE + CR_SYMBOL_ZONE, -1);
            }
            "container_size_overflow" => {
                Self::write_u64(data, CR_CONTAINER_SIZE, 0xFFFFFFFFFFFFFFF0);
                Self::write_u64(data, CLFS_SECTOR_SIZE + CR_CONTAINER_SIZE, 0xFFFFFFFFFFFFFFF0);
            }
            "block_signature_invalid" => {
                Self::write_u32(data, BR_SIGNATURE, 0x41414141);
            }
            "symbol_zone_oob" => {
                // Force symbol zone to point outside file
                Self::write_u64(data, CR_SYMBOL_ZONE, 0x7FFFFFFFFFFFFFFF);
                Self::write_u64(data, CLFS_SECTOR_SIZE + CR_SYMBOL_ZONE, 0x7FFFFFFFFFFFFFFF);
            }
            "symbol_zone_overflow" => {
                // Overflow symbol zone size via huge container size + symbol zone
                Self::write_u64(data, CR_SYMBOL_ZONE, 0xFFFFFFFFFFFFFF00);
                Self::write_u64(data, CLFS_SECTOR_SIZE + CR_SYMBOL_ZONE, 0xFFFFFFFFFFFFFF00);
                Self::write_u64(data, CR_CONTAINER_SIZE, 0x1000);
            }
            "corrupt_checksum" => {
                Self::write_u32(data, CR_CRC, 0xDEADBEEF);
                Self::write_u32(data, CLFS_SECTOR_SIZE + CR_CRC, 0xBADC0FFE);
            }
            _ => {
                // Random byte flip
                let idx = rng.gen_range(0..data.len());
                data[idx] = rng.gen();
            }
        }
    }
    
    // Generate a complete malformed BLF file
    fn generate_malformed_blf(&self, mutation: &str) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut data = self.build_valid_blf();

        // Apply the specific mutation
        self.apply_mutation(&mut data, mutation);

        // Recalculate CRCs unless we're explicitly corrupting them
        if mutation != "corrupt_checksum" {
            self.update_control_record_crc(&mut data, 0);
            self.update_control_record_crc(&mut data, CLFS_SECTOR_SIZE);
        }

        // Light random corruption after valid structure to reach deeper paths
        if rng.gen_bool(0.2) {
            for _ in 0..rng.gen_range(1..5) {
                let idx = rng.gen_range(0..data.len());
                data[idx] = rng.gen();
            }
        }

        data
    }
    
    // Try to open a BLF file with CLFS API
    fn trigger_clfs_parse(&self, blf_path: &PathBuf) -> Result<(), String> {
        // Convert path to CLFS log path format: "LOG:C:\path\file.blf::Stream"
        let log_path = format!("LOG:{}::DefaultStream", blf_path.to_string_lossy());
        let wide_path: Vec<u16> = OsStr::new(&log_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        
        unsafe {
            // Try to open as existing log
            let handle = CreateLogFile(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
            );
            
            if handle != INVALID_HANDLE_VALUE {
                CloseHandle(handle);
                // Try DeleteLogFile to trigger cleanup/flush paths
                let _ = DeleteLogFile(wide_path.as_ptr(), std::ptr::null_mut());
                return Ok(());
            }
            
            // Try OPEN_ALWAYS
            let handle = CreateLogFile(
                wide_path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_ALWAYS,
                0,
            );
            
            if handle != INVALID_HANDLE_VALUE {
                CloseHandle(handle);
                let _ = DeleteLogFile(wide_path.as_ptr(), std::ptr::null_mut());
                return Ok(());
            }
        }
        
        Err("Failed to trigger CLFS parsing".to_string())
    }
    
    // Alternative: trigger via file system operations
    fn trigger_via_filesystem(&self, blf_path: &PathBuf) -> Result<(), String> {
        use std::process::Command;
        
        // Use fsutil to force file system to examine the file
        let _ = Command::new("fsutil")
            .args(["file", "queryExtents", &blf_path.to_string_lossy()])
            .output();
        
        // Try reading the file to trigger any deferred parsing
        if let Ok(data) = fs::read(blf_path) {
            // Just accessing it can trigger CLFS operations
            let _ = data.len();
        }
        
        Ok(())
    }
    
    // Main fuzzing loop
    pub fn run(&mut self, max_iterations: u64) {
        use std::time::Instant;
        
        println!("[*] 📄 CLFS FUZZER | clfs.sys | CVE-2025-29824 style | {:?}", self.crash_dir);
        
        let mutation_count = self.mutations.len();
        let start_time = Instant::now();
        
        for i in 0..max_iterations {
            self.iteration = i;
            
            // Pick a mutation strategy
            let mutation = &self.mutations[i as usize % mutation_count].clone();
            
            // Generate malformed BLF
            let blf_data = self.generate_malformed_blf(mutation);
            
            // Write to temp file
            let blf_path = self.work_dir.join(format!("fuzz_{:08}.blf", i));
            if let Ok(mut file) = File::create(&blf_path) {
                let _ = file.write_all(&blf_data);
            }
            
            // Try to trigger CLFS parsing
            let result = self.trigger_clfs_parse(&blf_path);
            let _ = self.trigger_via_filesystem(&blf_path);
            
            // Progress output - single line with timestamp
            let elapsed = start_time.elapsed().as_secs();
            let rate = if elapsed > 0 { i / elapsed } else { 0 };
            print!("\r[{:02}:{:02}:{:02}] 📄 CLFS | {:>8} iter | {} | {}/s | {:20}          ",
                   elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60,
                   i, if result.is_ok() { "✓" } else { "x" }, rate,
                   &mutation[..mutation.len().min(20)]);
            std::io::stdout().flush().ok();
            
            // Cleanup old files (keep last 100)
            if i > 100 {
                let old_path = self.work_dir.join(format!("fuzz_{:08}.blf", i - 100));
                let _ = fs::remove_file(old_path);
            }
        }
        
        let elapsed = start_time.elapsed().as_secs();
        let rate = if elapsed > 0 { max_iterations / elapsed } else { 0 };
        println!("\n\n[+] DONE | {} iter | {}/s", max_iterations, rate);
    }
    
    // Save a crashing input
    pub fn save_crash(&self, data: &[u8], mutation: &str) {
        let crash_path = self.crash_dir.join(format!(
            "crash_{}_{}.blf", 
            self.iteration, 
            mutation.replace(" ", "_")
        ));
        
        if let Ok(mut file) = File::create(&crash_path) {
            let _ = file.write_all(data);
            println!("\n[!] CRASH SAVED: {:?}", crash_path);
        }
    }
}

// Additional UAF-focused mutations for CLFS
pub struct ClfsUafHunter {
    base_fuzzer: ClfsFuzzer,
}

impl ClfsUafHunter {
    pub fn new(output_dir: &str) -> Self {
        ClfsUafHunter {
            base_fuzzer: ClfsFuzzer::new(output_dir),
        }
    }
    
    // Generate specifically UAF-triggering patterns
    pub fn generate_uaf_trigger(&self) -> Vec<u8> {
        let mut data = self.base_fuzzer.build_valid_blf();
        let mut rng = rand::thread_rng();

        // Increase container count to force allocations
        ClfsFuzzer::write_u32(&mut data, CR_CONTAINER_COUNT, 128);
        ClfsFuzzer::write_u32(&mut data, CLFS_SECTOR_SIZE + CR_CONTAINER_COUNT, 128);

        // Fake container array region (post-base record)
        let container_array_off = 0x1000usize;
        if data.len() < container_array_off {
            data.resize(container_array_off, 0);
        }

        for i in 0..128u64 {
            let base = container_array_off + (i as usize * 0x30);
            if data.len() < base + 0x30 {
                data.resize(base + 0x30, 0);
            }

            // container_id
            ClfsFuzzer::write_u64(&mut data, base + 0x00, i + 1);
            // physical_lsn (invalid / freed patterns)
            ClfsFuzzer::write_u64(&mut data, base + 0x08, 0xFEEE_FEEE_FEEE_0000u64 | i);
            // file_size
            ClfsFuzzer::write_u64(&mut data, base + 0x10, 0xFFFFFFFFFFFFF000u64);
            // file_name_offset (point into freed-ish region)
            ClfsFuzzer::write_u32(&mut data, base + 0x18, 0xDEAD0000u32 | (i as u32));
        }

        // Add random heap-like noise to simulate UAF conditions
        let noise_start = data.len();
        data.resize(noise_start + 0x20000, 0);
        for idx in noise_start..data.len() {
            data[idx] = if rng.gen_bool(0.4) { 0xFE } else { rng.gen() };
        }

        // Recalculate CRCs
        self.base_fuzzer.update_control_record_crc(&mut data, 0);
        self.base_fuzzer.update_control_record_crc(&mut data, CLFS_SECTOR_SIZE);

        data
    }
    
    pub fn run_uaf_hunt(&mut self, iterations: u64) {
        use std::time::Instant;
        
        println!("[*] 🎯 CLFS UAF HUNT | targeting container/block UAF");
        let start_time = Instant::now();
        
        for i in 0..iterations {
            let uaf_data = self.generate_uaf_trigger();
            
            let blf_path = self.base_fuzzer.work_dir.join(format!("uaf_{:08}.blf", i));
            if let Ok(mut file) = File::create(&blf_path) {
                let _ = file.write_all(&uaf_data);
            }
            
            let _ = self.base_fuzzer.trigger_clfs_parse(&blf_path);
            let _ = self.base_fuzzer.trigger_via_filesystem(&blf_path);
            
            // Progress output - single line
            let elapsed = start_time.elapsed().as_secs();
            let rate = if elapsed > 0 { i / elapsed } else { 0 };
            print!("\r[{:02}:{:02}:{:02}] 🎯 UAF | {:>8} iter | {}b | {}/s          ",
                   elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60,
                   i, uaf_data.len(), rate);
            std::io::stdout().flush().ok();
            
            // Cleanup
            if i > 50 {
                let old = self.base_fuzzer.work_dir.join(format!("uaf_{:08}.blf", i - 50));
                let _ = fs::remove_file(old);
            }
        }
        
        println!("\n[+] UAF hunt complete");
    }
}
