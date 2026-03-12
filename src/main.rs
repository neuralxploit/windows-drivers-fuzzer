//! Ladybug 🐞 - Windows Kernel Driver Fuzzer
//! 
//! A Rust-based fuzzer that uses response-based pseudo-coverage to find bugs 
//! in Windows drivers. Since kernel coverage requires Intel PT or instrumentation,
//! this uses response characteristics as a proxy for code path discovery.

// Suppress warnings for planned/future features
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

mod driver;
mod mutator;
mod coverage;
mod corpus;
mod stateful;
mod race;
mod learner;
mod poc_generator;
mod exploit;
mod rl_fuzzer;
mod clfs_fuzzer;
mod font_fuzzer;
mod gdi_race_fuzzer;
mod win32k_fuzzer;
mod tcp_client;
mod driver_hunter;
mod process_injector;
mod pte_exploit;
mod exploit_patterns;

use clap::Parser;
use colored::*;
use std::path::PathBuf;
use std::time::Instant;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::io::Write;

use driver::DriverIO;
use mutator::Mutator;
use coverage::ResponseCoverage;
use corpus::{Corpus, CorpusEntry};
use learner::{SmartFuzzer, FuzzPhase};
use poc_generator::PocGenerator;
use stateful::{StatefulFuzzer, SequencePattern};
use exploit::ExploitInfo;
use rl_fuzzer::RLFuzzer;
use tcp_client::TcpDriverIO;
use rand::Rng;

/// Coverage-guided Windows Driver Fuzzer
#[derive(Parser, Debug)]
#[command(name = "windriver_fuzzer")]
#[command(author = "Security Researcher")]
#[command(version = "2.0")]
#[command(about = "Coverage-guided fuzzer for Windows kernel drivers", long_about = None)]
struct Args {
    /// Target device path (e.g., \\.\DriverName)
    #[arg(short, long)]
    device: Option<String>,

    /// IOCTL code to fuzz (hex, e.g., 0x220000)
    #[arg(short, long, value_parser = parse_hex)]
    ioctl: Option<u32>,

    /// Brute-force IOCTL range start
    #[arg(long, value_parser = parse_hex)]
    ioctl_start: Option<u32>,

    /// Brute-force IOCTL range end  
    #[arg(long, value_parser = parse_hex)]
    ioctl_end: Option<u32>,

    /// Number of iterations (0 = unlimited)
    #[arg(short, long, default_value = "0")]
    iterations: u64,

    /// Corpus directory for seed inputs
    #[arg(long)]
    corpus: Option<PathBuf>,

    /// Output directory for crashes
    #[arg(short, long, default_value = ".\\crashes")]
    output: PathBuf,

    /// Discover drivers and IOCTLs
    #[arg(long)]
    discover: bool,

    /// Probe for valid IOCTLs on the device
    #[arg(long)]
    probe: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Maximum input size
    #[arg(long, default_value = "4096")]
    max_size: usize,
    
    /// Stateful/UAF fuzzing mode
    #[arg(long)]
    stateful: bool,
    
    /// ULTIMATE mode - ALL techniques combined: Format-RL + Genetic + UAF + Coverage
    #[arg(long)]
    ultimate: bool,

    /// CLFS mode - file-based fuzzer targeting clfs.sys (CVE-2025-29824 style UAF)
    #[arg(long)]
    clfs: bool,

    /// WIN32K mode - NtUser*/NtGdi* syscall fuzzing
    #[arg(long)]
    win32k: bool,

    /// DEEPSCAN mode - scan ALL possible IOCTLs from 0x00000000 to find every valid one (~5-10 min)
    #[arg(long)]
    deepscan: bool,

    /// SAFE mode - use minimal/null buffers during deepscan to avoid triggering vulnerabilities
    /// Use this with --deepscan on intentionally vulnerable drivers like HEVD
    #[arg(long)]
    safe: bool,

    /// Load a previously saved RL model to resume learning
    #[arg(long)]
    load_model: Option<PathBuf>,

    /// Save RL model every N iterations (default: 100000)
    #[arg(long, default_value = "100000")]
    save_interval: u64,

    /// Dump kernel addresses and exploit info (for shellcode building)
    #[arg(long)]
    info: bool,

    /// Replay a specific crash - provide path to last_input.bin or crash file
    #[arg(long)]
    replay: Option<PathBuf>,

    /// Test a specific IOCTL with null/zero input (for debugging crashes)
    #[arg(long, value_parser = parse_hex)]
    test_ioctl: Option<u32>,

    /// DEBUG mode - print iteration heartbeat every 100 iterations to track where crashes happen
    #[arg(long)]
    debug: bool,

    /// NULL-PTR mode - test METHOD_NEITHER IOCTLs with NULL/invalid pointers (DANGEROUS!)
    /// This tests if driver validates pointers before use - can cause kernel crash!
    #[arg(long)]
    null_ptr: bool,

    /// TCP target for two-agent fuzzing (e.g., 192.168.1.100:9999)
    /// Run executor.exe in VM, then use this to connect from host
    #[arg(long)]
    target: Option<String>,

    /// Pre-analysis JSON from quick_scan.py or analyze_driver.py
    /// Provides IOCTL codes, buffer sizes, and constraints discovered via static analysis
    #[arg(long)]
    analysis: Option<PathBuf>,

    /// GDI/USER Object Race Fuzzer - targets win32k.sys UAF bugs
    /// Creates/destroys GDI+User objects across threads to trigger race conditions
    #[arg(long)]
    gdi_race: bool,

    /// SCAN mode - enumerate loaded drivers and find vulnerable 3rd party targets
    /// Based on Connor McGarr's talk: 3rd party drivers are easier targets
    #[arg(long)]
    scan: bool,

    /// List processes that may have loaded vulnerable drivers
    #[arg(long)]
    processes: bool,

    /// Show PTE U/S bit flip technique for SMEP bypass
    #[arg(long)]
    pte: bool,
}

fn parse_hex(s: &str) -> Result<u32, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).map_err(|e| e.to_string())
}

/// Pre-analysis data from Python static analyzer (quick_scan.py / analyze_driver.py)
#[derive(Debug, Clone, Default)]
pub struct DriverAnalysis {
    pub driver_name: String,
    pub ioctls: Vec<IoctlInfo>,
    pub dependency_groups: Vec<Vec<u32>>,
}

#[derive(Debug, Clone)]
pub struct IoctlInfo {
    pub code: u32,
    pub min_input_size: usize,
    pub max_input_size: usize,
    pub min_output_size: usize,
    pub method: String,      // BUFFERED, IN_DIRECT, OUT_DIRECT, NEITHER
    pub access: String,      // ANY, READ, WRITE, READ|WRITE
    pub address: u64,        // Address in driver where it's handled
}

impl DriverAnalysis {
    /// Load analysis from JSON file
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read analysis file: {}", e))?;
        
        // Parse JSON manually (avoiding serde_json dependency in main binary)
        let mut analysis = DriverAnalysis::default();
        
        // Extract driver name
        if let Some(start) = content.find("\"driver\":") {
            if let Some(name_start) = content[start..].find('"').map(|i| start + i + 1) {
                if let Some(name_start2) = content[name_start..].find('"').map(|i| name_start + i + 1) {
                    if let Some(name_end) = content[name_start2..].find('"').map(|i| name_start2 + i) {
                        analysis.driver_name = content[name_start2..name_end].to_string();
                    }
                }
            }
        }
        
        // Extract IOCTLs - look for pattern "0x????????": {
        let ioctl_pattern = regex::Regex::new(r#""(0x[0-9A-Fa-f]{8})":\s*\{([^}]+)\}"#)
            .map_err(|e| format!("Regex error: {}", e))?;
        
        for cap in ioctl_pattern.captures_iter(&content) {
            let ioctl_str = cap.get(1).map(|m| m.as_str()).unwrap_or("0x00000000");
            let block = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            
            // Parse IOCTL code
            let code = u32::from_str_radix(
                ioctl_str.trim_start_matches("0x").trim_start_matches("0X"), 
                16
            ).unwrap_or(0);
            
            if code == 0 {
                continue;
            }
            
            // Parse fields from block
            let min_input = Self::extract_number(block, "min_input_size").unwrap_or(0) as usize;
            let max_input = Self::extract_number(block, "max_input_size").unwrap_or(4096) as usize;
            let min_output = Self::extract_number(block, "min_output_size").unwrap_or(0) as usize;
            let method = Self::extract_string(block, "method").unwrap_or_else(|| "BUFFERED".to_string());
            let access = Self::extract_string(block, "access").unwrap_or_else(|| "ANY".to_string());
            let address = Self::extract_hex(block, "address").unwrap_or(0);
            
            analysis.ioctls.push(IoctlInfo {
                code,
                min_input_size: min_input,
                max_input_size: max_input.max(min_input + 1),
                min_output_size: min_output,
                method,
                access,
                address,
            });
        }
        
        // Sort IOCTLs by code
        analysis.ioctls.sort_by_key(|i| i.code);
        
        Ok(analysis)
    }
    
    fn extract_number(block: &str, field: &str) -> Option<u64> {
        let pattern = format!(r#""{}":\s*(\d+)"#, field);
        let re = regex::Regex::new(&pattern).ok()?;
        re.captures(block)?.get(1)?.as_str().parse().ok()
    }
    
    fn extract_string(block: &str, field: &str) -> Option<String> {
        let pattern = format!(r#""{}":\s*"([^"]+)""#, field);
        let re = regex::Regex::new(&pattern).ok()?;
        Some(re.captures(block)?.get(1)?.as_str().to_string())
    }
    
    fn extract_hex(block: &str, field: &str) -> Option<u64> {
        let pattern = format!(r#""{}":\s*"(0x[0-9A-Fa-f]+)""#, field);
        let re = regex::Regex::new(&pattern).ok()?;
        let hex_str = re.captures(block)?.get(1)?.as_str();
        u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).ok()
    }
    
    /// Get list of IOCTL codes
    pub fn get_ioctl_codes(&self) -> Vec<u32> {
        self.ioctls.iter().map(|i| i.code).collect()
    }
    
    /// Get info for specific IOCTL
    pub fn get_ioctl_info(&self, code: u32) -> Option<&IoctlInfo> {
        self.ioctls.iter().find(|i| i.code == code)
    }
    
    /// Get minimum buffer size for IOCTL (to avoid wasting time with undersized buffers)
    pub fn get_min_size(&self, code: u32) -> usize {
        self.get_ioctl_info(code).map(|i| i.min_input_size).unwrap_or(0)
    }
    
    /// Print summary
    pub fn print_summary(&self) {
        println!("\n{}", "╔════════════════════════════════════════════════════════════════╗".cyan().bold());
        println!("{}", "║           📊 STATIC ANALYSIS LOADED                            ║".cyan().bold());
        println!("{}", "╚════════════════════════════════════════════════════════════════╝".cyan().bold());
        println!("  Driver: {}", self.driver_name.yellow());
        println!("  IOCTLs: {}", self.ioctls.len().to_string().green());
        
        if !self.ioctls.is_empty() {
            println!("\n  {:^12} {:^10} {:^12} {:^15}", "IOCTL", "MinSize", "Method", "Access");
            println!("  {} {} {} {}", "-".repeat(12), "-".repeat(10), "-".repeat(12), "-".repeat(15));
            
            for info in &self.ioctls {
                println!("  {:<12} {:>10} {:^12} {:^15}",
                    format!("0x{:08X}", info.code).yellow(),
                    info.min_input_size,
                    info.method,
                    info.access
                );
            }
        }
        println!();
    }
}

/// Check for kernel crashes from previous fuzzing sessions
fn check_for_kernel_crashes(output_dir: &std::path::Path) {
    // Check Windows minidump folder
    let minidump_dir = std::path::Path::new("C:\\Windows\\Minidump");
    
    // Load our last run timestamp (if exists)
    let timestamp_file = output_dir.join(".last_run_timestamp");
    let last_run: Option<std::time::SystemTime> = std::fs::metadata(&timestamp_file)
        .ok()
        .and_then(|m| m.modified().ok());
    
    // Check for new minidumps
    if minidump_dir.exists() {
        let mut new_crashes = Vec::new();
        
        if let Ok(entries) = std::fs::read_dir(minidump_dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        // Check if dump is newer than our last run
                        let is_new = match last_run {
                            Some(last) => modified > last,
                            None => {
                                // If no timestamp, check if dump is from today
                                if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default();
                                    // Within last 24 hours
                                    now.as_secs().saturating_sub(duration.as_secs()) < 86400
                                } else {
                                    false
                                }
                            }
                        };
                        
                        if is_new {
                            new_crashes.push(entry.path());
                        }
                    }
                }
            }
        }
        
        if !new_crashes.is_empty() {
            println!("\n{}", "╔════════════════════════════════════════════════════════════════╗".red().bold());
            println!("{}", "║  🔴 KERNEL CRASHES DETECTED FROM PREVIOUS SESSION!             ║".red().bold());
            println!("{}", "╚════════════════════════════════════════════════════════════════╝".red().bold());
            
            for crash in &new_crashes {
                println!("  {} {}", "→".red(), crash.display());
            }
            
            // Check for our last_input.bin
            let last_input = output_dir.join("last_input.bin");
            let last_ioctl = output_dir.join("last_ioctl_info.txt");
            
            if last_input.exists() {
                println!("\n{}", "[+] Last fuzzer input found - this may have caused the crash!".yellow().bold());
                println!("    Input: {}", last_input.display());
                
                if last_ioctl.exists() {
                    if let Ok(info) = std::fs::read_to_string(&last_ioctl) {
                        println!("    IOCTL info:\n{}", info);
                    }
                }
                
                // Copy to crashes folder with timestamp
                let crash_name = format!("kernel_crash_{}.bin", 
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0));
                let crash_dest = output_dir.join(&crash_name);
                if std::fs::copy(&last_input, &crash_dest).is_ok() {
                    println!("    {} Saved crash input: {}", "[+]".green(), crash_dest.display());
                }
            }
            
            println!("\n{}", "[!] Analyze dumps with WinDbg: !analyze -v".cyan());
            println!("{}", "[!] Previous fuzzing session caused kernel crash(es)!".yellow().bold());
            println!();
        }
    }
    
    // Update timestamp for next run
    std::fs::create_dir_all(output_dir).ok();
    if let Ok(mut f) = std::fs::File::create(&timestamp_file) {
        let _ = std::io::Write::write_all(&mut f, b"timestamp marker");
    }
}

fn print_banner() {
    // Enable Windows ANSI colors
    #[cfg(windows)]
    let _ = colored::control::set_virtual_terminal(true);
    
    println!(r#"
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   ██╗      █████╗ ██████╗ ██╗   ██╗██████╗ ██╗   ██╗ ██████╗ ║
    ║   ██║     ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗██║   ██║██╔════╝ ║
    ║   ██║     ███████║██║  ██║ ╚████╔╝ ██████╔╝██║   ██║██║  ███╗║
    ║   ██║     ██╔══██║██║  ██║  ╚██╔╝  ██╔══██╗██║   ██║██║   ██║║
    ║   ███████╗██║  ██║██████╔╝   ██║   ██████╔╝╚██████╔╝╚██████╔╝║
    ║   ╚══════╝╚═╝  ╚═╝╚═════╝    ╚═╝   ╚═════╝  ╚═════╝  ╚═════╝ ║
    ║                                                        🐞    ║
    ║       Windows Kernel Driver Fuzzer v1.0                      ║
    ║       "Heap corruption is not a bug, it's a feature"         ║
    ╚══════════════════════════════════════════════════════════════╝
    "#);
    let _ = std::io::stdout().flush();
}

fn main() {
    // Set panic hook to print useful info before crashing
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("\n[!!!] FUZZER PANIC: {}", panic_info);
        if let Some(location) = panic_info.location() {
            eprintln!("[!!!] Location: {}:{}", location.file(), location.line());
        }
        eprintln!("[!!!] This might indicate a bug in the fuzzer or driver memory corruption");
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }));
    
    // Windows SEH handler - register via raw FFI
    #[cfg(windows)]
    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn SetUnhandledExceptionFilter(
                lpTopLevelExceptionFilter: Option<unsafe extern "system" fn(*const std::ffi::c_void) -> i32>
            ) -> Option<unsafe extern "system" fn(*const std::ffi::c_void) -> i32>;
        }
        
        unsafe extern "system" fn crash_handler(info: *const std::ffi::c_void) -> i32 {
            // Log the crash with exception details
            let _ = std::io::stderr().write_all(b"\n[!!!] UNHANDLED EXCEPTION - Driver corrupted fuzzer!\n");
            let _ = std::io::stderr().write_all(b"[!!!] This input may have triggered a kernel bug!\n");
            
            // Try to extract exception code from EXCEPTION_POINTERS
            if !info.is_null() {
                let ptrs = info as *const *const u32;
                if !(*ptrs).is_null() {
                    let record = *ptrs;
                    let code = *record;
                    let hex = format!("{:08X}\n", code);
                    let _ = std::io::stderr().write_all(b"[!!!] Exception Code: 0x");
                    let _ = std::io::stderr().write_all(hex.as_bytes());
                }
            }
            
            // Log crash info for debugging
            let _ = std::io::stderr().write_all(b"[!!!] Check last_input.bin and last_ioctl_info.txt for crash details\n");
            let _ = std::io::stderr().flush();
            1 // EXCEPTION_EXECUTE_HANDLER - let system terminate
        }
        
        SetUnhandledExceptionFilter(Some(crash_handler));
    }
    
    // Enable Windows ANSI colors first
    #[cfg(windows)]
    let _ = colored::control::set_virtual_terminal(true);
    
    print_banner();
    
    let mut args = Args::parse();
    
    // Compute output directory based on device name if not explicitly set
    // Default ".\crashes" means user didn't specify -o, so use device name
    if args.output == PathBuf::from(".\\crashes") || args.output == PathBuf::from("./crashes") {
        if let Some(device) = &args.device {
            // Extract driver name from device path: \\.\ahcache -> ahcache
            let driver_name = device
                .trim_start_matches(r"\\.\")
                .trim_start_matches(r"\\.\GLOBALROOT\Device\")
                .trim_start_matches(r"\\.\GLOBALROOT\\Device\\")
                .replace(r"\", "_")
                .replace("/", "_");
            if !driver_name.is_empty() {
                args.output = PathBuf::from(&driver_name);
                println!("{} Output directory: {}/", "[*]".cyan(), driver_name);
            }
        }
    }
    
    // Check for kernel crashes from previous sessions
    check_for_kernel_crashes(&args.output);

    // TEST-IOCTL mode - safely test a specific IOCTL for reproduction
    if let Some(test_ioctl) = args.test_ioctl {
        let device = match &args.device {
            Some(d) => d.clone(),
            None => {
                eprintln!("{}", "[-] --test-ioctl requires --device <path>".red());
                return;
            }
        };
        
        println!("\n{}", "╔══════════════════════════════════════════════════════════════╗".yellow());
        println!("{}", "║     🔬 IOCTL TEST MODE - Safe crash reproduction             ║".yellow());
        println!("{}", "╚══════════════════════════════════════════════════════════════╝".yellow());
        
        println!("\n[*] Device: {}", device);
        println!("[*] IOCTL:  0x{:08X}", test_ioctl);
        
        // Decode IOCTL
        let device_type = (test_ioctl >> 16) & 0xFFFF;
        let function = (test_ioctl >> 2) & 0xFFF;
        let method = test_ioctl & 0x3;
        let access = (test_ioctl >> 14) & 0x3;
        
        println!("[*] Decoded:");
        println!("    Device Type: 0x{:04X} ({})", device_type, device_type);
        println!("    Function:    0x{:03X} ({})", function, function);
        println!("    Method:      {} ({})", method, match method {
            0 => "BUFFERED",
            1 => "IN_DIRECT",
            2 => "OUT_DIRECT", 
            3 => "NEITHER ⚠️ DANGEROUS",
            _ => "UNKNOWN"
        });
        println!("    Access:      {} ({})", access, match access {
            0 => "ANY_ACCESS",
            1 => "READ",
            2 => "WRITE",
            3 => "READ|WRITE",
            _ => "UNKNOWN"
        });
        
        let mut driver = match DriverIO::new(&device) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[-] Failed to open device: {}", e);
                return;
            }
        };
        
        // Use extra large output buffer with guard bytes
        let mut output_buffer = vec![0xCCu8; 8192]; // 8KB with 0xCC pattern
        
        // Test with different input sizes
        let test_sizes = [0, 4, 8, 10, 16, 32, 64, 128, 256];
        
        for size in test_sizes {
            let input = vec![0u8; size];
            
            print!("[*] Testing {} bytes... ", size);
            let _ = std::io::stdout().flush();
            
            let result = driver.send_ioctl(test_ioctl, &input, &mut output_buffer);
            
            match result {
                Ok(bytes_ret) => {
                    println!("{} returned {} bytes", "SUCCESS".green(), bytes_ret);
                    if bytes_ret > 0 {
                        println!("    Output (first 64): {:02X?}", &output_buffer[..64.min(bytes_ret as usize)]);
                    }
                }
                Err(code) => {
                    let code_u = code as u32;
                    println!("Error 0x{:08X} ({})", code_u, error_name(code_u));
                }
            }
            
            // Check if guard bytes were corrupted (buffer overflow detection)
            if output_buffer[4096..].iter().any(|&b| b != 0xCC) {
                println!("\n{}", "⚠️  BUFFER OVERFLOW DETECTED! Driver wrote beyond 4096 bytes!".red().bold());
                println!("    This is a potential kernel vulnerability!");
                
                // Find how much was written
                let mut overflow_end = 4096;
                for i in 4096..output_buffer.len() {
                    if output_buffer[i] != 0xCC {
                        overflow_end = i + 1;
                    }
                }
                println!("    Overflow extent: {} bytes beyond buffer", overflow_end - 4096);
            }
            
            // Reset guard bytes
            output_buffer[4096..].fill(0xCC);
        }
        
        println!("\n[*] Test complete. If fuzzer crashed here previously, it may be a race condition.");
        println!("[*] Try running with WinDbg attached: windbg -g -G windriver_fuzzer.exe ...");
        return;
    }

    // REPLAY mode - replay a crash from last_input.bin
    if let Some(replay_path) = &args.replay {
        let device = match &args.device {
            Some(d) => d.clone(),
            None => {
                eprintln!("{}", "[-] --replay requires --device <path>".red());
                return;
            }
        };
        
        println!("\n{}", "╔══════════════════════════════════════════════════════════════╗".red());
        println!("{}", "║     🔁 CRASH REPLAY MODE                                      ║".red());
        println!("{}", "╚══════════════════════════════════════════════════════════════╝".red());
        
        // Read input file
        let input = match std::fs::read(replay_path) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("[-] Failed to read {}: {}", replay_path.display(), e);
                return;
            }
        };
        
        // Try to read IOCTL from accompanying info file
        let info_path = replay_path.with_file_name("last_ioctl_info.txt");
        let ioctl = if let Ok(info) = std::fs::read_to_string(&info_path) {
            // Parse IOCTL from info file
            info.lines()
                .find(|l| l.starts_with("IOCTL:"))
                .and_then(|l| {
                    let hex = l.trim_start_matches("IOCTL:").trim().trim_start_matches("0x");
                    u32::from_str_radix(hex, 16).ok()
                })
                .unwrap_or_else(|| args.ioctl.unwrap_or(0x220000))
        } else {
            args.ioctl.unwrap_or(0x220000)
        };
        
        println!("[*] Device: {}", device);
        println!("[*] IOCTL:  0x{:08X}", ioctl);
        println!("[*] Input:  {} bytes", input.len());
        println!("[*] Hex:    {:02X?}", &input[..input.len().min(64)]);
        
        let mut driver = match DriverIO::new(&device) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[-] Failed to open device: {}", e);
                return;
            }
        };
        
        let mut output_buffer = vec![0xCCu8; 8192];
        
        println!("\n[*] Replaying crash input...");
        let result = driver.send_ioctl(ioctl, &input, &mut output_buffer);
        
        match result {
            Ok(bytes) => println!("[+] Success! Returned {} bytes", bytes),
            Err(code) => println!("[-] Error: 0x{:08X} ({})", code as u32, error_name(code as u32)),
        }
        
        // Check for overflow
        if output_buffer[4096..].iter().any(|&b| b != 0xCC) {
            println!("\n{}", "⚠️  BUFFER OVERFLOW DETECTED!".red().bold());
        }
        
        return;
    }

    // Discovery mode
    if args.discover {
        println!("{}", "[*] Discovering drivers and devices...".yellow());
        driver::discover_drivers();
        return;
    }
    
    // DEEPSCAN mode - scan ALL IOCTLs for a specific driver
    if args.deepscan {
        let device = match &args.device {
            Some(d) => d.clone(),
            None => {
                eprintln!("{}", "[-] --deepscan requires --device <path>".red());
                return;
            }
        };
        
        println!("{}", "[*] 🔬 DEEP IOCTL SCAN - Finding ALL valid IOCTLs".cyan().bold());
        println!("[*] Target: {}", device);
        if args.safe {
            println!("{}", "[*] SAFE MODE enabled - using minimal buffers to avoid crashes".green());
        } else {
            println!("{}", "[!] Use --safe flag if scanning vulnerable drivers like HEVD".yellow());
        }
        
        let mut driver = match DriverIO::new(&device) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[-] Failed to open device: {}", e);
                return;
            }
        };
        
        // Use safe or normal deepscan based on --safe flag
        let found = if args.safe {
            deep_scan_ioctls_safe(&mut driver)
        } else {
            deep_scan_ioctls(&mut driver)
        };
        
        if !found.is_empty() {
            // Save to file for later use
            let filename = format!("ioctls_{}.txt", 
                device.replace("\\", "_").replace(".", "_").replace("?", ""));
            if let Ok(mut f) = std::fs::File::create(&filename) {
                use std::io::Write;
                writeln!(f, "# IOCTLs discovered by Ladybug deep scan").ok();
                writeln!(f, "# Device: {}", device).ok();
                writeln!(f, "# Total: {} IOCTLs", found.len()).ok();
                writeln!(f, "#").ok();
                for ioctl in &found {
                    let _ = writeln!(f, "0x{:08X}", ioctl);
                }
                println!();
                println!("┌──────────────────────────────────────────────────────────────────────────────┐");
                println!("│  💾 Results saved to: {:<54}│", filename);
                println!("└──────────────────────────────────────────────────────────────────────────────┘");
            }
        }
        return;
    }
    
    // Info mode - dump kernel addresses for exploit building
    if args.info {
        println!("{}", "[*] Gathering kernel exploit information...".magenta().bold());
        dump_exploit_info(&args);
        return;
    }
    
    // CLFS mode - file-based fuzzer (no device needed!)
    if args.clfs {
        println!("{}", "[*] 🔥 CLFS FILE-BASED FUZZER - CVE-2025-29824 Style".red().bold());
        println!("{}", "[*] Target: clfs.sys - Use-After-Free in log file parsing".yellow());
        run_clfs_fuzzing(&args);
        return;
    }
    
    // WIN32K mode - comprehensive syscall fuzzing
    if args.win32k {
        run_win32k_fuzzing(&args);
        return;
    }
    
    // GDI/USER Race mode - object lifecycle fuzzing
    if args.gdi_race {
        println!("{}", "[*] 🏎️ GDI/USER OBJECT RACE FUZZER".red().bold());
        println!("{}", "[*] Target: win32k.sys UAF via object lifecycle racing".yellow());
        run_gdi_race_fuzzing(&args);
        return;
    }
    
    // SCAN mode - find vulnerable 3rd party drivers
    if args.scan {
        println!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
        println!("{}", "║     🔍 DRIVER SCAN MODE - Find Vulnerable 3rd Party Drivers  ║".cyan());
        println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
        println!();
        println!("{}", "[*] Based on Connor McGarr's research:".yellow());
        println!("{}", "    - 3rd party drivers are easier targets than native Windows".white());
        println!("{}", "    - Many have blatant read/write primitives".white());
        println!("{}", "    - Can bypass HVCI/CET/KCFG with IAT overwrites".white());
        println!();
        
        let targets = driver_hunter::scan_for_targets();
        
        if targets.is_empty() {
            println!("{}", "[!] No vulnerable drivers found. Try installing:".yellow());
            println!("    - HWiNFO64 (hwinfo64.exe)");
            println!("    - CPU-Z (cpuz.exe)");
            println!("    - MSI Afterburner");
            println!("    - Any RGB lighting software");
        } else {
            println!("\n{}", "[*] Test driver accessibility:".green());
            process_injector::test_driver_access();
        }
        
        return;
    }
    
    // PROCESSES mode - find processes that loaded vulnerable drivers
    if args.processes {
        println!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
        println!("{}", "║     🎯 PROCESS SCAN - Find Driver Loaders                    ║".cyan());
        println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
        println!();
        
        let targets = process_injector::find_ioctl_targets();
        
        if !targets.is_empty() {
            println!("\n{}", "[*] Processes you might want to target:".green());
            for proc in targets.iter().take(20) {
                println!("    PID {} - {}", proc.pid, proc.name);
            }
        }
        
        return;
    }

    // PTE mode - show SMEP bypass technique
    if args.pte {
        println!("{}", "╔══════════════════════════════════════════════════════════════╗".magenta());
        println!("{}", "║     🔓 PTE U/S BIT FLIP - SMEP Bypass Technique              ║".magenta());
        println!("{}", "╚══════════════════════════════════════════════════════════════╝".magenta());
        println!();
        pte_exploit::print_pte_technique();
        
        // Also show KUSER_SHARED_DATA
        driver_hunter::dump_kuser_shared_data();
        
        return;
    }
    
    // Need device for fuzzing
    let device = match &args.device {
        Some(d) => d.clone(),
        None => {
            println!("{}", "[!] Error: --device required for fuzzing".red());
            println!("    Use --discover to find available drivers");
            println!("    Example: ladybug.exe --device \"\\\\.\\VBoxGuest\"");
            return;
        }
    };
    
    // ============================================================
    // TCP MODE: Device is on REMOTE VM, don't check locally!
    // ============================================================
    if let Some(ref target) = args.target {
        println!("{}", "[*] 🌐 TCP MODE: Two-agent fuzzing enabled!".cyan().bold());
        println!("[*] Executor target: {}", target.yellow());
        println!("[*] Device {} is on the remote VM", device.cyan());
        println!("[*] Controller will detect crashes via connection drops");
        println!();
        
        // Create output dir for this device
        let device_name = device.replace("\\", "_").replace(".", "").replace(":", "");
        let output_dir = args.output.join(&device_name);
        std::fs::create_dir_all(&output_dir).ok();
        println!("{} {}/", "[*] Output directory:".cyan(), device_name);
        
        // Load pre-analysis if provided
        let analysis: Option<DriverAnalysis> = if let Some(ref analysis_path) = args.analysis {
            match DriverAnalysis::load(analysis_path) {
                Ok(a) => {
                    a.print_summary();
                    Some(a)
                }
                Err(e) => {
                    eprintln!("{} Failed to load analysis: {}", "[!]".red(), e);
                    None
                }
            }
        } else {
            None
        };
        
        // Connect to executor
        let mut tcp_driver = TcpDriverIO::new(target);
        if let Err(e) = tcp_driver.connect() {
            eprintln!("{} Failed to connect to executor: {}", "[!]".red(), e);
            eprintln!("    Make sure executor.exe is running in the VM:");
            eprintln!("    executor.exe --port 9999 --device {}", device);
            return;
        }
        
        // Get IOCTLs from analysis or use defaults
        let tcp_ioctls = if let Some(ref a) = analysis {
            let analysis_ioctls = a.get_ioctl_codes();
            println!("{} {} {}", "[+]".green(), "Using".cyan(), 
                format!("{} IOCTLs from static analysis!", analysis_ioctls.len()).green().bold());
            analysis_ioctls
        } else {
            println!("{}", "[!] No --analysis file provided. Use msfuzz_symbolic.py or hevd.json".yellow());
            vec![0x222003] // Default HEVD IOCTL
        };
        
        // Run TCP fuzzing
        run_ultimate_fuzzing_tcp(&mut tcp_driver, &tcp_ioctls, &args);
        return;
    }
    
    // ============================================================
    // LOCAL MODE: Device is on THIS machine
    // ============================================================
    let mut driver = match DriverIO::new(&device) {
        Ok(d) => d,
        Err(e) => {
            println!("{} {} - {}", "[!] Failed to open driver:".red(), device, e);
            return;
        }
    };
    
    println!("{} {}", "[+] Connected to:".green(), device);
    
    // Probe mode
    if args.probe {
        println!("{}", "[*] Probing for valid IOCTLs...".yellow());
        probe_ioctls(&mut driver, &args);
        return;
    }
    
    // NULL POINTER test mode - tests METHOD_NEITHER with dangerous pointers
    if args.null_ptr {
        println!("{}", "╔════════════════════════════════════════════════════════════════╗".red().bold());
        println!("{}", "║     ⚠️  NULL POINTER TEST MODE - DANGEROUS! ⚠️                  ║".red().bold());
        println!("{}", "║  Tests METHOD_NEITHER IOCTLs with NULL/invalid pointers        ║".red().bold());
        println!("{}", "║  This can CRASH THE KERNEL if driver doesn't validate!         ║".red().bold());
        println!("{}", "╚════════════════════════════════════════════════════════════════╝".red().bold());
        println!();
        
        let ioctls: Vec<u32> = if let (Some(start), Some(end)) = (args.ioctl_start, args.ioctl_end) {
            (start..=end).step_by(4).collect()
        } else if let Some(ioctl) = args.ioctl {
            vec![ioctl]
        } else {
            println!("{}", "[!] Need --ioctl or --ioctl-start/end for null pointer test".red());
            return;
        };
        
        test_null_pointers(&mut driver, &ioctls, &args);
        return;
    }
    
    // Build IOCTL list
    let ioctls: Vec<u32> = if let Some(ioctl) = args.ioctl {
        vec![ioctl]
    } else if let (Some(start), Some(end)) = (args.ioctl_start, args.ioctl_end) {
        // Limit to reasonable number of IOCTLs (max 10000)
        let range: Vec<u32> = (start..=end).step_by(4).collect();
        let range_len = range.len();
        if range_len > 10000 {
            println!("{} Range too large ({} IOCTLs), sampling 10000", "[!]".yellow(), range_len);
            range.into_iter().step_by(range_len / 10000 + 1).collect()
        } else {
            range
        }
    } else if args.ultimate {
        // This mode will auto-probe, use empty placeholder
        vec![0x220000] // Default IOCTL, will be overridden
    } else {
        println!("{}", "[!] No IOCTL specified. Use --ioctl or --ultimate".yellow());
        println!("    Example: --ioctl 0x220000");
        println!("    Or use: --ultimate (auto-probes IOCTLs)");
        return;
    };
    
    println!("{} {}", "[*] Target IOCTLs:".green(), ioctls.len());
    
    // ============================================================
    // DUMP KERNEL ADDRESSES BEFORE FUZZING (survives BSOD!)
    // ============================================================
    println!("{}", "[*] Saving kernel addresses BEFORE fuzzing (for post-crash exploit)...".cyan());
    if let Ok(info) = ExploitInfo::gather() {
        let info_path = args.output.join("kernel_addresses.txt");
        std::fs::create_dir_all(&args.output).ok();
        if let Ok(_) = info.save_to_file(&info_path) {
            println!("{} {} {}", "[+]".green(), "Kernel info saved to:".cyan(), info_path.display());
            println!("    Kernel Base: {}", format!("0x{:016X}", info.kernel_base).yellow());
            if let Some(hevd) = info.hevd_base {
                println!("    HEVD Base:   {}", format!("0x{:016X}", hevd).yellow());
            }
        }
    }
    println!();

    // ULTIMATE mode - EVERYTHING combined intelligently
    // Auto-probe if no IOCTLs specified!
    if args.ultimate {
        println!("{}", "[*] ⚡ ULTIMATE MODE: ALL TECHNIQUES COMBINED! ⚡".red().bold());
        
        // Load pre-analysis if provided
        let analysis: Option<DriverAnalysis> = if let Some(ref analysis_path) = args.analysis {
            match DriverAnalysis::load(analysis_path) {
                Ok(a) => {
                    a.print_summary();
                    Some(a)
                }
                Err(e) => {
                    eprintln!("{} Failed to load analysis: {}", "[!]".red(), e);
                    None
                }
            }
        } else {
            None
        };
        
        // Check if TCP mode (two-agent fuzzing)
        if let Some(ref target) = args.target {
            println!("{}", "[*] 🌐 TCP MODE: Two-agent fuzzing enabled!".cyan().bold());
            println!("[*] Executor target: {}", target.yellow());
            println!("[*] Controller will detect crashes via connection drops");
            println!();
            
            // Connect to executor
            let mut tcp_driver = TcpDriverIO::new(target);
            if let Err(e) = tcp_driver.connect() {
                eprintln!("{} Failed to connect to executor: {}", "[!]".red(), e);
                eprintln!("    Make sure executor.exe is running in the VM:");
                eprintln!("    executor.exe --port 9999 --device \\\\.\\ahcache");
                return;
            }
            
            // Get IOCTLs: from analysis, command line, or deep scan
            let ultimate_ioctls = if let Some(ref a) = analysis {
                // Use IOCTLs from static analysis
                let analysis_ioctls = a.get_ioctl_codes();
                println!("{} {} {}", "[+]".green(), "Using".cyan(), 
                    format!("{} IOCTLs from static analysis!", analysis_ioctls.len()).green().bold());
                analysis_ioctls
            } else if ioctls.is_empty() {
                // No IOCTLs specified - do deep scan
                println!("{}", "[*] 🔬 Running DEEP SCAN to discover ALL valid IOCTLs...".cyan());
                println!("{}", "[*] TIP: Run quick_scan.py first for instant results!".yellow());
                let probed = deep_scan_ioctls_tcp(&mut tcp_driver);
                if probed.is_empty() {
                    println!("{}", "[!] No IOCTLs found via deep scan".yellow());
                    ioctls.clone()
                } else {
                    println!("{} {} {}", "[+]".green(), "Found".cyan(), format!("{} IOCTLs to fuzz!", probed.len()).green().bold());
                    probed
                }
            } else {
                // Use command-line specified IOCTLs
                println!("{} {} {}", "[+]".green(), "Using".cyan(), format!("{} IOCTLs from command line", ioctls.len()).green());
                ioctls.clone()
            };
            
            run_ultimate_fuzzing_tcp(&mut tcp_driver, &ultimate_ioctls, &args);
            return;
        }
        
        // LOCAL mode (original behavior)
        // Use IOCTLs from: analysis file > command line > deep scan
        let ultimate_ioctls = if let Some(ref a) = analysis {
            // Use IOCTLs from static analysis
            let analysis_ioctls = a.get_ioctl_codes();
            println!("{} {} {}", "[+]".green(), "Using".cyan(), 
                format!("{} IOCTLs from static analysis!", analysis_ioctls.len()).green().bold());
            analysis_ioctls
        } else if ioctls.is_empty() {
            // No IOCTLs specified - do DEEP SCAN
            println!("{}", "[*] 🔬 Running DEEP SCAN to discover ALL valid IOCTLs...".cyan());
            println!("{}", "[*] This takes 5-10 minutes but finds every attack surface".yellow());
            let probed = deep_scan_ioctls(&mut driver);
            if probed.is_empty() {
                println!("{}", "[!] No IOCTLs found via deep scan, trying quick probe...".yellow());
                let quick = auto_probe_ioctls(&mut driver);
                if quick.is_empty() {
                    println!("{}", "[!] No IOCTLs found, using default".yellow());
                    ioctls.clone()
                } else {
                    quick
                }
            } else {
                println!("{} {} {}", "[+]".green(), "Found".cyan(), format!("{} IOCTLs to fuzz!", probed.len()).green().bold());
                probed
            }
        } else {
            // Use command-line specified IOCTLs
            println!("{} {} {}", "[+]".green(), "Using".cyan(), format!("{} IOCTLs from command line", ioctls.len()).green());
            ioctls.clone()
        };
        
        run_ultimate_fuzzing(&mut driver, &ultimate_ioctls, &args);
        return;
    }
    
    // Stateful/UAF fuzzing mode
    if args.stateful {
        println!("{}", "[*] STATEFUL MODE: Hunting UAF, Double-Free, Race Conditions...".magenta().bold());
        run_stateful_fuzzing(&mut driver, &ioctls, &args);
        return;
    }
    
    // Initialize fuzzing components
    let mut mutator = Mutator::new();
    let mut coverage = ResponseCoverage::new();
    let mut corpus = Corpus::new(args.corpus.clone(), 10000);
    
    // Add initial seeds if corpus is empty
    if corpus.is_empty() {
        for &ioctl in &ioctls {
            for entry in Corpus::generate_initial(ioctl) {
                corpus.add(entry);
            }
        }
    }
    
    // Statistics
    let stats = FuzzStats::new();
    let running = Arc::new(AtomicBool::new(true));
    
    // Handle Ctrl+C
    let r = running.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        if r.swap(false, Ordering::SeqCst) {
            println!("\n{}", "[!] Stopping fuzzer...".yellow());
        }
    }) {
        println!("{} {}", "[!] Warning: Couldn't set Ctrl-C handler:".yellow(), e);
    }
    
    let start_time = Instant::now();
    
    println!("\n{}", "[*] Starting fuzzing...".green().bold());
    println!("{}", "─".repeat(60));
    
    // Main fuzzing loop
    let mut iteration: u64 = 0;
    // Use LARGE buffer for METHOD_NEITHER IOCTLs - drivers can write anywhere!
    // We use 64KB to give plenty of room and detect overflows
    let mut output_buffer = vec![0xCCu8; 65536];
    
    while running.load(Ordering::SeqCst) {
        if args.iterations > 0 && iteration >= args.iterations {
            break;
        }
        
        // Select IOCTL
        let ioctl = ioctls[iteration as usize % ioctls.len()];
        
        // Get input from corpus and mutate
        let base_input = if let Some(entry) = corpus.select() {
            entry.data.clone()
        } else {
            vec![0u8; 64]
        };
        
        let input = mutator.mutate(&base_input);
        
        // Send to driver
        let result = driver.send_ioctl(ioctl, &input, &mut output_buffer);
        
        stats.total_execs.fetch_add(1, Ordering::Relaxed);
        
        match result {
            Ok(bytes_returned) => {
                // Track response for pseudo-coverage
                // Clamp bytes_returned to buffer size to prevent panic from buggy drivers
                let safe_bytes = (bytes_returned as usize).min(output_buffer.len());
                let output = &output_buffer[..safe_bytes];
                let is_new = coverage.record_response(ioctl, 0, output);
                
                if is_new {
                    // NEW response pattern! Save this input
                    stats.new_coverage.fetch_add(1, Ordering::Relaxed);
                    
                    let mut entry = CorpusEntry::new(input.clone(), ioctl);
                    entry.new_edges = 1;
                    corpus.add(entry);
                    
                    if args.verbose {
                        println!("{} IOCTL 0x{:08X} - {} bytes -> {} bytes out", 
                            "[+] NEW RESPONSE!".green().bold(),
                            ioctl, 
                            input.len(),
                            bytes_returned
                        );
                    }
                }
            }
            Err(error_code) => {
                // Track error for coverage
                let is_new = coverage.record_response(ioctl, error_code, &[]);
                
                if is_new && args.verbose {
                    println!("{} IOCTL 0x{:08X} Error: 0x{:08X}", 
                        "[*] New error code:".yellow(),
                        ioctl,
                        error_code as u32
                    );
                }
                
                // Check for interesting errors (potential crashes)
                if is_interesting_error(error_code as u32) {
                    stats.crashes.fetch_add(1, Ordering::Relaxed);
                    
                    println!("{} IOCTL 0x{:08X} Error: 0x{:08X}", 
                        "[!] INTERESTING ERROR!".red().bold(),
                        ioctl,
                        error_code as u32
                    );
                    
                    // Save crash
                    save_crash(&args.output, ioctl, &input, error_code as u32);
                }
            }
        }
        
        iteration += 1;
        
        // Print stats every 1000 iterations
        if iteration % 1000 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let execs_per_sec = iteration as f64 / elapsed;
            
            print!("\r{} iter: {} | exec/s: {:.1} | coverage: {} | corpus: {} | crashes: {}   ",
                "[*]".cyan(),
                iteration,
                execs_per_sec,
                coverage.unique_responses(),
                corpus.len(),
                stats.crashes.load(Ordering::Relaxed)
            );
            std::io::stdout().flush().unwrap();
        }
    }
    
    // Final stats
    let elapsed = start_time.elapsed();
    println!("\n\n{}", "═".repeat(60));
    println!("{}", "              FUZZING SESSION COMPLETE".green().bold());
    println!("{}", "═".repeat(60));
    println!("  Total iterations:  {}", iteration);
    println!("  Runtime:           {:?}", elapsed);
    println!("  Exec/sec:          {:.2}", iteration as f64 / elapsed.as_secs_f64().max(0.001));
    println!("  Unique responses:  {}", coverage.unique_responses());
    println!("  Unique errors:     {}", coverage.unique_errors());
    println!("  Crashes found:     {}", stats.crashes.load(Ordering::Relaxed));
    println!("  Corpus size:       {}", corpus.len());
    println!("{}", "═".repeat(60));
}

fn probe_ioctls(driver: &mut DriverIO, args: &Args) {
    let ranges = vec![
        (0x00220000u32, 0x00220100u32, "Standard range"),
        (0x0022E000, 0x0022E100, "Extended range"),
        (0x00222000, 0x00222100, "Alternate range"),
        (0x80002000, 0x80002100, "High range"),
    ];
    
    let mut found = Vec::new();
    let test_input = vec![0u8; 64];
    let mut output = vec![0u8; 4096];
    let total_ranges = ranges.len();
    let mut current_range = 0;
    
    for (start, end, _name) in &ranges {
        current_range += 1;
        
        for ioctl in (*start..=*end).step_by(4) {
            let result = driver.send_ioctl(ioctl, &test_input, &mut output);
            print!("\r[*] Probing IOCTLs... {}/{} ranges | {} found          ", current_range, total_ranges, found.len());
            let _ = std::io::stdout().flush();
            
            match result {
                Ok(bytes) => {
                    found.push((ioctl, "Success", bytes));
                }
                Err(code) => {
                    // NOT_SUPPORTED and INVALID_FUNCTION mean the IOCTL isn't implemented
                    // Other errors might mean the IOCTL IS implemented but we sent bad data
                    let code_u = code as u32;
                    if code_u != 0x00000001 && // ERROR_INVALID_FUNCTION
                       code_u != 0xC00000BB && // STATUS_NOT_SUPPORTED
                       code_u != 0x80070001    // E_NOT_IMPL
                    {
                        let error_name = match code_u {
                            0x00000005 => "ACCESS_DENIED",
                            0x00000006 => "INVALID_HANDLE",
                            0x00000057 => "INVALID_PARAMETER",
                            0x0000007A => "INSUFFICIENT_BUFFER",
                            0xC0000010 => "INVALID_DEVICE_REQUEST",
                            0xC000000D => "INVALID_PARAMETER",
                            _ => "IMPLEMENTED?",
                        };
                        found.push((ioctl, error_name, 0));
                    }
                }
            }
        }
    }
    
    println!("\r[+] Probe complete: {} IOCTLs found                              ", found.len());
    
    // Show found IOCTLs in compact format - just the hex codes
    if !found.is_empty() {
        let ioctl_list: Vec<String> = found.iter().map(|(i, _, _)| format!("0x{:08X}", i)).collect();
        println!("    IOCTLs: {}", ioctl_list.join(", "));
    }
}

/// Test METHOD_NEITHER IOCTLs with NULL and invalid pointers
/// This can trigger kernel crashes if driver doesn't validate pointers!
fn test_null_pointers(driver: &mut DriverIO, ioctls: &[u32], args: &Args) {
    use std::io::Write;
    
    std::fs::create_dir_all(&args.output).ok();
    
    println!("[*] Testing {} IOCTLs with dangerous pointers...", ioctls.len());
    println!();
    
    // Different pointer values to test
    let test_pointers: Vec<(usize, &str)> = vec![
        (0x0, "NULL"),
        (0x1, "INVALID (0x1)"),
        (0x1000, "LOW_ADDR (0x1000)"),
        (0xFFFF_FFFF, "MAX_32BIT"),
        (0xDEAD_BEEF, "DEADBEEF"),
        (0xFFFF_8000_0000_0000, "KERNEL_SPACE"),  // Typical kernel address
    ];
    
    let mut crashes = Vec::new();
    
    for ioctl in ioctls {
        // Check if this is a METHOD_NEITHER IOCTL (last 2 bits = 3)
        let method = *ioctl & 0x3;
        let method_name = match method {
            0 => "BUFFERED",
            1 => "IN_DIRECT", 
            2 => "OUT_DIRECT",
            3 => "NEITHER",
            _ => "UNKNOWN",
        };
        
        print!("\r[*] Testing IOCTL 0x{:08X} ({})...          ", ioctl, method_name);
        let _ = std::io::stdout().flush();
        
        // Only test METHOD_NEITHER with NULL pointers (most dangerous)
        if method != 3 {
            continue;
        }
        
        println!();
        println!("  {} IOCTL 0x{:08X} is METHOD_NEITHER - testing dangerous pointers!", "[!]".yellow(), ioctl);
        
        for (ptr_val, ptr_name) in &test_pointers {
            print!("    Testing {} pointer... ", ptr_name);
            let _ = std::io::stdout().flush();
            
            // Save info before potentially crashing
            let info_path = args.output.join("last_null_test.txt");
            let mut f = std::fs::File::create(&info_path).ok();
            if let Some(ref mut file) = f {
                writeln!(file, "IOCTL: 0x{:08X}", ioctl).ok();
                writeln!(file, "Pointer: {} (0x{:X})", ptr_name, ptr_val).ok();
                writeln!(file, "Method: {}", method_name).ok();
            }
            
            // Try with NULL/invalid input pointer, valid output
            let mut output = vec![0u8; 65536];
            let result = driver.send_ioctl_raw(
                *ioctl,
                *ptr_val,           // Dangerous input pointer!
                0x1000,             // Claim there's 4KB of input
                output.as_mut_ptr() as usize,
                output.len() as u32,
            );
            
            match result {
                Ok(bytes) => {
                    println!("{} returned {} bytes", "SUCCESS".green(), bytes);
                }
                Err(code) => {
                    let code_u = code as u32;
                    let status = match code_u {
                        0xC0000005 => "ACCESS_VIOLATION ⚠️",
                        0xC000000D => "INVALID_PARAMETER",
                        0xC0000010 => "INVALID_DEVICE_REQUEST",
                        _ => "OTHER_ERROR",
                    };
                    println!("{} (0x{:08X})", status, code_u);
                    
                    if code_u == 0xC0000005 {
                        crashes.push((*ioctl, *ptr_val, *ptr_name));
                    }
                }
            }
            
            // Small delay to let kernel settle
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    
    println!();
    println!("{}", "═".repeat(60));
    println!("{}", "NULL POINTER TEST RESULTS".cyan().bold());
    println!("{}", "═".repeat(60));
    
    if crashes.is_empty() {
        println!("{}", "[+] No crashes detected - driver appears to validate pointers".green());
    } else {
        println!("{}", "[!] POTENTIAL VULNERABILITIES FOUND!".red().bold());
        for (ioctl, ptr, name) in &crashes {
            println!("  IOCTL 0x{:08X} crashed with {} pointer (0x{:X})", ioctl, name, ptr);
        }
        println!();
        println!("{}", "If kernel BSOD'd, this is a kernel vulnerability!".yellow().bold());
    }
}

/// Deep scan: systematically scan ALL realistic IOCTL ranges to find every valid IOCTL
/// This is comprehensive but slow (~5-10 minutes)
fn deep_scan_ioctls(driver: &mut DriverIO) -> Vec<u32> {
    deep_scan_ioctls_with_safe(driver, false)
}

fn deep_scan_ioctls_safe(driver: &mut DriverIO) -> Vec<u32> {
    deep_scan_ioctls_with_safe(driver, true)
}

fn deep_scan_ioctls_with_safe(driver: &mut DriverIO, safe_mode: bool) -> Vec<u32> {
    if safe_mode {
        println!("[*] SAFE DEEPSCAN: Using NULL/minimal buffers to avoid triggering vulns");
        println!("    This mode discovers IOCTLs without crashing vulnerable drivers");
    } else {
        println!("[*] DEEP SCAN: Scanning entire IOCTL space systematically...");
        println!("    WARNING: May crash intentionally vulnerable drivers! Use --safe for HEVD");
    }
    println!();
    
    let mut found = Vec::new();
    let mut output = vec![0u8; 4096];
    
    // IOCTL structure:
    // Bits 31-16: Device Type
    // Bits 15-14: Required Access  
    // Bits 13-2:  Function Code (0-4095)
    // Bits 1-0:   Method (0-3)
    
    // Scan ALL device types that real drivers use
    // Skip: 0x00 (reserved), 0x01-0x10 (system devices)
    let device_types: Vec<u32> = vec![
        0x0012, // FILE_DEVICE_NETWORK - AFD, tcpip
        0x0022, // FILE_DEVICE_UNKNOWN - most custom drivers (HEVD, VBox, etc.)
        0x0027, // FILE_DEVICE_DISK_FILE_SYSTEM
        0x0029, // FILE_DEVICE_NETWORK_FILE_SYSTEM
        0x002D, // FILE_DEVICE_KS (kernel streaming)
        0x0034, // FILE_DEVICE_KSEC
        0x0038, // FILE_DEVICE_CRYPT_PROVIDER
        0x0039, // FILE_DEVICE_WPD
        0x003E, // FILE_DEVICE_BIOMETRIC
        0x8000, // High bit set - custom drivers
    ];
    
    let total_device_types = device_types.len();
    let start_time = std::time::Instant::now();
    let mut total_scanned: u64 = 0;
    
    // Error codes that mean "IOCTL not implemented" - skip these
    let not_implemented_errors: [i32; 6] = [
        0x00000001,                    // ERROR_INVALID_FUNCTION
        0xC00000BB_u32 as i32,         // STATUS_NOT_SUPPORTED  
        0x80070001_u32 as i32,         // E_NOT_IMPL
        0xC0000010_u32 as i32,         // STATUS_INVALID_DEVICE_REQUEST
        1,                             // ERROR_INVALID_FUNCTION (raw)
        6,                             // ERROR_INVALID_HANDLE
    ];
    
    // Error codes that mean "IOCTL exists but wrong params" - KEEP these
    let implemented_errors: [i32; 8] = [
        0x00000057,                    // ERROR_INVALID_PARAMETER
        0x0000007A,                    // ERROR_INSUFFICIENT_BUFFER
        0xC000000D_u32 as i32,         // STATUS_INVALID_PARAMETER
        0xC0000023_u32 as i32,         // STATUS_BUFFER_TOO_SMALL
        0xC0000206_u32 as i32,         // STATUS_INVALID_BUFFER_SIZE
        0x80070057_u32 as i32,         // E_INVALIDARG
        0x8007007A_u32 as i32,         // ERROR_INSUFFICIENT_BUFFER (HRESULT)
        0x00000018,                    // ERROR_BAD_LENGTH
    ];
    
    // SAFE MODE: Only use METHOD_BUFFERED (0) and minimal sizes to avoid triggering vulns
    // NORMAL MODE: Try all methods and larger sizes
    let test_sizes: Vec<usize> = if safe_mode {
        vec![0, 4, 8]  // Minimal sizes - just enough to check if IOCTL exists
    } else {
        vec![0, 8, 16, 32, 64, 128, 256]
    };
    
    // In safe mode, only scan METHOD_BUFFERED (0) which is safest
    let methods: Vec<u32> = if safe_mode {
        vec![0]  // Only METHOD_BUFFERED - copies data, safer
    } else {
        vec![0, 1, 2, 3]  // All methods
    };
    
    for (dt_idx, &device_type) in device_types.iter().enumerate() {
        // Scan function codes - most drivers use 0x800-0xFFF range
        for function in 0x0000u32..=0x0FFF {
            for &method in &methods {
                for access in 0u32..=3 {
                    // Build IOCTL: CTL_CODE(device_type, function, method, access)
                    let ioctl = (device_type << 16) | (access << 14) | (function << 2) | method;
                    
                    total_scanned += 1;
                    
                    // Progress every 10000 IOCTLs
                    if total_scanned % 10000 == 0 {
                        let elapsed = start_time.elapsed().as_secs_f32();
                        let rate = total_scanned as f32 / elapsed;
                        print!("\r[*] DevType 0x{:02X} ({}/{}) | Scanned: {} | Found: {} | {:.0}/sec          ", 
                               device_type, dt_idx + 1, total_device_types, total_scanned, found.len(), rate);
                        let _ = std::io::stdout().flush();
                    }
                    
                    // Skip if already found
                    if found.contains(&ioctl) {
                        continue;
                    }
                    
                    // Try multiple input sizes
                    let mut is_implemented = false;
                    for &size in &test_sizes {
                        // SAFE MODE: Use all zeros (less likely to trigger vulns)
                        // NORMAL MODE: Use 0x41 pattern (better for finding parsing bugs)
                        let test_input = if safe_mode {
                            vec![0u8; size]  // All zeros - safe
                        } else {
                            vec![0x41u8; size]  // 'A' pattern - may trigger vulns
                        };
                        let result = driver.send_ioctl(ioctl, &test_input, &mut output);
                        
                        match result {
                            Ok(_) => {
                                // Success = definitely implemented
                                is_implemented = true;
                                break;
                            }
                            Err(code) => {
                                // Check if this error means "not implemented"
                                if not_implemented_errors.contains(&code) {
                                    break; // Skip - not implemented
                                }
                                
                                // Check if this error means "implemented but wrong params"
                                if implemented_errors.contains(&code) {
                                    is_implemented = true;
                                    break;
                                }
                                
                                // ACCESS_DENIED might mean implemented but needs privileges
                                // Count it as implemented
                                if code == 5 || code == 0x80070005_u32 as i32 {
                                    is_implemented = true;
                                    break;
                                }
                                
                                // Any other non-zero error that's not "not implemented"
                                // is likely an implemented IOCTL with validation
                                if code != 0 && !not_implemented_errors.contains(&code) {
                                    is_implemented = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if is_implemented {
                        found.push(ioctl);
                    }
                }
            }
        }
    }
    
    let elapsed = start_time.elapsed();
    println!("\r                                                                              ");
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                        🔬 DEEP SCAN COMPLETE                                 ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║  Scanned: {:>10} IOCTLs in {:.1}s                                        ║", total_scanned, elapsed.as_secs_f32());
    println!("║  Found:   {:>10} valid IOCTLs                                            ║", found.len());
    if safe_mode {
        println!("║  Mode:    SAFE (minimal buffers)                                            ║");
    } else {
        println!("║  Mode:    NORMAL (full probing)                                             ║");
    }
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    
    // Sort and show detailed results
    if !found.is_empty() {
        found.sort();
        
        // Group by device type
        let mut by_device_type: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
        for &ioctl in &found {
            let device_type = (ioctl >> 16) & 0xFFFF;
            by_device_type.entry(device_type).or_insert_with(Vec::new).push(ioctl);
        }
        
        println!();
        println!("┌──────────────────────────────────────────────────────────────────────────────┐");
        println!("│                          DISCOVERED IOCTLs                                   │");
        println!("├──────────────────────────────────────────────────────────────────────────────┤");
        
        // Show by device type
        let mut device_types: Vec<_> = by_device_type.keys().collect();
        device_types.sort();
        
        for &dt in &device_types {
            let ioctls = &by_device_type[dt];
            let dt_name = match *dt {
                0x0012 => "FILE_DEVICE_NETWORK",
                0x0022 => "FILE_DEVICE_UNKNOWN",
                0x0027 => "FILE_DEVICE_DISK_FILE_SYSTEM",
                0x0029 => "FILE_DEVICE_NETWORK_FILE_SYSTEM",
                0x002D => "FILE_DEVICE_KS",
                0x0034 => "FILE_DEVICE_KSEC",
                0x0038 => "FILE_DEVICE_CRYPT_PROVIDER",
                0x0039 => "FILE_DEVICE_WPD",
                0x003E => "FILE_DEVICE_BIOMETRIC",
                0x8000 => "CUSTOM_DEVICE (0x8000)",
                _ => "UNKNOWN",
            };
            println!("│                                                                              │");
            println!("│  Device Type 0x{:04X} ({})                           ", *dt, dt_name);
            println!("│  ─────────────────────────────────────────────────────────────────────────── │");
            
            // Print IOCTLs in rows of 4
            for chunk in ioctls.chunks(4) {
                let formatted: Vec<String> = chunk.iter().map(|x| format!("0x{:08X}", x)).collect();
                let line = formatted.join("  ");
                println!("│    {}{}│", line, " ".repeat(72 - line.len() - 4));
            }
        }
        
        println!("│                                                                              │");
        println!("└──────────────────────────────────────────────────────────────────────────────┘");
        
        // Summary for fuzzing
        println!();
        println!("┌──────────────────────────────────────────────────────────────────────────────┐");
        println!("│                          FUZZING RECOMMENDATIONS                             │");
        println!("├──────────────────────────────────────────────────────────────────────────────┤");
        println!("│                                                                              │");
        println!("│  To fuzz these IOCTLs:                                                       │");
        println!("│    ladybug --device <device> --ioctl 0x{:08X} --iterations 100000        │", found[0]);
        println!("│                                                                              │");
        println!("│  To fuzz a range:                                                            │");
        println!("│    ladybug --device <device> --ioctl_start 0x{:08X} --ioctl_end 0x{:08X} │", 
                 found.first().unwrap(), found.last().unwrap());
        println!("│                                                                              │");
        println!("│  For ultimate fuzzing (all techniques):                                      │");
        println!("│    ladybug --device <device> --ultimate --iterations 1000000                 │");
        println!("│                                                                              │");
        println!("└──────────────────────────────────────────────────────────────────────────────┘");
    } else {
        println!();
        println!("┌──────────────────────────────────────────────────────────────────────────────┐");
        println!("│  ⚠️  No IOCTLs found! Check:                                                  │");
        println!("│    - Device path is correct                                                  │");
        println!("│    - Driver is loaded (sc query <driver>)                                    │");
        println!("│    - You have access permissions                                             │");
        println!("└──────────────────────────────────────────────────────────────────────────────┘");
    }
    
    found
}

/// Auto-probe common IOCTL ranges and return list of real IOCTLs
fn auto_probe_ioctls(driver: &mut DriverIO) -> Vec<u32> {
    // Use the SAME ranges as --probe (these are the ones that actually work)
    let ranges = vec![
        (0x00220000u32, 0x00220100u32),  // Standard range
        (0x0022E000, 0x0022E100),         // Extended range
        (0x00222000, 0x00222100),         // Alternate range
        (0x80002000, 0x80002100),         // High range
    ];
    
    let mut found = Vec::new();
    let test_sizes = vec![0, 8, 24, 48, 64, 128, 256, 512];
    let mut output = vec![0u8; 4096];
    let total_ranges = ranges.len();
    let mut scanned = 0usize;
    
    for (start, end) in ranges {
        scanned += 1;
        print!("\r[*] Scanning IOCTLs... {}/{} ranges | {} found          ", scanned, total_ranges, found.len());
        let _ = std::io::stdout().flush();
        
        for ioctl in (start..=end).step_by(4) {
            // Try multiple input sizes to find what works
            for &size in &test_sizes {
                let test_input = vec![0u8; size];
                let result = driver.send_ioctl(ioctl, &test_input, &mut output);
                
                match result {
                    Ok(_) => {
                        // Success! This IOCTL is definitely implemented
                        if !found.contains(&ioctl) {
                            found.push(ioctl);
                        }
                        break;
                    }
                    Err(code) => {
                        let code_u = code as u32;
                        // These errors mean "IOCTL not supported by this driver" - skip
                        let not_implemented = 
                           code_u == 0x00000001 || // ERROR_INVALID_FUNCTION
                           code_u == 0xC00000BB || // STATUS_NOT_SUPPORTED  
                           code_u == 0x80070001 || // E_NOT_IMPL
                           code_u == 0xC0000010 || // STATUS_INVALID_DEVICE_REQUEST
                           code == 1;              // ERROR_INVALID_FUNCTION (raw)
                        
                        if not_implemented {
                            break; // Skip - not implemented
                        }
                        
                        // ACCESS_DENIED without trying - skip
                        if code == 5 || code_u == 0x80070005 {
                            break;
                        }
                        
                        // Any OTHER error = IOCTL exists, just needs different input
                        // This includes STATUS_INVALID_PARAMETER, BUFFER_TOO_SMALL, etc.
                        if !found.contains(&ioctl) {
                            found.push(ioctl);
                        }
                        break;
                    }
                }
            }
        }
    }
    
    println!("\r[+] Scan complete: {} IOCTLs found                              ", found.len());
    
    // Sort for consistent ordering
    found.sort();
    found
}

struct FuzzStats {
    total_execs: AtomicU64,
    new_coverage: AtomicU64,
    crashes: AtomicU64,
}

impl FuzzStats {
    fn new() -> Self {
        Self {
            total_execs: AtomicU64::new(0),
            new_coverage: AtomicU64::new(0),
            crashes: AtomicU64::new(0),
        }
    }
}

fn is_interesting_error(code: u32) -> bool {
    matches!(code, 
        0xC0000005 |  // ACCESS_VIOLATION
        0xC0000006 |  // IN_PAGE_ERROR
        0xC0000017 |  // NO_MEMORY
        0xC000001D |  // ILLEGAL_INSTRUCTION
        0xC0000025 |  // NONCONTINUABLE_EXCEPTION
        0xC0000026 |  // INVALID_DISPOSITION
        0xC00000FD |  // STACK_OVERFLOW
        0xC0000135 |  // DLL_NOT_FOUND (can indicate corruption)
        0xC0000142    // DLL_INIT_FAILED
    )
}

fn save_crash(output: &PathBuf, ioctl: u32, input: &[u8], error: u32) {
    use std::fs;
    use sha2::{Sha256, Digest};
    
    let _ = fs::create_dir_all(output);
    
    let mut hasher = Sha256::new();
    hasher.update(input);
    let hash_bytes = hasher.finalize();
    let hash = format!("{:x}", hash_bytes).chars().take(16).collect::<String>();
    
    let filename = output.join(format!(
        "crash_ioctl_{:08X}_err_{:08X}_{}.bin",
        ioctl, error, hash
    ));
    
    let _ = fs::write(&filename, input);
    
    // Save metadata as JSON
    let meta = format!(
        r#"{{
  "ioctl": "0x{:08X}",
  "ioctl_decoded": "{}",
  "error": "0x{:08X}",
  "input_size": {},
  "input_hex": "{}",
  "timestamp": "{}"
}}"#,
        ioctl,
        driver::ioctl_decode(ioctl),
        error,
        input.len(),
        hex::encode(input),
        chrono::Utc::now().to_rfc3339()
    );
    
    let meta_filename = output.join(format!(
        "crash_ioctl_{:08X}_err_{:08X}_{}.json",
        ioctl, error, hash
    ));
    
    let _ = fs::write(&meta_filename, meta);
    
    println!("{} {}", "[+] Crash saved:".green(), filename.display());
}
/// Stateful fuzzing mode - finds UAF, Double-Free, state bugs
fn run_stateful_fuzzing(driver: &mut DriverIO, ioctls: &[u32], args: &Args) {
    
    let mut stateful = StatefulFuzzer::new();
    
    // Add all IOCTLs to stateful fuzzer
    for &ioctl in ioctls {
        stateful.add_ioctl(ioctl);
    }
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let _ = ctrlc::set_handler(move || {
        if r.swap(false, Ordering::SeqCst) {
            println!("\n{}", "[!] Stopping stateful fuzzer...".yellow());
        }
    });
    
    let start_time = Instant::now();
    let mut sequences_run = 0u64;
    let mut crashes = 0u64;
    let mut interesting = 0u64;
    let mut output_buffer = vec![0u8; 4096];
    
    let patterns = SequencePattern::all();
    
    println!("{}", "[*] Starting stateful fuzzing (UAF/Double-Free hunter)...".green().bold());
    println!("{}", "    Patterns: UseAfterFree, DoubleFree, AllocateMany, Interleaved".cyan());
    println!("{}", "─".repeat(60));
    
    while running.load(Ordering::SeqCst) {
        if args.iterations > 0 && sequences_run >= args.iterations {
            break;
        }
        
        // Pick a pattern
        let pattern = patterns[sequences_run as usize % patterns.len()];
        
        // Generate sequence
        let sequence = stateful.generate_sequence(pattern);
        
        if args.verbose {
            println!("{} {:?} ({} calls)", "[>] Sequence:".cyan(), pattern, sequence.len());
        }
        
        // Execute sequence
        for (ioctl, input) in &sequence {
            let result = driver.send_ioctl(*ioctl, input, &mut output_buffer);
            
            match result {
                Ok(bytes) => {
                    let output = &output_buffer[..bytes as usize];
                    stateful.record_response(*ioctl, input, output, true);
                    
                    if args.verbose && bytes > 0 {
                        println!("    {} 0x{:08X} -> {} bytes", "[OK]".green(), ioctl, bytes);
                    }
                }
                Err(code) => {
                    stateful.record_response(*ioctl, input, &[], false);
                    
                    let code_u = code as u32;
                    
                    // Check for UAF/memory corruption indicators
                    if is_interesting_error(code_u) {
                        crashes += 1;
                        println!("{} Pattern {:?} IOCTL 0x{:08X} Error: 0x{:08X}", 
                            "[!!!] CRASH/UAF DETECTED!".red().bold(),
                            pattern,
                            ioctl,
                            code_u
                        );
                        
                        // Save the entire sequence
                        save_sequence_crash(&args.output, &sequence, code_u, pattern);
                    } else if is_state_error(code_u) {
                        interesting += 1;
                        if args.verbose {
                            println!("    {} 0x{:08X} state error: 0x{:08X}", 
                                "[?]".yellow(), ioctl, code_u);
                        }
                    }
                }
            }
        }
        
        sequences_run += 1;
        
        // Stats every 100 sequences
        if sequences_run % 100 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let seq_per_sec = sequences_run as f64 / elapsed;
            
            print!("\r{} seqs: {} | seq/s: {:.1} | crashes: {} | interesting: {}   ",
                "[*]".cyan(),
                sequences_run,
                seq_per_sec,
                crashes,
                interesting
            );
            let _ = std::io::stdout().flush();
        }
    }
    
    // Final stats
    let elapsed = start_time.elapsed();
    println!("\n\n{}", "═".repeat(60));
    println!("{}", "         STATEFUL FUZZING SESSION COMPLETE".green().bold());
    println!("{}", "═".repeat(60));
    println!("  Sequences run:     {}", sequences_run);
    println!("  Runtime:           {:?}", elapsed);
    println!("  Seq/sec:           {:.2}", sequences_run as f64 / elapsed.as_secs_f64().max(0.001));
    println!("  Crashes found:     {}", crashes);
    println!("  State errors:      {}", interesting);
    println!("{}", "═".repeat(60));
}

/// Check for state-related errors (might indicate UAF setup)
fn is_state_error(code: u32) -> bool {
    matches!(code,
        0xC0000008 |  // STATUS_INVALID_HANDLE
        0xC0000022 |  // STATUS_ACCESS_DENIED
        0xC000000E |  // STATUS_NO_SUCH_DEVICE
        0xC0000034 |  // STATUS_OBJECT_NAME_NOT_FOUND
        0xC0000061    // STATUS_PRIVILEGE_NOT_HELD
    )
}

/// Save a crashing sequence
fn save_sequence_crash(output: &PathBuf, sequence: &[(u32, Vec<u8>)], error: u32, pattern: SequencePattern) {
    use std::fs;
    use sha2::{Sha256, Digest};
    
    let _ = fs::create_dir_all(output);
    
    let mut hasher = Sha256::new();
    for (ioctl, data) in sequence {
        hasher.update(&ioctl.to_le_bytes());
        hasher.update(data);
    }
    let hash_bytes = hasher.finalize();
    let hash = format!("{:x}", hash_bytes).chars().take(16).collect::<String>();
    
    // Save sequence as JSON
    let seq_json: Vec<String> = sequence.iter()
        .map(|(ioctl, data)| format!(r#"{{"ioctl": "0x{:08X}", "input": "{}"}}"#, ioctl, hex::encode(data)))
        .collect();
    
    let meta = format!(
        r#"{{
  "type": "sequence_crash",
  "pattern": "{:?}",
  "error": "0x{:08X}",
  "sequence_length": {},
  "sequence": [{}],
  "timestamp": "{}"
}}"#,
        pattern,
        error,
        sequence.len(),
        seq_json.join(",\n    "),
        chrono::Utc::now().to_rfc3339()
    );
    
    let filename = output.join(format!(
        "uaf_seq_{:?}_err_{:08X}_{}.json",
        pattern, error, hash
    ));
    
    let _ = fs::write(&filename, meta);
    println!("{} {}", "[+] Sequence saved:".green(), filename.display());
}

/// SMART fuzzing - learns driver behavior and hunts for UAF/DoubleFree
fn run_smart_fuzzing(driver: &mut DriverIO, ioctls: &[u32], args: &Args) {
    println!("{}", "─".repeat(60));
    println!("    Phase 1: LEARNING - Probing {} IOCTLs to understand behavior", ioctls.len());
    println!("    Phase 2: CLASSIFY - Auto-classify IOCTLs (Allocator/User/Freer)");
    println!("    Phase 3: HUNT - Generate UAF/Double-Free sequences");
    println!("{}", "─".repeat(60));
    
    // Create log directory and files
    let log_dir = args.output.clone();
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir.join("fuzzer_log.txt");
    let device_name = args.device.as_ref().map(|s| s.as_str()).unwrap_or("unknown");
    
    // Initialize PoC generator with real-time logging
    let mut poc_gen = PocGenerator::new(device_name, Some(&log_path));
    
    println!("{} {}", "[*] Logging to:".green(), log_path.display());
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let _ = ctrlc::set_handler(move || {
        if r.swap(false, Ordering::SeqCst) {
            println!("\n{}", "[!] Stopping smart fuzzer...".yellow());
        }
    });
    
    let mut smart = SmartFuzzer::new(ioctls.to_vec());
    let mut output = vec![0u8; 4096];
    let mut iterations = 0u64;
    let mut crashes = 0u64;
    let mut interesting = 0u64;
    
    let start_time = Instant::now();
    let max_iters = args.iterations;
    let mut last_print = Instant::now();
    let mut phase_announced = false;
    
    println!("\n{}", "[*] Phase 1: LEARNING...".cyan().bold());
    
    while running.load(Ordering::SeqCst) {
        if max_iters > 0 && iterations >= max_iters {
            break;
        }
        
        // Check if learning is complete, transition to hunting
        if smart.phase() == FuzzPhase::Learning && smart.learning_complete() {
            println!("\n\n{}", "[*] Learning complete! Analyzing...".green().bold());
            smart.start_hunting();
            phase_announced = false;
            
            // Save emergency dump when transitioning (in case we crash during hunting)
            let dump_path = log_dir.join("pre_hunt_dump.txt");
            let _ = poc_gen.emergency_dump(&dump_path);
        }
        
        // Announce new phase
        if !phase_announced {
            match smart.phase() {
                FuzzPhase::Learning => {
                    // Already announced
                }
                FuzzPhase::UafHunting => {
                    println!("\n{}", "[*] Phase 3: UAF HUNTING - Sending Alloc->Free->Use sequences".magenta().bold());
                }
                FuzzPhase::DoubleFreeHunting => {
                    println!("\n{}", "[*] Phase 3: DOUBLE-FREE HUNTING - Sending Alloc->Free->Free sequences".magenta().bold());
                }
                FuzzPhase::StatefulFuzzing => {
                    println!("\n{}", "[*] Phase 3: STATEFUL FUZZING - Random sequences".yellow().bold());
                }
            }
            phase_announced = true;
        }
        
        // Generate and execute based on phase
        if smart.phase() == FuzzPhase::Learning {
            // Learning: single IOCTLs with varied inputs
            let (ioctl, input) = smart.next_input();
            iterations += 1;
            
            // LOG BEFORE CALL (in case of BSOD!)
            poc_gen.log_before_call(ioctl, &input);
            
            let result = driver.send_ioctl(ioctl, &input, &mut output);
            
            let (success, error_code, bytes_ret) = match result {
                Ok(bytes) => (true, 0u32, bytes),
                Err(code) => {
                    let code32 = code as u32;
                    if is_interesting_error(code32) {
                        interesting += 1;
                    }
                    (false, code32, 0)
                }
            };
            
            // Log result after call
            poc_gen.log_after_call(ioctl, &input, if success { 0 } else { -1 }, error_code);
            smart.record_result(ioctl, &input, &output, bytes_ret, error_code, success);
        } else {
            // Hunting: execute full sequences
            let sequence = smart.generate_full_uaf_sequence();
            
            // Emergency dump before sequence (in case sequence causes BSOD)
            let seq_dump = log_dir.join(format!("seq_{}.txt", iterations));
            let _ = poc_gen.emergency_dump(&seq_dump);
            
            // Generate PoC for this sequence BEFORE executing
            let poc_code = poc_gen.generate_sequence_poc(&sequence, &format!("{:?}", smart.phase()));
            let poc_path = log_dir.join(format!("poc_seq_{}.py", iterations));
            let _ = poc_gen.save_poc(&poc_code, &poc_path);
            
            for (ioctl, input) in &sequence {
                iterations += 1;
                
                // LOG BEFORE CALL!
                poc_gen.log_before_call(*ioctl, input);
                
                let result = driver.send_ioctl(*ioctl, input, &mut output);
                
                let (success, error_code, bytes_ret) = match result {
                    Ok(bytes) => (true, 0u32, bytes),
                    Err(code) => {
                        let code32 = code as u32;
                        
                        // Check for crash indicators
                        if is_interesting_error(code32) || code32 == 0xC0000005 {
                            crashes += 1;
                            println!("\n{}", "!".repeat(60).red());
                            println!("{} IOCTL 0x{:08X} Error: 0x{:08X}",
                                "[!!!] POTENTIAL UAF/CRASH!".red().bold(),
                                ioctl,
                                code32
                            );
                            println!("      Phase: {:?}", smart.phase());
                            println!("{}", "!".repeat(60).red());
                            
                            // Save crash data + PoC
                            let crash_dir = &args.output;
                            let _ = std::fs::create_dir_all(crash_dir);
                            
                            // Save raw input
                            let filename = crash_dir.join(format!(
                                "crash_0x{:08X}_{}.bin",
                                ioctl,
                                chrono::Utc::now().format("%Y%m%d_%H%M%S")
                            ));
                            let _ = std::fs::write(&filename, input);
                            
                            // Generate and save Python PoC!
                            let poc = poc_gen.generate_single_poc(*ioctl, input);
                            let poc_file = crash_dir.join(format!(
                                "poc_crash_0x{:08X}_{}.py",
                                ioctl,
                                chrono::Utc::now().format("%Y%m%d_%H%M%S")
                            ));
                            let _ = poc_gen.save_poc(&poc, &poc_file);
                            println!("{} {}", "[+] PoC saved:".green(), poc_file.display());
                            
                            // Emergency dump
                            let dump = crash_dir.join("last_crash_dump.txt");
                            let _ = poc_gen.emergency_dump(&dump);
                        }
                        
                        (false, code32, 0)
                    }
                };
                
                // Log after call
                poc_gen.log_after_call(*ioctl, input, if success { 0 } else { -1 }, error_code);
                smart.record_result(*ioctl, input, &output, bytes_ret, error_code, success);
            }
        }
        
        // Progress output
        if last_print.elapsed().as_millis() >= 500 {
            let elapsed = start_time.elapsed().as_secs_f64().max(0.001);
            let phase_str = match smart.phase() {
                FuzzPhase::Learning => "LEARN",
                FuzzPhase::UafHunting => "UAF",
                FuzzPhase::DoubleFreeHunting => "DFREE",
                FuzzPhase::StatefulFuzzing => "STATE",
            };
            print!("\r{} [{}] iter: {} | exec/s: {:.1} | crashes: {} | interesting: {}      ",
                "[*]".cyan(),
                phase_str.magenta(),
                iterations,
                iterations as f64 / elapsed,
                crashes,
                interesting
            );
            let _ = std::io::stdout().flush();
            last_print = Instant::now();
        }
    }
    
    // Final analysis
    smart.learner.analyze();
    
    let elapsed = start_time.elapsed();
    
    println!("\n\n{}", "═".repeat(60));
    println!("{}", "           SMART FUZZING COMPLETE".green().bold());
    println!("{}", "═".repeat(60));
    println!("  Iterations:        {}", iterations);
    println!("  Runtime:           {:?}", elapsed);
    println!("  Exec/sec:          {:.2}", iterations as f64 / elapsed.as_secs_f64().max(0.001));
    println!("  Crashes found:     {}", crashes);
    println!("  Interesting:       {}", interesting);
    println!("{}", "═".repeat(60));
    
    // Print learned knowledge
    smart.learner.print_knowledge();
}

/// HEVD-specific UAF fuzzing
fn run_hevd_uaf_fuzzing(driver: &mut DriverIO, args: &Args) {
    use stateful::HevdUafFuzzer;
    
    println!("{}", "[*] HEVD Use-After-Free Exploit Mode".magenta().bold());
    println!("    Target: HackSys Extreme Vulnerable Driver");
    println!("    IOCTLs: 0x22201F (Alloc), 0x222027 (Free), 0x222023 (Use)");
    println!("{}", "─".repeat(60));
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let _ = ctrlc::set_handler(move || {
        if r.swap(false, Ordering::SeqCst) {
            println!("\n{}", "[!] Stopping HEVD UAF fuzzer...".yellow());
        }
    });
    
    let mut fuzzer = HevdUafFuzzer::new();
    let mut iterations = 0u64;
    let mut sequences = 0u64;
    let mut crashes = 0u64;
    let mut output = vec![0u8; 4096];
    
    let start_time = Instant::now();
    let max_iters = args.iterations;
    let mut last_print = Instant::now();
    
    println!("{}", "[*] Starting UAF sequence injection...".cyan());
    println!("    Will trigger: Allocate -> Free -> Use (UAF!)");
    println!("{}", "─".repeat(60));
    
    while running.load(Ordering::SeqCst) {
        if max_iters > 0 && sequences >= max_iters {
            break;
        }
        
        // Generate UAF sequence variant
        let sequence = fuzzer.generate_random_variant();
        sequences += 1;
        
        // Execute the sequence
        let mut seq_crash = false;
        for (ioctl, input) in &sequence {
            iterations += 1;
            
            let result = driver.send_ioctl(*ioctl, input, &mut output);
            
            match result {
                Ok(_) => {
                    // Success - continue sequence
                }
                Err(code) => {
                    let code32 = code as u32;
                    // Check for interesting errors
                    if is_interesting_error(code32) || code32 == 0xC0000005 {
                        crashes += 1;
                        seq_crash = true;
                        println!("\n{}", "!".repeat(60).red());
                        println!("{} IOCTL 0x{:08X}", 
                            "[!!!] UAF CRASH DETECTED!".red().bold(),
                            ioctl);
                        println!("      Error code: 0x{:08X}", code32);
                        println!("      Input size: {} bytes", input.len());
                        println!("      Sequence #: {}", sequences);
                        println!("{}", "!".repeat(60).red());
                        
                        // Save crash
                        let crash_dir = &args.output;
                        let _ = std::fs::create_dir_all(crash_dir);
                        let filename = crash_dir.join(format!(
                            "hevd_uaf_crash_{}_0x{:08X}.bin",
                            chrono::Utc::now().format("%Y%m%d_%H%M%S"),
                            ioctl
                        ));
                        let _ = std::fs::write(&filename, input);
                        println!("{} {}", "[+] Crash saved:".green(), filename.display());
                    }
                }
            }
            
            if seq_crash {
                break;
            }
        }
        
        // Progress output
        if last_print.elapsed().as_millis() >= 500 {
            let elapsed = start_time.elapsed().as_secs_f64().max(0.001);
            print!("\r{} seqs: {} | ioctls: {} | crashes: {} | seq/s: {:.1}      ",
                "[*]".cyan(),
                sequences,
                iterations,
                crashes,
                sequences as f64 / elapsed
            );
            use std::io::Write;
            let _ = std::io::stdout().flush();
            last_print = Instant::now();
        }
    }
    
    let elapsed = start_time.elapsed();
    
    println!("\n\n{}", "═".repeat(60));
    println!("{}", "           HEVD UAF FUZZING COMPLETE".green().bold());
    println!("{}", "═".repeat(60));
    println!("  Sequences:         {}", sequences);
    println!("  Total IOCTLs:      {}", iterations);
    println!("  Runtime:           {:?}", elapsed);
    println!("  Seq/sec:           {:.2}", sequences as f64 / elapsed.as_secs_f64().max(0.001));
    println!("  {} {}", "UAF Crashes:".red().bold(), crashes);
    println!("{}", "═".repeat(60));
}

/// Race condition fuzzing with multiple threads
fn run_race_fuzzing(device_path: &str, ioctls: &[u32], thread_count: usize, args: &Args) {
    use std::thread;
    use race::SpinBarrier;
    use rand::Rng;
    
    println!("{} {} threads hitting {} IOCTLs", 
        "[*] Race fuzzing:".magenta().bold(), thread_count, ioctls.len());
    println!("{}", "─".repeat(60));
    
    let running = Arc::new(AtomicBool::new(true));
    let crashes = Arc::new(AtomicU64::new(0));
    let iterations = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(SpinBarrier::new(thread_count as u64));
    
    // Shared handle for racing
    let shared_handle = Arc::new(AtomicU64::new(0x41414141));
    
    let r = running.clone();
    let _ = ctrlc::set_handler(move || {
        if r.swap(false, Ordering::SeqCst) {
            println!("\n{}", "[!] Stopping race fuzzer...".yellow());
        }
    });
    
    let start_time = Instant::now();
    let device = device_path.to_string();
    let ioctls = ioctls.to_vec();
    let max_iters = args.iterations;
    
    let mut handles = Vec::new();
    
    for thread_id in 0..thread_count {
        let running = running.clone();
        let crashes = crashes.clone();
        let iterations = iterations.clone();
        let barrier = barrier.clone();
        let shared_handle = shared_handle.clone();
        let device = device.clone();
        let ioctls = ioctls.clone();
        
        let handle = thread::spawn(move || {
            let mut driver = match DriverIO::new(&device) {
                Ok(d) => d,
                Err(_) => return,
            };
            
            let mut output = vec![0u8; 4096];
            let mut rng = rand::thread_rng();
            
            while running.load(Ordering::SeqCst) {
                let current_iter = iterations.fetch_add(1, Ordering::Relaxed);
                if max_iters > 0 && current_iter >= max_iters {
                    break;
                }
                
                // Pick an IOCTL
                let ioctl = ioctls[rng.gen_range(0..ioctls.len())];
                
                // Generate input with shared handle (all threads use same handle)
                let handle_val = shared_handle.load(Ordering::Relaxed) as u32;
                let input = race::generate_race_input(handle_val, thread_id);
                
                // Synchronize threads for maximum race likelihood
                barrier.wait();
                
                // Send IOCTL (racing with other threads!)
                let result = driver.send_ioctl(ioctl, &input, &mut output);
                
                if let Err(code) = result {
                    if is_interesting_error(code as u32) {
                        crashes.fetch_add(1, Ordering::Relaxed);
                        println!("{} Thread {} IOCTL 0x{:08X} Error: 0x{:08X}",
                            "[!] RACE CRASH!".red().bold(),
                            thread_id,
                            ioctl,
                            code as u32
                        );
                    }
                }
                
                barrier.reset();
                
                // Occasionally change the shared handle
                if rng.gen_bool(0.01) {
                    shared_handle.store(rng.gen::<u64>(), Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for threads
    for handle in handles {
        let _ = handle.join();
    }
    
    let elapsed = start_time.elapsed();
    let total_iters = iterations.load(Ordering::Relaxed);
    
    println!("\n\n{}", "═".repeat(60));
    println!("{}", "           RACE FUZZING SESSION COMPLETE".green().bold());
    println!("{}", "═".repeat(60));
    println!("  Total calls:       {}", total_iters);
    println!("  Threads:           {}", thread_count);
    println!("  Runtime:           {:?}", elapsed);
    println!("  Calls/sec:         {:.2}", total_iters as f64 / elapsed.as_secs_f64().max(0.001));
    println!("  Race crashes:      {}", crashes.load(Ordering::Relaxed));
    println!("{}", "═".repeat(60));
}

/// CLFS file-based fuzzer - targets clfs.sys like CVE-2025-29824
fn run_clfs_fuzzing(args: &Args) {
    use clfs_fuzzer::{ClfsFuzzer, ClfsUafHunter};
    
    // Create output directory
    let output_dir = args.output.to_string_lossy().to_string();
    std::fs::create_dir_all(&output_dir).ok();
    
    // Dump kernel info first (silent)
    if let Ok(info) = ExploitInfo::gather() {
        let info_path = args.output.join("kernel_addresses.txt");
        let _ = info.save_to_file(&info_path);
    }
    
    let iterations = if args.iterations == 0 { u64::MAX } else { args.iterations };
    
    // Phase 1: Standard mutations
    let mut fuzzer = ClfsFuzzer::new(&output_dir);
    fuzzer.run(iterations / 2);
    
    // Phase 2: UAF hunting
    let mut uaf_hunter = ClfsUafHunter::new(&output_dir);
    uaf_hunter.run_uaf_hunt(iterations / 2);
}

/// Font fuzzer - targets win32k.sys / atmfd.sys for RCE
fn run_font_fuzzing(args: &Args) {
    use font_fuzzer::{FontFuzzer, GeneticFontFuzzer};
    
    // Create output directory
    let output_dir = args.output.to_string_lossy().to_string();
    std::fs::create_dir_all(&output_dir).ok();
    
    // Dump kernel info first (silent)
    if let Ok(info) = ExploitInfo::gather() {
        let info_path = args.output.join("kernel_addresses.txt");
        let _ = info.save_to_file(&info_path);
    }
    
    // -i 0 means UNLIMITED (run forever until BSOD)
    let unlimited = args.iterations == 0;
    let iterations = if unlimited { u64::MAX } else { args.iterations };
    
    let mut fuzzer = FontFuzzer::new(&output_dir);
    fuzzer.run(iterations);
}

/// GDI Race Condition Fuzzer - targets win32k.sys UAF bugs
fn run_gdi_race_fuzzing(args: &Args) {
    use gdi_race_fuzzer::GdiRaceFuzzer;
    
    // Create output directory
    let output_dir = args.output.to_string_lossy().to_string();
    std::fs::create_dir_all(&output_dir).ok();
    
    // -i 0 means UNLIMITED (run forever until BSOD)
    let iterations = if args.iterations == 0 { u64::MAX } else { args.iterations };
    
    let fuzzer = GdiRaceFuzzer::new(&output_dir);
    fuzzer.run(iterations);
}

/// Win32k Syscall Fuzzer - targets NtUser*/NtGdi* for $50K-$200K bounties!
fn run_win32k_fuzzing(args: &Args) {
    use win32k_fuzzer::Win32kFuzzer;
    
    // Create output directory
    let output_dir = args.output.to_string_lossy().to_string();
    std::fs::create_dir_all(&output_dir).ok();
    
    // Dump kernel info silently
    if let Ok(info) = ExploitInfo::gather() {
        let info_path = args.output.join("kernel_addresses.txt");
        let _ = info.save_to_file(&info_path);
    }
    
    // -i 0 means UNLIMITED
    let iterations = if args.iterations == 0 { u64::MAX } else { args.iterations };
    
    let fuzzer = Win32kFuzzer::new(&output_dir);
    fuzzer.run(iterations);
}

/// Dynamically enumerate ALL device objects accessible from userland
fn enumerate_device_objects() -> Vec<(String, String)> {
    use std::process::Command;
    
    let mut devices: Vec<(String, String)> = Vec::new();
    
    // Method 1: Query all driver services and derive device paths
    let output = Command::new("powershell")
        .args(&["-Command", r#"
            Get-WmiObject Win32_SystemDriver | Where-Object { $_.State -eq 'Running' } | ForEach-Object {
                $name = $_.Name
                # Common device path patterns
                Write-Output "\\.\$name|$($_.DisplayName)"
                Write-Output "\\.\GLOBALROOT\Device\$name|$($_.DisplayName)"
            }
        "#])
        .output();
    
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 2 {
                devices.push((parts[0].to_string(), parts[1].to_string()));
            }
        }
    }
    
    // Method 2: Also try common device naming patterns
    let common_prefixes = vec![
        (r"\\.\", "Direct"),
        (r"\\.\GLOBALROOT\Device\", "GlobalRoot"),
    ];
    
    // Get driver names from registry
    let reg_output = Command::new("powershell")
        .args(&["-Command", r#"
            Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | ForEach-Object {
                $svc = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($svc.Type -eq 1 -or $svc.Type -eq 2) {
                    Write-Output $_.PSChildName
                }
            }
        "#])
        .output();
    
    if let Ok(out) = reg_output {
        let text = String::from_utf8_lossy(&out.stdout);
        for name in text.lines() {
            let name = name.trim();
            if !name.is_empty() {
                for (prefix, _) in &common_prefixes {
                    let path = format!("{}{}", prefix, name);
                    if !devices.iter().any(|(p, _)| p == &path) {
                        devices.push((path, name.to_string()));
                    }
                }
            }
        }
    }
    
    devices
}

/// Test if a device is accessible from current user (non-admin check)
fn test_device_access(device_path: &str) -> Option<bool> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
    use windows::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE};
    
    let wide: Vec<u16> = device_path.encode_utf16().chain(std::iter::once(0)).collect();
    
    unsafe {
        // Try with READ|WRITE first
        let handle = CreateFileW(
            PCWSTR(wide.as_ptr()),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        );
        
        if let Ok(h) = handle {
            if !h.is_invalid() {
                CloseHandle(h).ok();
                return Some(true); // Full access
            }
        }
        
        // Try read-only
        let handle = CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        );
        
        if let Ok(h) = handle {
            if !h.is_invalid() {
                CloseHandle(h).ok();
                return Some(false); // Read-only access
            }
        }
    }
    
    None // No access
}

/// Comprehensive driver scan - probes ALL Windows drivers for IOCTLs
fn run_comprehensive_scan(args: &Args) {
    use std::collections::HashMap;
    
    println!("\n{}", "╔══════════════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║         COMPREHENSIVE WINDOWS DRIVER SCANNER                         ║".cyan());
    println!("{}", "║         Finding ALL attack surfaces for bug hunting                  ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════════════╝".cyan());
    
    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 1: Dynamic enumeration - find ALL device objects on this system
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n{}", "[*] Phase 1: Discovering ALL device objects on this system...".yellow());
    
    let dynamic_devices = enumerate_device_objects();
    println!("    Found {} potential device paths from driver enumeration", dynamic_devices.len());
    
    // Test which devices are accessible from userland
    println!("{}", "[*] Testing device accessibility (userland vs admin)...".yellow());
    
    let mut userland_accessible: Vec<(String, String, bool)> = Vec::new(); // (path, name, full_access)
    let mut admin_only: Vec<(String, String)> = Vec::new();
    
    for (path, name) in &dynamic_devices {
        match test_device_access(path) {
            Some(full) => {
                userland_accessible.push((path.clone(), name.clone(), full));
            }
            None => {
                admin_only.push((path.clone(), name.clone()));
            }
        }
    }
    
    // Print userland accessible devices (HIGH VALUE!)
    if !userland_accessible.is_empty() {
        println!("\n{}", "┌─ 🎯 USERLAND ACCESSIBLE DEVICES (HIGH VALUE FOR BOUNTY!) ───────────┐".green().bold());
        for (path, name, full) in &userland_accessible {
            let access = if *full { "R/W" } else { "R/O" };
            println!("│  [{}] {} - {}", access.yellow(), path, name);
        }
        println!("{}", "└─────────────────────────────────────────────────────────────────────┘".green());
    }
    
    // ═══════════════════════════════════════════════════════════════════════
    // PHASE 2: Known high-value targets with specific IOCTL ranges
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n{}", "[*] Phase 2: Scanning known high-value targets for IOCTLs...".yellow());
    
    // All security-critical drivers to scan
    let targets: Vec<(&str, &str, Vec<(u32, u32)>)> = vec![
        // (device_path, description, [(ioctl_start, ioctl_end), ...])
        
        // === CLFS - CVE-2025-29824 ===
        (r"\\.\Clfs", "CLFS (CVE-2025-29824)", vec![
            (0x00500000, 0x005000FF), // CLFS IOCTLs
        ]),
        
        // === Security/Crypto - HIGH VALUE ===
        (r"\\.\TPM", "TPM (Crypto)", vec![
            (0x00220000, 0x002200FF),
            (0x00228000, 0x002280FF),
            (0x22C000, 0x22C0FF),
        ]),
        (r"\\.\PEAUTH", "PEAUTH (DRM)", vec![
            (0x00220000, 0x002200FF),
            (0x0022E000, 0x0022E0FF),
        ]),
        (r"\\.\WindowsTrustedRT", "TrustedRT", vec![
            (0x00220000, 0x002200FF),
        ]),
        (r"\\.\CNG", "CNG (Crypto)", vec![
            (0x00390000, 0x003900FF),
        ]),
        (r"\\.\KSecDD", "KSecDD", vec![
            (0x00390000, 0x003900FF),
        ]),
        
        // === Network Drivers ===
        (r"\\.\GLOBALROOT\\Device\\Afd", "AFD (Winsock)", vec![
            (0x00012000, 0x000120FF), // AFD IOCTLs
            (0x00012100, 0x000121FF),
        ]),
        (r"\\.\Nsi", "NSI (Network)", vec![
            (0x0012C000, 0x0012C0FF),
        ]),
        (r"\\.\Tcp", "TCP Driver", vec![
            (0x00120000, 0x001200FF),
        ]),
        (r"\\.\GLOBALROOT\\Device\\Nsi", "NSI (alt)", vec![
            (0x0012C000, 0x0012C0FF),
        ]),
        
        // === Storage ===
        (r"\\.\spaceport", "Storage Spaces", vec![
            (0x002D0000, 0x002D00FF),
            (0x002D4000, 0x002D40FF),
        ]),
        (r"\\.\vdrvroot", "Virtual Disk", vec![
            (0x00220000, 0x002200FF),
        ]),
        (r"\\.\PartMgr", "Partition Mgr", vec![
            (0x00700000, 0x007000FF),
        ]),
        (r"\\.\MountPointManager", "MountPoint Mgr", vec![
            (0x006D0000, 0x006D00FF),
        ]),
        
        // === App Compat ===
        (r"\\.\ahcache", "App Compat Cache", vec![
            (0x00012000, 0x000120FF),  // Main ahcache IOCTLs (includes 0x12017!)
            (0x00224000, 0x002240FF),
            (0x80002000, 0x800020FF),
        ]),
        
        // === Kernel Streaming ===
        (r"\\.\Ks", "Kernel Streaming", vec![
            (0x002F0000, 0x002F00FF),
        ]),
        
        // === HTTP.sys ===
        (r"\\.\HTTP", "HTTP.sys", vec![
            (0x00228000, 0x002280FF),
        ]),
        
        // === Filter Manager ===
        (r"\\.\FltMgr", "Filter Manager", vec![
            (0x009C0000, 0x009C00FF),
        ]),
        
        // === Graphics ===
        (r"\\.\DxgKrnl", "DirectX Kernel", vec![
            (0x00230000, 0x002300FF),
        ]),
        
        // === Windows Defender / Security ===
        (r"\\.\WdFilter", "Defender Filter", vec![
            (0x00220000, 0x002200FF),
            (0x0022C000, 0x0022C0FF),
        ]),
        (r"\\.\WdNisDrv", "Defender Network", vec![
            (0x00220000, 0x002200FF),
        ]),
        (r"\\.\MpKsl", "Defender Kernel", vec![
            (0x00220000, 0x002200FF),
        ]),
        (r"\\.\MpFilter", "Defender MpFilter", vec![
            (0x00220000, 0x002200FF),
        ]),
        
        // === Hyper-V (if enabled) ===
        (r"\\.\VMBus", "Hyper-V VMBus", vec![
            (0x003E0000, 0x003E00FF),
        ]),
        (r"\\.\VidExo", "Hyper-V VID", vec![
            (0x00220000, 0x002200FF),
        ]),
        
        // === WSL2 (if enabled) ===
        (r"\\.\lxss", "WSL2 Linux", vec![
            (0x00220000, 0x002200FF),
        ]),
        (r"\\.\P9RdrDevice", "WSL2 P9", vec![
            (0x00220000, 0x002200FF),
        ]),
        
        // === Sandbox / Container ===
        (r"\\.\BindFlt", "Container BindFlt", vec![
            (0x009C0000, 0x009C00FF),
        ]),
        (r"\\.\wcifs", "Container WCIFS", vec![
            (0x009C0000, 0x009C00FF),
        ]),
    ];
    
    let mut results: HashMap<String, Vec<u32>> = HashMap::new();
    let mut total_ioctls = 0;
    
    println!("\n{}", "[*] Scanning each driver for accessible IOCTLs...".yellow());
    println!("{}", "    (This may take a few minutes)\n".yellow());
    
    for (device, desc, ioctl_ranges) in &targets {
        print!("  [{:20}] {:30} ", desc, device);
        std::io::stdout().flush().ok();
        
        match DriverIO::new(device) {
            Ok(mut driver) => {
                let mut found_ioctls: Vec<u32> = Vec::new();
                
                for (start, end) in ioctl_ranges {
                    for ioctl in (*start..=*end).step_by(4) {
                        let mut output = vec![0u8; 256];
                        let input = vec![0u8; 64];
                        
                        match driver.send_ioctl(ioctl, &input, &mut output) {
                            Ok(_) => {
                                found_ioctls.push(ioctl);
                            }
                            Err(code) => {
                                // These codes mean the IOCTL exists but needs different input
                                let code_u = code as u32;
                                if matches!(code_u,
                                    0x80070057 |  // INVALID_PARAMETER  
                                    0x8007007A |  // INSUFFICIENT_BUFFER
                                    0x80070018 |  // BAD_LENGTH
                                    0x8007000D |  // INVALID_DATA
                                    0x800703E3 |  // IO_INCOMPLETE
                                    0x80070016 |  // NOT_READY
                                    87 | 122 | 24 | 13  // Same as above, raw
                                ) {
                                    found_ioctls.push(ioctl);
                                }
                            }
                        }
                    }
                }
                
                if found_ioctls.is_empty() {
                    println!("{}", "0 IOCTLs".red());
                } else {
                    println!("{}", format!("{} IOCTLs ✓", found_ioctls.len()).green().bold());
                    total_ioctls += found_ioctls.len();
                    results.insert(device.to_string(), found_ioctls);
                }
            }
            Err(e) => {
                let code = e.code().0 as u32;
                if code == 0x80070005 {
                    println!("{}", "ACCESS_DENIED".red());
                } else if code == 0x80070002 {
                    println!("{}", "NOT_FOUND".dimmed());
                } else {
                    println!("{}", format!("ERROR 0x{:08X}", code).yellow());
                }
            }
        }
    }
    
    // NOTE: Phase 3 (probing all userland devices) removed - many drivers block indefinitely
    // The userland accessible list above is still shown for reference
    
    // Summary
    println!("\n{}", "═".repeat(70).green());
    println!("{}", "                    SCAN COMPLETE - RESULTS".green().bold());
    println!("{}", "═".repeat(70).green());
    
    // Show userland accessible count
    println!("\n  {} devices accessible from USERLAND (no admin!) 🎯", userland_accessible.len());
    println!("  {} drivers with IOCTLs found", results.len());
    println!("  {} total IOCTLs to fuzz\n", total_ioctls);

    if !results.is_empty() {
        println!("{}", "┌─ FUZZABLE TARGETS ──────────────────────────────────────────────────┐".green());
        for (device, ioctls) in &results {
            // Mark if userland accessible - normalize paths for comparison
            let device_normalized = device.to_lowercase().replace("\\\\", "\\");
            let is_userland = userland_accessible.iter().any(|(p, _, _)| {
                let p_normalized = p.to_lowercase().replace("\\\\", "\\");
                p_normalized == device_normalized || 
                p_normalized.contains(&device_normalized) ||
                device_normalized.contains(&p_normalized)
            });
            let marker = if is_userland { "🎯 USERLAND" } else { "   ADMIN" };
            
            println!("│");
            println!("│  [{}] {} - {} IOCTLs", marker, device.cyan(), ioctls.len());
            println!("│  Sample IOCTLs: {:?}", &ioctls[..std::cmp::min(5, ioctls.len())]);
            println!("│  Command: ladybug.exe --device \"{}\" --ultimate", device);
        }
        println!("│");
        println!("{}", "└─────────────────────────────────────────────────────────────────────┘".green());
        
        // Save results to output directory (-o flag)
        std::fs::create_dir_all(&args.output).ok();
        let output_path = args.output.join("scan_results.txt");
        
        let mut report = String::new();
        report.push_str("=== WINDOWS DRIVER SCAN RESULTS ===\n\n");
        
        report.push_str(&format!("USERLAND ACCESSIBLE DEVICES: {}\n", userland_accessible.len()));
        for (path, name, full) in &userland_accessible {
            let access = if *full { "R/W" } else { "R/O" };
            report.push_str(&format!("  [{}] {} - {}\n", access, path, name));
        }
        report.push_str("\n");
        
        report.push_str("FUZZABLE DRIVERS WITH IOCTLs:\n\n");
        for (device, ioctls) in &results {
            let device_normalized = device.to_lowercase().replace("\\\\", "\\");
            let is_userland = userland_accessible.iter().any(|(p, _, _)| {
                let p_normalized = p.to_lowercase().replace("\\\\", "\\");
                p_normalized == device_normalized || 
                p_normalized.contains(&device_normalized) ||
                device_normalized.contains(&p_normalized)
            });
            report.push_str(&format!("Driver: {} {}\n", device, if is_userland { "(USERLAND!)" } else { "(admin)" }));
            report.push_str(&format!("IOCTLs: {}\n", ioctls.len()));
            for ioctl in ioctls {
                report.push_str(&format!("  0x{:08X}\n", ioctl));
            }
            report.push_str("\n");
        }
        
        if std::fs::write(&output_path, &report).is_ok() {
            println!("\n{} Saved to: {}", "[+]".green(), output_path.display());
        }
    }
    
    // Recommendations
    println!("\n{}", "═".repeat(70).yellow());
    println!("{}", "                    RECOMMENDED NEXT STEPS".yellow().bold());
    println!("{}", "═".repeat(70).yellow());
    
    println!("
  1. {} - Use --clfs mode (already supported!)
     ladybug.exe --clfs -o crashes

  2. For each driver with IOCTLs:
     ladybug.exe --device \"DEVICE\" --auto -o crashes
  
  3. For deep fuzzing with RL:
     ladybug.exe --device \"DEVICE\" --ultimate -o crashes
  
  4. For TCP mode (VM fuzzing):
     Host:  ladybug.exe --tcp 192.168.1.243:9999 --device \"DEVICE\"
     VM:    executor.exe --listen 9999
  
  5. Check for specific CVE patterns in your Windows build!
",
        "CLFS (CVE-2025-29824 style)".red().bold(),
    );
}

/// Dump kernel addresses and exploit information
fn dump_exploit_info(args: &Args) {
    println!();
    println!("{}", "=".repeat(70).cyan());
    println!("{}  KERNEL EXPLOIT INFORMATION GATHERING", "".cyan());
    println!("{}  (For building your shellcode)", "".cyan());
    println!("{}", "=".repeat(70).cyan());
    
    match ExploitInfo::gather() {
        Ok(info) => {
            info.print();
            
            // Save to output directory
            let output_path = args.output.join("exploit_info.txt");
            std::fs::create_dir_all(&args.output).ok();
            
            match info.save_to_file(&output_path) {
                Ok(_) => {
                    println!("\n{} Saved to: {}", "[+]".green(), output_path.display());
                }
                Err(e) => {
                    println!("{} Failed to save: {}", "[!]".red(), e);
                }
            }
            
            // Print important notes
            println!("\n{}", "=".repeat(70).yellow());
            println!("{}", "  IMPORTANT NOTES FOR EXPLOITATION:".yellow().bold());
            println!("{}", "=".repeat(70).yellow());
            println!("
  1. {} - Run --info again after each reboot!
     Kernel addresses change every boot due to KASLR.
  
  2. {} - Same for each Windows build
     Token, PID, Links offsets don't change after reboot.
  
  3. {} - For UAF exploitation you need:
     - Allocate vulnerable object
     - Free object (dangling pointer)
     - Spray pool with fake object (points to shellcode)
     - Trigger Use -> shellcode executes!
  
  4. {} - The shellcode:
     - Finds current EPROCESS
     - Walks process list to find SYSTEM (PID 4)
     - Copies SYSTEM token to your process
     - Spawn cmd.exe = SYSTEM shell!
  
  5. {} - Copy addresses to your exploit:
     Kernel Base:   0x{:016X}
     Token Offset:  0x{:X}
     PID Offset:    0x{:X}
     Links Offset:  0x{:X}
",
                "ADDRESSES CHANGE!".red().bold(),
                "OFFSETS ARE FIXED".green().bold(),
                "UAF EXPLOIT FLOW".cyan().bold(),
                "TOKEN STEALING".magenta().bold(),
                "YOUR VALUES".white().bold(),
                info.kernel_base,
                info.eprocess_token_offset,
                info.eprocess_pid_offset,
                info.eprocess_links_offset,
            );
            
            // Generate shellcode C array
            let shellcode = exploit::generate_shellcode(
                info.eprocess_token_offset,
                info.eprocess_pid_offset,
                info.eprocess_links_offset,
            );
            
            println!("{}", "[*] TOKEN STEALING SHELLCODE (copy to your exploit):".cyan().bold());
            println!();
            println!("// C/Rust array:");
            print!("unsigned char shellcode[] = {{ ");
            for (i, b) in shellcode.iter().enumerate() {
                print!("0x{:02X}", b);
                if i < shellcode.len() - 1 {
                    print!(", ");
                }
                if (i + 1) % 12 == 0 {
                    print!("\n    ");
                }
            }
            println!(" }};");
            println!();
            
            println!("// Python bytes:");
            print!("shellcode = b\"");
            for b in &shellcode {
                print!("\\x{:02X}", b);
            }
            println!("\"");
            println!();
        }
        Err(e) => {
            println!("{} Failed to gather exploit info: {}", "[!]".red(), e);
            println!("\nMake sure you're running as Administrator!");
        }
    }
}

/// RL (Reinforcement Learning) fuzzing mode
fn run_rl_fuzzing(driver: &mut DriverIO, ioctls: &[u32], args: &Args) {
    println!("\n{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║     REINFORCEMENT LEARNING FUZZER                            ║".cyan());
    println!("{}", "║     Agent learns optimal fuzzing strategies over time        ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    
    println!("\n[*] Configuration:");
    println!("    IOCTLs:          {}", ioctls.len());
    println!("    Learning Rate:   0.1 (α)");
    println!("    Discount Factor: 0.95 (γ)");
    println!("    Initial Explore: 100% (ε)");
    println!("    Explore Decay:   0.9995 per episode");
    
    // Setup signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        if r.swap(false, Ordering::SeqCst) {
            println!("\n{}", "[!] Stopping RL fuzzer...".yellow());
        }
    }).expect("Error setting Ctrl-C handler");
    
    let mut rl = RLFuzzer::new(ioctls.to_vec());
    let device_str = args.device.clone().unwrap_or_default();
    let poc_gen = PocGenerator::new(&device_str, None);
    
    let start_time = Instant::now();
    let mut last_print = Instant::now();
    let mut output_buffer = vec![0u8; args.max_size];
    
    // Create output directory
    std::fs::create_dir_all(&args.output).ok();
    
    println!("\n{}", "[*] Starting RL training loop...".green().bold());
    println!("    Press Ctrl+C to stop and see learned knowledge\n");
    
    while running.load(Ordering::SeqCst) {
        // Optional iteration limit
        if args.iterations > 0 && rl.get_episode() >= args.iterations {
            break;
        }
        
        // Choose action using epsilon-greedy policy
        let action = rl.choose_action();
        let (ioctl, input) = rl.action_to_input(&action);
        
        // Execute the action
        let result = driver.send_ioctl(
            ioctl,
            &input,
            &mut output_buffer,
        );
        
        let (success, error_code, bytes_ret) = match result {
            Ok(bytes) => (true, 0u32, bytes),
            Err(code) => (false, code as u32, 0),
        };
        
        // Check for crash (would need external detection, but we can check for timeout)
        let crashed = false; // Would need watchdog thread for real crash detection
        
        // Process result and update Q-table
        let reward = rl.process_result(
            action,
            ioctl,
            error_code,
            success,
            &output_buffer,
            bytes_ret,
            crashed,
        );
        
        // Print status periodically
        if last_print.elapsed().as_secs() >= 2 {
            let elapsed = start_time.elapsed();
            let eps_per_sec = rl.get_episode() as f64 / elapsed.as_secs_f64();
            let stats = rl.get_stats();
            
            print!("\r[{}] Episode {} | ε={:.3} | Reward={:.0} | Q-table={} | ",
                   format!("{:02}:{:02}:{:02}", 
                           elapsed.as_secs() / 3600,
                           (elapsed.as_secs() % 3600) / 60,
                           elapsed.as_secs() % 60).cyan(),
                   rl.get_episode(),
                   rl.get_epsilon(),
                   rl.get_total_reward(),
                   rl.get_q_table_size());
            
            print!("Crashes={} | NewErr={} | {:.0} eps/s    ",
                   stats.crashes,
                   stats.new_errors,
                   eps_per_sec);
            
            let _ = std::io::stdout().flush();
            last_print = Instant::now();
        }
        
        // Only log REALLY interesting rewards (crashes, not every new error)
        // NewErrorCode spam is annoying - these happen constantly at start
        if reward.value >= 100.0 {
            println!("\n{} Episode {} - {:?}: IOCTL 0x{:08X} | Reward: {:.0}",
                     "[!]".yellow().bold(),
                     rl.get_episode(),
                     reward.reason,
                     ioctl,
                     reward.value);
            
            // Save interesting input
            let filename = format!("rl_interesting_{}_0x{:08X}.bin", 
                                   rl.get_episode(), ioctl);
            let filepath = args.output.join(&filename);
            if let Ok(mut f) = std::fs::File::create(&filepath) {
                use std::io::Write;
                let _ = f.write_all(&input);
                println!("    Saved: {}", filepath.display());
            }
        }
        
        // Save crash if detected
        if crashed {
            println!("\n{}", "╔═══════════════════════════════════════╗".red().bold());
            println!("{}", "║           💥 CRASH DETECTED! 💥         ║".red().bold());
            println!("{}", "╚═══════════════════════════════════════╝".red().bold());
            
            let filename = format!("rl_crash_{}_0x{:08X}.bin", rl.get_episode(), ioctl);
            let filepath = args.output.join(&filename);
            if let Ok(mut f) = std::fs::File::create(&filepath) {
                use std::io::Write;
                let _ = f.write_all(&input);
                println!("[+] Crash input saved: {}", filepath.display());
            }
            
            // Generate PoC
            let poc = poc_gen.generate_single_poc(ioctl, &input);
            let poc_path = args.output.join(format!("rl_crash_{}.py", rl.get_episode()));
            if let Ok(mut f) = std::fs::File::create(&poc_path) {
                use std::io::Write;
                let _ = f.write_all(poc.as_bytes());
            }
        }
    }
    
    println!("\n");
    
    // Print learned knowledge
    rl.print_knowledge();
    
    // Save Q-table
    let qtable_path = args.output.join("rl_qtable.txt");
    if let Ok(_) = rl.save(&qtable_path.to_string_lossy()) {
        println!("\n{} Q-table saved to: {}", "[+]".green(), qtable_path.display());
    }
    
    // Print recommendations
    println!("\n{}", "[*] Recommendations based on learning:".cyan().bold());
    let top = rl.get_top_actions(5);
    if !top.is_empty() {
        println!("    Focus fuzzing on these IOCTL + size + pattern combinations:");
        for (i, (action, value)) in top.iter().enumerate() {
            let ioctl = ioctls.get(action.ioctl_idx).unwrap_or(&0);
            println!("    {}. 0x{:08X} with {:?} size, {:?} pattern (Q={:.2})",
                     i + 1, ioctl, action.size_bucket, action.pattern, value);
        }
    }
}

/// SMART+RL Combined Mode - The ultimate fuzzer
/// Combines RL learning with UAF/Double-Free hunting
fn run_smart_rl_fuzzing(driver: &mut DriverIO, ioctls: &[u32], args: &Args) {
    println!("\n{}", "╔══════════════════════════════════════════════════════════════╗".magenta());
    println!("{}", "║     🧠 SMART + RL COMBINED FUZZER 🧠                          ║".magenta());
    println!("{}", "║     RL Learning + IOCTL Classification + UAF Hunting         ║".magenta());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".magenta());
    
    println!("\n[*] This mode combines:");
    println!("    ✓ Reinforcement Learning (learns what works)");
    println!("    ✓ IOCTL Classification (Allocator/Freer/User)");
    println!("    ✓ UAF Sequence Generation");
    println!("    ✓ Adaptive exploration/exploitation");
    
    // Setup signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        if r.swap(false, Ordering::SeqCst) {
            println!("\n{}", "[!] Stopping smart+RL fuzzer...".yellow());
        }
    }).expect("Error setting Ctrl-C handler");
    
    // Initialize both systems
    let mut rl = RLFuzzer::new(ioctls.to_vec());
    let mut smart = SmartFuzzer::new(ioctls.to_vec());
    let device_str = args.device.clone().unwrap_or_default();
    let poc_gen = PocGenerator::new(&device_str, None);
    
    let start_time = Instant::now();
    let mut last_print = Instant::now();
    let mut output_buffer = vec![0u8; args.max_size];
    
    // Phases
    let mut phase = 0; // 0=Learning, 1=Classification, 2=Hunting
    let learning_episodes = ioctls.len() as u64 * 100;
    
    // Track interesting IOCTLs
    let mut interesting_ioctls: Vec<(u32, f64)> = Vec::new(); // (ioctl, score)
    
    std::fs::create_dir_all(&args.output).ok();
    
    // Stats
    let mut crashes = 0u64;
    let mut unique_crashes: std::collections::HashSet<(u32, u32)> = std::collections::HashSet::new();
    
    println!("\n{}", "[*] Phase 1: RL Learning + IOCTL Behavior Analysis...".green().bold());
    println!("    Learning {} IOCTLs × 100 patterns = {} episodes", ioctls.len(), learning_episodes);
    println!("    Crash output: {}", args.output.display());
    println!("    Press Ctrl+C to stop\n");
    
    while running.load(Ordering::SeqCst) {
        // Optional iteration limit
        if args.iterations > 0 && rl.get_episode() >= args.iterations {
            break;
        }
        
        // Phase transitions
        if phase == 0 && rl.get_episode() >= learning_episodes {
            phase = 1;
            println!("\n\n{}", "═".repeat(60).cyan());
            println!("{}", "[*] Phase 2: Analyzing learned behavior...".cyan().bold());
            
            // Analyze smart learner
            smart.learner.analyze();
            smart.learner.print_knowledge();
            
            // Get top RL actions and mark those IOCTLs as interesting
            let top = rl.get_top_actions(20);
            for (action, value) in top {
                if value > 5.0 {
                    let ioctl = ioctls.get(action.ioctl_idx).copied().unwrap_or(0);
                    interesting_ioctls.push((ioctl, value));
                }
            }
            
            println!("\n[*] RL identified {} interesting IOCTLs", interesting_ioctls.len());
            for (ioctl, score) in interesting_ioctls.iter().take(10) {
                println!("    0x{:08X} - Score: {:.1}", ioctl, score);
            }
            
            phase = 2;
            println!("\n{}", "[*] Phase 3: UAF/DoubleFree Hunting with learned knowledge...".red().bold());
            println!("{}", "═".repeat(60).cyan());
        }
        
        // Generate input based on phase
        let (ioctl, input) = if phase < 2 {
            // Learning phase - use RL to explore
            let action = rl.choose_action();
            let (ioctl, input) = rl.action_to_input(&action);
            
            // Also feed to smart learner
            (ioctl, input)
        } else {
            // Hunting phase - generate UAF sequences using learned knowledge
            // Mix of: RL exploitation + Smart UAF sequences
            if rl.get_episode() % 5 < 3 {
                // 60% - Use RL's learned best actions
                let action = rl.choose_action();
                rl.action_to_input(&action)
            } else {
                // 40% - Generate UAF/double-free sequences
                if let Some(seq) = smart.learner.generate_uaf_sequence() {
                    if let Some((ioctl, _)) = seq.first() {
                        let mut input = vec![0u8; 64];
                        rand::thread_rng().fill(&mut input[..]);
                        (*ioctl, input)
                    } else {
                        let action = rl.choose_action();
                        rl.action_to_input(&action)
                    }
                } else {
                    let action = rl.choose_action();
                    rl.action_to_input(&action)
                }
            }
        };
        
        // Execute IOCTL
        let result = driver.send_ioctl(ioctl, &input, &mut output_buffer);
        
        let (success, error_code, bytes_ret) = match result {
            Ok(bytes) => (true, 0u32, bytes),
            Err(code) => (false, code as u32, 0),
        };
        
        // Feed to both learners
        let action = rl_fuzzer::FuzzAction {
            ioctl_idx: ioctls.iter().position(|&x| x == ioctl).unwrap_or(0),
            size_bucket: rl_fuzzer::SizeBucket::Medium,
            pattern: rl_fuzzer::PatternType::Random,
        };
        
        let reward = rl.process_result(
            action, ioctl, error_code, success, &output_buffer, bytes_ret, false
        );
        
        // Also record in smart learner
        smart.record_result(ioctl, &input, &output_buffer, bytes_ret, error_code, success);
        
        // Status update
        if last_print.elapsed().as_secs() >= 2 {
            let elapsed = start_time.elapsed();
            let eps = rl.get_episode() as f64 / elapsed.as_secs_f64();
            let phase_str = match phase {
                0 => "LEARNING",
                1 => "ANALYZING", 
                2 => "HUNTING",
                _ => "FUZZING",
            };
            
            print!("\r[{}] {} | Ep {} | ε={:.2} | 💀{} | Q={} | {:.0}/s    ",
                   format!("{:02}:{:02}:{:02}", 
                           elapsed.as_secs() / 3600,
                           (elapsed.as_secs() % 3600) / 60,
                           elapsed.as_secs() % 60).cyan(),
                   phase_str.yellow(),
                   rl.get_episode(),
                   rl.get_epsilon(),
                   crashes,
                   rl.get_q_table_size(),
                   eps);
            
            let _ = std::io::stdout().flush();
            last_print = Instant::now();
        }
        
        // Check for actual CRASH error codes (memory corruption)
        let is_crash = matches!(error_code,
            0xC0000005 |  // STATUS_ACCESS_VIOLATION
            0xC0000374 |  // STATUS_HEAP_CORRUPTION  
            0xC0000409 |  // STATUS_STACK_BUFFER_OVERRUN
            0xC000001D |  // STATUS_ILLEGAL_INSTRUCTION
            0xC0000420 |  // STATUS_ASSERTION_FAILURE
            0x80000002 |  // STATUS_DATATYPE_MISALIGNMENT
            0xC000009D |  // STATUS_DEVICE_NOT_READY (can indicate corruption)
            0xC0000008 |  // STATUS_INVALID_HANDLE (can indicate UAF)
            0xC0000006    // STATUS_IN_PAGE_ERROR
        );
        
        if is_crash {
            crashes += 1;
            let is_unique = unique_crashes.insert((ioctl, error_code));
            
            println!("\n\n{}", "╔══════════════════════════════════════════════════════════════╗".red().bold());
            println!("{}", "║                    💀 CRASH DETECTED! 💀                      ║".red().bold());
            println!("{}", "╚══════════════════════════════════════════════════════════════╝".red().bold());
            println!("    IOCTL:  0x{:08X}", ioctl);
            println!("    Error:  0x{:08X}", error_code);
            println!("    Input:  {} bytes", input.len());
            println!("    Crash #{} | Unique: {}", crashes, if is_unique { "YES ✓" } else { "no (duplicate)" });
            
            if is_unique {
                // Save crash using existing function
                save_crash(&args.output, ioctl, &input, error_code);
                
                // Generate PoC
                let poc = poc_gen.generate_single_poc(ioctl, &input);
                let poc_path = args.output.join(format!("crash_0x{:08X}_poc.py", ioctl));
                if let Ok(mut f) = std::fs::File::create(&poc_path) {
                    let _ = f.write_all(poc.as_bytes());
                }
                println!("    PoC:    {}", poc_path.display());
            }
        }
        
        // Log high-value finds (non-crash but interesting)
        if reward.value >= 100.0 && !is_crash {
            println!("\n{} {:?}: IOCTL 0x{:08X} | Reward: {:.0}",
                     "[!] INTERESTING!".yellow().bold(),
                     reward.reason,
                     ioctl,
                     reward.value);
            
            let filename = format!("smartrl_{}_0x{:08X}.bin", rl.get_episode(), ioctl);
            let filepath = args.output.join(&filename);
            if let Ok(mut f) = std::fs::File::create(&filepath) {
                let _ = f.write_all(&input);
            }
            
            // Generate PoC
            let poc = poc_gen.generate_single_poc(ioctl, &input);
            let poc_path = args.output.join(format!("smartrl_{}_poc.py", rl.get_episode()));
            if let Ok(mut f) = std::fs::File::create(&poc_path) {
                let _ = f.write_all(poc.as_bytes());
            }
        }
    }
    
    println!("\n\n");
    
    // Final report
    println!("{}", "╔══════════════════════════════════════════════════════════════╗".green());
    println!("{}", "║              SMART+RL FUZZING COMPLETE                       ║".green());
    println!("╚══════════════════════════════════════════════════════════════╝");
    
    // Crash summary
    println!("\n{}", "[*] CRASH SUMMARY:".red().bold());
    println!("    Total Crashes:  {}", crashes);
    println!("    Unique Crashes: {}", unique_crashes.len());
    println!("    Output Dir:     {}", args.output.display());
    if !unique_crashes.is_empty() {
        println!("\n    Unique crash signatures:");
        for (ioctl, err) in &unique_crashes {
            println!("      IOCTL 0x{:08X} → Error 0x{:08X}", ioctl, err);
        }
    }
    
    // Print RL knowledge
    rl.print_knowledge();
    
    // Print Smart classifications
    smart.learner.print_knowledge();
    
    // Save state
    let qtable_path = args.output.join("smartrl_qtable.txt");
    if let Ok(_) = rl.save(&qtable_path.to_string_lossy()) {
        println!("\n{} Q-table saved to: {}", "[+]".green(), qtable_path.display());
    }
    
    // Recommendations
    println!("\n{}", "[*] COMBINED RECOMMENDATIONS:".cyan().bold());
    println!("\n    From RL (best input patterns):");
    let top = rl.get_top_actions(5);
    for (i, (action, value)) in top.iter().enumerate() {
        let ioctl = ioctls.get(action.ioctl_idx).unwrap_or(&0);
        println!("      {}. 0x{:08X} | {:?} | {:?} | Q={:.1}",
                 i + 1, ioctl, action.size_bucket, action.pattern, value);
    }
    
    println!("\n    From Smart (potential UAF chains):");
    let allocators = smart.learner.get_allocators();
    let freers = smart.learner.get_freers();
    let users = smart.learner.get_users();
    
    if !allocators.is_empty() {
        println!("      Allocators: {:?}", allocators.iter().take(3).map(|x| format!("0x{:08X}", x)).collect::<Vec<_>>());
        println!("      Freers:     {:?}", freers.iter().take(3).map(|x| format!("0x{:08X}", x)).collect::<Vec<_>>());
        println!("      Users:      {:?}", users.iter().take(3).map(|x| format!("0x{:08X}", x)).collect::<Vec<_>>());
    } else {
        println!("      No clear UAF patterns found - driver may need structured input");
    }
}

/// TURBO MODE - ALL TECHNIQUES COMBINED
fn run_turbo_fuzzing(driver: &mut DriverIO, ioctls: &[u32], args: &Args) {
    use rand::Rng;
    
    println!("\n{}", "╔══════════════════════════════════════════════════════════════╗".red());
    println!("{}", "║     🚀 TURBO MODE - MAXIMUM AGGRESSION 🚀                     ║".red());
    println!("{}", "║     RL + Smart + Stateful + Race Conditions                   ║".red());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".red());
    
    println!("\n[*] TURBO combines:");
    println!("    ✓ {} - finds optimal inputs", "Reinforcement Learning".cyan());
    println!("    ✓ {} - classifies IOCTLs", "Smart Learning".cyan());
    println!("    ✓ {} - UAF/Double-Free hunting", "Stateful Sequences".cyan());
    println!("    ✓ {} - rapid-fire same-IOCTL", "Race Simulation".cyan());
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        if r.swap(false, Ordering::SeqCst) {
            println!("\n{}", "[!] Stopping TURBO fuzzer...".yellow());
        }
    }).expect("Error setting Ctrl-C handler");
    
    let mut rl = RLFuzzer::new(ioctls.to_vec());
    let mut smart = SmartFuzzer::new(ioctls.to_vec());
    let device_str = args.device.clone().unwrap_or_default();
    let poc_gen = PocGenerator::new(&device_str, None);
    
    let start_time = Instant::now();
    let mut last_print = Instant::now();
    let mut output_buffer = vec![0u8; args.max_size];
    
    std::fs::create_dir_all(&args.output).ok();
    
    let mut crashes = 0u64;
    let mut unique_crashes: std::collections::HashSet<(u32, u32)> = std::collections::HashSet::new();
    let mut phase = 0;
    let learning_episodes = (ioctls.len() as u64 * 50).max(500);
    
    let mut last_inputs: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut sequence_count = 0u64;
    
    println!("\n{}", "[*] Phase 1: LEARNING (RL + Smart)...".green().bold());
    println!("    {} episodes, then HUNT, then RACE", learning_episodes);
    println!("    Crash output: {}", args.output.display());
    println!("    Press Ctrl+C to stop\n");
    
    while running.load(Ordering::SeqCst) {
        if args.iterations > 0 && rl.get_episode() >= args.iterations {
            break;
        }
        
        // Phase transitions
        if phase == 0 && rl.get_episode() >= learning_episodes {
            phase = 1;
            println!("\n\n{}", "═".repeat(60).yellow());
            println!("{}", "[*] Phase 2: HUNTING (Stateful sequences)...".yellow().bold());
            smart.learner.analyze();
            println!("{}", "═".repeat(60).yellow());
        }
        
        if phase == 1 && rl.get_episode() >= learning_episodes * 3 {
            phase = 2;
            println!("\n\n{}", "═".repeat(60).red());
            println!("{}", "[*] Phase 3: RACE (rapid-fire)...".red().bold());
            println!("{}", "═".repeat(60).red());
        }
        
        // Generate based on phase
        let (ioctl, input) = match phase {
            0 => {
                let action = rl.choose_action();
                rl.action_to_input(&action)
            }
            1 => {
                let choice = rand::random::<u8>() % 10;
                if choice < 5 {
                    let action = rl.choose_action();
                    rl.action_to_input(&action)
                } else if choice < 8 && !last_inputs.is_empty() && !ioctls.is_empty() {
                    let (_, prev_input) = &last_inputs[rand::random::<usize>() % last_inputs.len()];
                    let new_ioctl = ioctls[rand::random::<usize>() % ioctls.len()];
                    (new_ioctl, prev_input.clone())
                } else if let Some((last_ioctl, last_input)) = last_inputs.last() {
                    (*last_ioctl, last_input.clone())
                } else {
                    let action = rl.choose_action();
                    rl.action_to_input(&action)
                }
            }
            _ => {
                sequence_count += 1;
                if sequence_count % 100 < 90 {
                    if let Some((last_ioctl, _)) = last_inputs.last() {
                        let mut rng = rand::thread_rng();
                        let mut input = vec![0u8; rng.gen_range(8..512)];
                        rng.fill(&mut input[..]);
                        (*last_ioctl, input)
                    } else {
                        let action = rl.choose_action();
                        rl.action_to_input(&action)
                    }
                } else {
                    let action = rl.choose_action();
                    rl.action_to_input(&action)
                }
            }
        };
        
        let result = driver.send_ioctl(ioctl, &input, &mut output_buffer);
        
        let (success, error_code, bytes_ret) = match result {
            Ok(bytes) => (true, 0u32, bytes),
            Err(code) => (false, code as u32, 0),
        };
        
        last_inputs.push((ioctl, input.clone()));
        if last_inputs.len() > 20 {
            last_inputs.remove(0);
        }
        
        let action = rl_fuzzer::FuzzAction {
            ioctl_idx: ioctls.iter().position(|&x| x == ioctl).unwrap_or(0),
            size_bucket: rl_fuzzer::SizeBucket::Medium,
            pattern: rl_fuzzer::PatternType::Random,
        };
        
        let reward = rl.process_result(action, ioctl, error_code, success, &output_buffer, bytes_ret, false);
        smart.record_result(ioctl, &input, &output_buffer, bytes_ret, error_code, success);
        
        // Real crash codes only - not normal driver rejections
        let is_crash = matches!(error_code,
            0xC0000005 | 0xC0000374 | 0xC0000409 | 0xC000001D |
            0xC0000420 | 0xC000009D
        );
        
        if is_crash {
            crashes += 1;
            let is_unique = unique_crashes.insert((ioctl, error_code));
            
            println!("\n\n{}", "╔══════════════════════════════════════════════════════════════╗".red().bold());
            println!("{}", "║                    💀 CRASH DETECTED! 💀                      ║".red().bold());
            println!("{}", "╚══════════════════════════════════════════════════════════════╝".red().bold());
            println!("    IOCTL:  0x{:08X}", ioctl);
            println!("    Error:  0x{:08X}", error_code);
            println!("    Phase:  {}", match phase { 0 => "LEARN", 1 => "HUNT", _ => "RACE" });
            
            if is_unique {
                save_crash(&args.output, ioctl, &input, error_code);
                let poc = poc_gen.generate_single_poc(ioctl, &input);
                let poc_path = args.output.join(format!("turbo_crash_0x{:08X}_poc.py", ioctl));
                if let Ok(mut f) = std::fs::File::create(&poc_path) {
                    let _ = f.write_all(poc.as_bytes());
                }
                
                let seq_path = args.output.join(format!("turbo_sequence_{}.txt", crashes));
                if let Ok(mut f) = std::fs::File::create(&seq_path) {
                    writeln!(f, "# Crash sequence (last 20 calls)").ok();
                    for (i, (io, inp)) in last_inputs.iter().enumerate() {
                        writeln!(f, "{}. IOCTL 0x{:08X} | {} bytes", i + 1, io, inp.len()).ok();
                    }
                }
            }
        }
        
        if last_print.elapsed().as_secs() >= 2 {
            let elapsed = start_time.elapsed();
            let eps = rl.get_episode() as f64 / elapsed.as_secs_f64();
            let phase_str = match phase {
                0 => "LEARN".green(),
                1 => "HUNT".yellow(),
                _ => "RACE".red(),
            };
            
            print!("\r[{}] 🚀{} | Ep {} | ε={:.2} | 💀{} | Q={} | {:.0}/s    ",
                   format!("{:02}:{:02}:{:02}", 
                           elapsed.as_secs() / 3600,
                           (elapsed.as_secs() % 3600) / 60,
                           elapsed.as_secs() % 60).cyan(),
                   phase_str,
                   rl.get_episode(),
                   rl.get_epsilon(),
                   crashes,
                   rl.get_q_table_size(),
                   eps);
            
            let _ = std::io::stdout().flush();
            last_print = Instant::now();
        }
        
        if reward.value >= 100.0 && !is_crash {
            println!("\n{} {:?}: IOCTL 0x{:08X}", "[!] INTERESTING!".yellow().bold(), reward.reason, ioctl);
        }
    }
    
    println!("\n\n");
    println!("{}", "╔══════════════════════════════════════════════════════════════╗".red());
    println!("{}", "║              🚀 TURBO FUZZING COMPLETE 🚀                    ║".red());
    println!("╚══════════════════════════════════════════════════════════════╝");
    
    println!("\n{}", "[*] CRASH SUMMARY:".red().bold());
    println!("    Total:  {} | Unique: {}", crashes, unique_crashes.len());
    println!("    Output: {}", args.output.display());
    
    if !unique_crashes.is_empty() {
        for (ioctl, err) in &unique_crashes {
            println!("    💀 IOCTL 0x{:08X} → 0x{:08X}", ioctl, err);
        }
    }
    
    rl.print_knowledge();
}

/// FORMAT MODE - Format-aware fuzzing with SDB, TPM, PEAUTH patterns
fn run_format_fuzzing(driver: &mut DriverIO, ioctls: &[u32], args: &Args) {
    use rand::{Rng, SeedableRng};
    use rl_fuzzer::PatternType;
    
    println!("\n{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║     📋 FORMAT-AWARE FUZZER                                    ║".cyan());
    println!("{}", "║     Structured input patterns for hardened drivers            ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════╝".cyan());
    
    // Detect target driver and pick patterns
    let device = args.device.clone().unwrap_or_default().to_lowercase();
    let patterns: Vec<PatternType> = if device.contains("ahcache") {
        println!("\n[*] Detected: {} - using SDB patterns", "ahcache".yellow());
        vec![
            PatternType::SdbHeader,
            PatternType::SdbMalformed,
            PatternType::SdbTagFuzz,
            PatternType::StructuredHeader,
            PatternType::SizePrefix,
        ]
    } else if device.contains("tpm") {
        println!("\n[*] Detected: {} - using TPM patterns", "TPM".yellow());
        vec![
            PatternType::TpmCommand,
            PatternType::StructuredHeader,
            PatternType::SizePrefix,
        ]
    } else if device.contains("peauth") {
        println!("\n[*] Detected: {} - using PEAUTH patterns", "PEAUTH".yellow());
        vec![
            PatternType::PeAuthRequest,
            PatternType::StructuredHeader,
            PatternType::SizePrefix,
        ]
    } else {
        println!("\n[*] Unknown driver - using all format patterns");
        vec![
            PatternType::SdbHeader,
            PatternType::SdbMalformed,
            PatternType::SdbTagFuzz,
            PatternType::TpmCommand,
            PatternType::PeAuthRequest,
            PatternType::StructuredHeader,
            PatternType::SizePrefix,
            PatternType::HandleLike,
        ]
    };
    
    println!("    Patterns: {:?}", patterns.iter().map(|p| format!("{:?}", p)).collect::<Vec<_>>());
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        if r.swap(false, Ordering::SeqCst) {
            println!("\n{}", "[!] Stopping format fuzzer...".yellow());
        }
    }).expect("Error setting Ctrl-C handler");
    
    let device_str = args.device.clone().unwrap_or_default();
    let poc_gen = PocGenerator::new(&device_str, None);
    
    let start_time = Instant::now();
    let mut last_print = Instant::now();
    let mut output_buffer = vec![0u8; args.max_size];
    let mut rng = rand::rngs::StdRng::seed_from_u64(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    
    std::fs::create_dir_all(&args.output).ok();
    
    let mut iterations = 0u64;
    let mut crashes = 0u64;
    let mut successes = 0u64;
    let mut unique_crashes: std::collections::HashSet<(u32, u32)> = std::collections::HashSet::new();
    let mut error_codes: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    let mut pattern_stats: std::collections::HashMap<String, (u64, u64)> = std::collections::HashMap::new(); // (tries, successes)
    
    // Sizes to try - including boundary cases
    let sizes = vec![0, 4, 8, 12, 16, 20, 24, 32, 48, 64, 128, 256, 512, 1024, 2048, 4096];
    
    println!("    Sizes: {:?}", sizes);
    println!("    IOCTLs: {}", ioctls.len());
    println!("    Crash output: {}", args.output.display());
    println!("    Press Ctrl+C to stop\n");
    
    while running.load(Ordering::SeqCst) {
        if args.iterations > 0 && iterations >= args.iterations {
            break;
        }
        
        // Pick random IOCTL, pattern, and size
        let ioctl = ioctls[rng.gen_range(0..ioctls.len())];
        let pattern = &patterns[rng.gen_range(0..patterns.len())];
        let size = sizes[rng.gen_range(0..sizes.len())];
        
        // Generate input
        let input = pattern.generate(size, &mut rng);
        
        // Execute
        let result = driver.send_ioctl(ioctl, &input, &mut output_buffer);
        iterations += 1;
        
        let pattern_key = format!("{:?}", pattern);
        let entry = pattern_stats.entry(pattern_key.clone()).or_insert((0, 0));
        entry.0 += 1;
        
        let (success, error_code, _bytes_ret) = match result {
            Ok(bytes) => {
                successes += 1;
                entry.1 += 1;
                (true, 0u32, bytes)
            }
            Err(code) => (false, code as u32, 0),
        };
        
        *error_codes.entry(error_code).or_insert(0) += 1;
        
        // Real crash codes only - not normal driver rejections
        let is_crash = matches!(error_code,
            0xC0000005 | 0xC0000374 | 0xC0000409 | 0xC000001D |
            0xC0000420 | 0xC000009D
        );
        
        if is_crash {
            crashes += 1;
            let is_unique = unique_crashes.insert((ioctl, error_code));
            
            println!("\n\n{}", "╔══════════════════════════════════════════════════════════════╗".red().bold());
            println!("{}", "║                    💀 CRASH DETECTED! 💀                      ║".red().bold());
            println!("{}", "╚══════════════════════════════════════════════════════════════╝".red().bold());
            println!("    IOCTL:   0x{:08X}", ioctl);
            println!("    Error:   0x{:08X}", error_code);
            println!("    Pattern: {:?}", pattern);
            println!("    Size:    {} bytes", size);
            
            if is_unique {
                save_crash(&args.output, ioctl, &input, error_code);
                let poc = poc_gen.generate_single_poc(ioctl, &input);
                let poc_path = args.output.join(format!("format_crash_0x{:08X}_poc.py", ioctl));
                if let Ok(mut f) = std::fs::File::create(&poc_path) {
                    let _ = f.write_all(poc.as_bytes());
                }
            }
        }
        
        // Success is interesting! Print it
        if success {
            println!("\n{} IOCTL 0x{:08X} | {:?} | {} bytes",
                     "[+] SUCCESS!".green().bold(),
                     ioctl, pattern, size);
        }
        
        // Status update
        if last_print.elapsed().as_secs() >= 2 {
            let elapsed = start_time.elapsed();
            let eps = iterations as f64 / elapsed.as_secs_f64();
            
            // Find best pattern
            let best_pattern = pattern_stats.iter()
                .max_by(|a, b| {
                    let rate_a = if a.1.0 > 0 { a.1.1 as f64 / a.1.0 as f64 } else { 0.0 };
                    let rate_b = if b.1.0 > 0 { b.1.1 as f64 / b.1.0 as f64 } else { 0.0 };
                    rate_a.partial_cmp(&rate_b).unwrap()
                })
                .map(|(k, _)| k.clone())
                .unwrap_or_default();
            
            print!("\r[{}] 📋 | {} iter | 💀{} | ✓{} | {} err | Best: {} | {:.0}/s    ",
                   format!("{:02}:{:02}:{:02}", 
                           elapsed.as_secs() / 3600,
                           (elapsed.as_secs() % 3600) / 60,
                           elapsed.as_secs() % 60).cyan(),
                   iterations,
                   crashes,
                   successes,
                   error_codes.len(),
                   best_pattern.chars().take(12).collect::<String>(),
                   eps);
            
            let _ = std::io::stdout().flush();
            last_print = Instant::now();
        }
    }
    
    println!("\n\n");
    println!("{}", "╔══════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║              📋 FORMAT FUZZING COMPLETE                      ║".cyan());
    println!("╚══════════════════════════════════════════════════════════════╝");
    
    println!("\n{}", "[*] RESULTS:".cyan().bold());
    println!("    Iterations: {}", iterations);
    println!("    Crashes:    {} ({} unique)", crashes, unique_crashes.len());
    println!("    Successes:  {}", successes);
    
    println!("\n[*] Error Codes Seen:");
    let mut errors: Vec<_> = error_codes.iter().collect();
    errors.sort_by(|a, b| b.1.cmp(a.1));
    for (code, count) in errors.iter().take(10) {
        println!("    0x{:08X}: {} times", code, count);
    }
    
    println!("\n[*] Pattern Performance:");
    for (pattern, (tries, successes)) in &pattern_stats {
        let rate = if *tries > 0 { (*successes as f64 / *tries as f64) * 100.0 } else { 0.0 };
        println!("    {:20} | {} tries | {} success ({:.1}%)", 
                 pattern, tries, successes, rate);
    }
    
    if !unique_crashes.is_empty() {
        println!("\n{}", "[*] UNIQUE CRASHES:".red().bold());
        for (ioctl, err) in &unique_crashes {
            println!("    💀 IOCTL 0x{:08X} → 0x{:08X}", ioctl, err);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ULTIMATE FUZZER - Maximum Intelligence, All Techniques Combined
// ═══════════════════════════════════════════════════════════════════════════════

/// Genetic individual - represents a promising input
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct GeneticIndividual {
    ioctl: u32,
    data: Vec<u8>,
    pattern: String,
    fitness: f64,
    generation: u32,
    error_code: u32,
    #[serde(skip)]
    parent_ids: (u64, u64),
}

impl GeneticIndividual {
    fn new(ioctl: u32, data: Vec<u8>, pattern: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        Self {
            ioctl,
            data,
            pattern: pattern.to_string(),
            fitness: 0.0,
            generation: 0,
            error_code: 0,
            parent_ids: (id, id),
        }
    }
    
    /// Crossover two individuals
    fn crossover(&self, other: &Self, rng: &mut rand::rngs::StdRng) -> Self {
        use rand::Rng;
        let mut child_data = Vec::new();
        
        // Safety: handle empty data
        if self.data.is_empty() && other.data.is_empty() {
            return GeneticIndividual {
                ioctl: self.ioctl,
                data: vec![0u8; 64],
                pattern: "empty_crossover".to_string(),
                fitness: 0.0,
                generation: self.generation + 1,
                error_code: 0,
                parent_ids: (0, 0),
            };
        }
        
        // Use the longer parent's data as base
        let (longer, shorter) = if self.data.len() >= other.data.len() {
            (&self.data, &other.data)
        } else {
            (&other.data, &self.data)
        };
        
        // Safety: ensure longer is not empty
        if longer.is_empty() {
            return GeneticIndividual {
                ioctl: self.ioctl,
                data: vec![0u8; 64],
                pattern: "empty_longer".to_string(),
                fitness: 0.0,
                generation: self.generation + 1,
                error_code: 0,
                parent_ids: (0, 0),
            };
        }
        
        // Crossover strategies
        match rng.gen_range(0..4) {
            0 => {
                // Single-point crossover
                let point = rng.gen_range(0..longer.len());
                child_data.extend_from_slice(&longer[..point]);
                if shorter.len() > point {
                    child_data.extend_from_slice(&shorter[point..]);
                } else {
                    child_data.extend_from_slice(&longer[point..]);
                }
            }
            1 => {
                // Two-point crossover
                let p1 = rng.gen_range(0..longer.len());
                let p2 = rng.gen_range(p1..=longer.len());
                child_data.extend_from_slice(&longer[..p1]);
                if !shorter.is_empty() && p1 < shorter.len() {
                    let end = p2.min(shorter.len());
                    child_data.extend_from_slice(&shorter[p1..end]);
                }
                if p2 < longer.len() {
                    child_data.extend_from_slice(&longer[p2..]);
                }
            }
            2 => {
                // Uniform crossover (byte-by-byte coin flip)
                for i in 0..longer.len() {
                    if rng.gen_bool(0.5) && i < shorter.len() {
                        child_data.push(shorter[i]);
                    } else {
                        child_data.push(longer[i]);
                    }
                }
            }
            _ => {
                // Chunk swap
                child_data.extend_from_slice(longer);
                if shorter.len() >= 8 && child_data.len() >= 8 {
                    let chunk_start = rng.gen_range(0..shorter.len().saturating_sub(7));
                    let chunk_end = (chunk_start + 8).min(shorter.len());
                    let insert_pos = rng.gen_range(0..child_data.len().saturating_sub(7));
                    for (i, b) in shorter[chunk_start..chunk_end].iter().enumerate() {
                        if insert_pos + i < child_data.len() {
                            child_data[insert_pos + i] = *b;
                        }
                    }
                }
            }
        }
        
        // Ensure minimum size
        if child_data.is_empty() {
            child_data = longer.clone();
        }
        
        // Cap data size to prevent memory issues
        if child_data.len() > 8192 {
            child_data.truncate(8192);
        }
        
        // Cap pattern string length to prevent unbounded growth (HEAP CORRUPTION FIX!)
        let pattern = if self.pattern.len() + other.pattern.len() > 64 {
            format!("gen{}", self.generation + 1)
        } else {
            format!("{}_x_{}", self.pattern, other.pattern)
        };
        
        GeneticIndividual {
            ioctl: if rng.gen_bool(0.5) { self.ioctl } else { other.ioctl },
            data: child_data,
            pattern,
            fitness: 0.0,
            generation: self.generation.max(other.generation) + 1,
            error_code: 0,
            parent_ids: (self.parent_ids.0, other.parent_ids.0),
        }
    }
    
    /// Mutate the individual
    fn mutate(&mut self, rng: &mut rand::rngs::StdRng) {
        use rand::Rng;
        use rand::seq::SliceRandom;
        if self.data.is_empty() {
            return;
        }
        
        // Apply multiple mutation types
        for _ in 0..rng.gen_range(1..5) {
            match rng.gen_range(0..12) {
                0 => {
                    // Bit flip
                    let idx = rng.gen_range(0..self.data.len());
                    let bit = rng.gen_range(0..8);
                    self.data[idx] ^= 1 << bit;
                }
                1 => {
                    // Byte flip
                    let idx = rng.gen_range(0..self.data.len());
                    self.data[idx] = !self.data[idx];
                }
                2 => {
                    // Set to interesting value
                    let idx = rng.gen_range(0..self.data.len());
                    let vals = [0x00u8, 0x01, 0x7F, 0x80, 0xFF, 0x41];
                    self.data[idx] = *vals.choose(rng).unwrap();
                }
                3 if self.data.len() >= 4 => {
                    // Integer mutation (32-bit boundary)
                    let idx = (rng.gen_range(0..self.data.len()) / 4) * 4;
                    if idx + 4 <= self.data.len() {
                        let vals = [0u32, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x41414141];
                        let val: u32 = *vals.choose(rng).unwrap();
                        self.data[idx..idx+4].copy_from_slice(&val.to_le_bytes());
                    }
                }
                4 if self.data.len() >= 8 => {
                    // Pointer mutation (64-bit)
                    let idx = (rng.gen_range(0..self.data.len()) / 8) * 8;
                    if idx + 8 <= self.data.len() {
                        let vals = [0u64, 0xFFFFFFFFFFFFFFFF, 0xDEADBEEF, 0x4141414141414141];
                        let val: u64 = *vals.choose(rng).unwrap();
                        self.data[idx..idx+8].copy_from_slice(&val.to_le_bytes());
                    }
                }
                5 => {
                    // Insert random bytes
                    let pos = rng.gen_range(0..=self.data.len());
                    let count = rng.gen_range(1..8);
                    for _ in 0..count {
                        if self.data.len() < 8192 {
                            self.data.insert(pos.min(self.data.len()), rng.gen());
                        }
                    }
                }
                6 if self.data.len() > 8 => {
                    // Delete random bytes
                    let pos = rng.gen_range(0..self.data.len());
                    let count = rng.gen_range(1..4).min(self.data.len() - pos);
                    self.data.drain(pos..pos+count);
                }
                7 => {
                    // Duplicate a chunk
                    if self.data.len() >= 4 && self.data.len() < 4096 {
                        let start = rng.gen_range(0..self.data.len());
                        let len = rng.gen_range(1..8).min(self.data.len() - start);
                        let chunk: Vec<u8> = self.data[start..start+len].to_vec();
                        let insert = rng.gen_range(0..=self.data.len());
                        for (i, b) in chunk.iter().enumerate() {
                            self.data.insert((insert + i).min(self.data.len()), *b);
                        }
                    }
                }
                8 => {
                    // Arithmetic mutation
                    let idx = rng.gen_range(0..self.data.len());
                    let delta: i8 = rng.gen_range(-16..16);
                    self.data[idx] = self.data[idx].wrapping_add(delta as u8);
                }
                9 if self.data.len() >= 4 => {
                    // Size field corruption (UAF pattern)
                    // Target first 4 bytes as size, set to huge value
                    let vals = [0xFFFFFFFFu32, 0x7FFFFFFF, 0x80000000];
                    let huge: u32 = *vals.choose(rng).unwrap();
                    self.data[0..4].copy_from_slice(&huge.to_le_bytes());
                }
                10 if self.data.len() >= 16 => {
                    // Null pointer injection
                    let idx = (rng.gen_range(0..self.data.len()) / 8) * 8;
                    if idx + 8 <= self.data.len() {
                        self.data[idx..idx+8].fill(0);
                    }
                }
                11 => {
                    // Type confusion - change what looks like a type field
                    if self.data.len() >= 8 {
                        let idx = rng.gen_range(0..self.data.len() / 4) * 4;
                        if idx + 4 <= self.data.len() {
                            let type_val: u32 = rng.gen();
                            self.data[idx..idx+4].copy_from_slice(&type_val.to_le_bytes());
                        }
                    }
                }
                _ => {}
            }
        }
        
        // Cap data size after mutations
        if self.data.len() > 8192 {
            self.data.truncate(8192);
        }
        
        // Cap pattern string length to prevent unbounded growth (HEAP CORRUPTION FIX!)
        if self.pattern.len() < 60 {
            self.pattern = format!("{}_mut", self.pattern);
        }
    }
}

fn run_ultimate_fuzzing(driver: &mut DriverIO, ioctls: &[u32], args: &Args) {
    use rand::{Rng, SeedableRng};
    use rand::seq::SliceRandom;
    use rl_fuzzer::{RLFuzzer, PatternType};
    use std::collections::{HashMap, HashSet};
    use std::cmp::Ordering as CmpOrdering;
    
    println!("\n[*] ⚡ ULTIMATE FUZZER | 6 techniques | {} IOCTLs | {} max | (--gdi-race for race bugs)", ioctls.len(), args.max_size);
    
    // Detect target and get format patterns (silent detection)
    let device = args.device.clone().unwrap_or_default().to_lowercase();
    let format_patterns: Vec<PatternType> = if device.contains("vboxguest") || device.contains("vbox") {
        vec![
            PatternType::VBoxRequest,
            PatternType::VBoxHGCMCall,
            PatternType::VBoxGuestInfo,
            PatternType::VBoxMouse,
            PatternType::VBoxVideo,
            PatternType::StructuredHeader,
            PatternType::SizePrefix,
        ]
    } else if device.contains("ahcache") {
        vec![
            PatternType::AhcacheQuery, 
            PatternType::AhcacheLookup, 
            PatternType::AhcacheNotify,
            PatternType::UnicodeString,
            PatternType::SdbHeader, 
            PatternType::SdbMalformed, 
            PatternType::SdbTagFuzz,
            PatternType::StructuredHeader,
            PatternType::SizePrefix,
        ]
    } else if device.contains("tpm") {
        vec![PatternType::TpmCommand, PatternType::StructuredHeader]
    } else if device.contains("peauth") {
        vec![PatternType::PeAuthRequest, PatternType::StructuredHeader]
    } else if device.contains("trustedrt") || device.contains("windowstrusted") {
        // WindowsTrustedRT - Trusted Runtime driver (wtd.sys)
        // Uses structured requests similar to DRM/crypto drivers
        vec![
            PatternType::StructuredHeader,
            PatternType::SizePrefix,
            PatternType::HandleLike,
            PatternType::ObjectAttrs,
            PatternType::NullPointers,
            PatternType::MaxValues,
            PatternType::Overflow,
        ]
    } else {
        PatternType::all()
    };
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        // Only print once - check if already stopping
        if r.swap(false, Ordering::SeqCst) {
            println!("\n{}", "[!] Stopping ULTIMATE fuzzer...".yellow());
        }
    }).ok(); // Ignore error if handler already set
    
    // Initialize components
    let mut rl = RLFuzzer::new(ioctls.to_vec());
    
    // Load saved model if provided (silent)
    if let Some(ref model_path) = args.load_model {
        let _ = rl.load_model(model_path);
    }
    
    // Initialize FuzzerState - ALL learning in ONE file
    let state_path = args.output.join("fuzzer_state.bin");
    let mut fuzzer_state = if state_path.exists() {
        match learner::FuzzerState::load(&state_path) {
            Ok(loaded) => {
                println!("[+] Loaded FuzzerState: {}", loaded.stats());
                loaded
            }
            Err(e) => {
                eprintln!("[!] Failed to load FuzzerState ({}), starting fresh", e);
                learner::FuzzerState::new()
            }
        }
    } else {
        learner::FuzzerState::new()
    };
    fuzzer_state.smart_dedup.init_ioctls(ioctls);
    
    // Note: Access fuzzer_state.smart_dedup directly throughout
    
    let device_str = args.device.clone().unwrap_or_default();
    let poc_gen = PocGenerator::new(&device_str, None);
    let mut rng = rand::rngs::StdRng::seed_from_u64(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    );
    
    std::fs::create_dir_all(&args.output).ok();
    
    // Setup model save path
    let model_save_path = args.output.join("rl_model.bin");
    let mut last_save = Instant::now();
    
    // Dependency learning phase flag
    let mut dependency_learning_done = false;
    let mut last_ioctl_called: Option<u32> = None;
    
    // State tracking
    let start_time = Instant::now();
    let mut last_print = Instant::now();
    // Use larger output buffer with guard region to detect buffer overflows
    let output_size = args.max_size + 4096; // Extra 4KB guard region
    let mut output_buffer = vec![0xCCu8; output_size];
    let mut buffer_overflows = 0u64;
    
    // Statistics
    let mut iterations = 0u64;
    let mut crashes = 0u64;
    let mut successes = 0u64;
    let mut unique_crashes: HashSet<(u32, u32)> = HashSet::new();
    let mut error_coverage: HashMap<u32, u64> = HashMap::new();
    let mut technique_stats: HashMap<&str, (u64, u64, u64)> = HashMap::new(); // (tries, successes, crashes)
    
    // Genetic population
    let mut population: Vec<GeneticIndividual> = Vec::new();
    let population_max = 100;
    let mut generation = 0u32;
    
    // Interesting inputs (different error codes)
    let mut interesting_inputs: Vec<GeneticIndividual> = Vec::new();
    
    // Phase control
    let mut phase = 0;
    let phase_duration = 50000u64; // iterations per phase (longer phases)
    let mut phase_start = 0u64;
    let phases = ["FORMAT-RL", "GENETIC", "UAF-HUNT", "INTENSIVE", "ADAPTIVE", "SMART"];
    
    // Race condition state
    let mut race_candidates: Vec<(u32, Vec<u8>)> = Vec::new();
    
    // Set panic hook to show what went wrong
    std::panic::set_hook(Box::new(|info| {
        eprintln!("\n[PANIC] Ultimate fuzzer crashed: {}", info);
        if let Some(loc) = info.location() {
            eprintln!("[PANIC] Location: {}:{}:{}", loc.file(), loc.line(), loc.column());
        }
    }));
    
    let mut exit_reason = "unknown";
    
    // Debug: print args.iterations to see if limit is set
    if args.iterations > 0 {
        println!("[DEBUG] Iteration limit set to: {}", args.iterations);
    }
    
    while running.load(Ordering::SeqCst) {
        // Wrap entire iteration in catch_unwind to survive ANY crash
        let iteration_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        
        if args.iterations > 0 && iterations >= args.iterations {
            return Some("iteration_limit");
        }
        
        // Phase transitions (cycle through techniques)
        if iterations >= phase_start + phase_duration {
            let old_phase = phase;
            phase = (phase + 1) % phases.len();
            phase_start = iterations;
            // Silent phase transition - shown in status line
            
            // Evolve population when entering GENETIC phase
            if phase == 1 && population.len() >= 2 {
                generation += 1;
                
                // Cap collections to prevent memory bloat
                if population.len() > 150 {
                    population.sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap_or(std::cmp::Ordering::Equal));
                    population.truncate(100);
                }
                if interesting_inputs.len() > 300 {
                    interesting_inputs.drain(0..interesting_inputs.len() - 200);
                }
                
                evolve_population(&mut population, &mut rng, population_max);
                population.retain(|ind| !ind.data.is_empty() && ind.data.len() <= args.max_size);
            }
        }
        
        // Generate input based on current phase
        let (ioctl, input, technique) = match phase {
            0 => {
                // FORMAT-RL: Format-aware patterns with RL selection
                let action = rl.choose_action();
                let (ioctl, mut input) = rl.action_to_input(&action);
                
                // Override with format pattern 70% of time
                if rng.gen_bool(0.7) {
                    let pattern = format_patterns.choose(&mut rng).unwrap();
                    let sizes = [32usize, 64, 128, 256, 512, 1024];
                    let size = *sizes.choose(&mut rng).unwrap();
                    input = pattern.generate(size, &mut rng);
                }
                
                (ioctl, input, "FORMAT-RL")
            }
            1 => {
                // GENETIC: Evolve promising inputs
                // Safety: ensure we have valid population
                if population.is_empty() {
                    let pattern = format_patterns.choose(&mut rng).unwrap();
                    let ioctl = ioctls.get(0).copied().unwrap_or(0x220000);
                    (ioctl, pattern.generate(256, &mut rng), "GENETIC-FALLBACK")
                } else if population.len() >= 2 && rng.gen_bool(0.6) {
                    // Crossover two parents
                    let idx1 = rng.gen_range(0..population.len());
                    let idx2 = rng.gen_range(0..population.len());
                    let mut child = population[idx1].crossover(&population[idx2], &mut rng);
                    
                    // Mutate
                    if rng.gen_bool(0.8) {
                        child.mutate(&mut rng);
                    }
                    
                    // Safety: ensure child has data
                    if child.data.is_empty() {
                        child.data = population[idx1].data.clone();
                    }
                    if child.data.is_empty() {
                        child.data = vec![0u8; 64];
                    }
                    
                    (child.ioctl, child.data.clone(), "GENETIC")
                } else if !interesting_inputs.is_empty() && rng.gen_bool(0.5) {
                    // Mutate an interesting input
                    let idx = rng.gen_range(0..interesting_inputs.len());
                    let mut ind = interesting_inputs[idx].clone();
                    ind.mutate(&mut rng);
                    (ind.ioctl, ind.data.clone(), "GENETIC-INT")
                } else if !ioctls.is_empty() {
                    // Fall back to format pattern
                    let pattern = format_patterns.choose(&mut rng).unwrap();
                    let size = rng.gen_range(32..1024);
                    let ioctl = ioctls[rng.gen_range(0..ioctls.len())];
                    (ioctl, pattern.generate(size, &mut rng), "GENETIC-NEW")
                } else {
                    // Safety: use default IOCTL
                    let pattern = format_patterns.choose(&mut rng).unwrap();
                    (0x220000, pattern.generate(256, &mut rng), "GENETIC-SAFE")
                }
            }
            2 => {
                // UAF-HUNT: Apply UAF/memory corruption mutations
                // HEVD-specific: If targeting HEVD, use proper Allocate→Free→Use sequence
                if device.contains("hacksys") || device.contains("hevd") {
                    // HEVD NonPagedPoolNx UAF IOCTLs
                    const HEVD_ALLOC: u32 = 0x22201F;
                    const HEVD_FREE: u32 = 0x222027;
                    const HEVD_USE: u32 = 0x222023;
                    
                    // Execute the full UAF sequence inline
                    let alloc_input = vec![0x41u8; 64];
                    let free_input = vec![0x42u8; 64];
                    let use_input: Vec<u8> = (0..64).map(|_| rng.gen::<u8>()).collect();
                    
                    // 1. Allocate
                    let _ = driver.send_ioctl(HEVD_ALLOC, &alloc_input, &mut output_buffer);
                    // 2. Free (creates dangling pointer)
                    let _ = driver.send_ioctl(HEVD_FREE, &free_input, &mut output_buffer);
                    // 3. Use (triggers UAF!) - this is what we return for crash detection
                    (HEVD_USE, use_input, "UAF-HEVD")
                } else {
                    // Generic UAF mutation for other drivers
                    let base_input = if !interesting_inputs.is_empty() && rng.gen_bool(0.7) {
                        let idx = rng.gen_range(0..interesting_inputs.len());
                        interesting_inputs[idx].data.clone()
                    } else {
                        let pattern = format_patterns.choose(&mut rng).unwrap();
                        pattern.generate(rng.gen_range(64..512), &mut rng)
                    };
                    
                    let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                    let corrupted = apply_uaf_mutation(&base_input, &mut rng);
                    
                    (ioctl, corrupted, "UAF-HUNT")
                }
            }
            3 => {
                // INTENSIVE: Rapid-fire promising inputs with mutations
                // (Race condition testing moved to --gdi-race for better results)
                
                // Use interesting inputs or format patterns
                let base_input = if !interesting_inputs.is_empty() && rng.gen_bool(0.8) {
                    let idx = rng.gen_range(0..interesting_inputs.len());
                    interesting_inputs[idx].data.clone()
                } else if !population.is_empty() && rng.gen_bool(0.5) {
                    let idx = rng.gen_range(0..population.len());
                    population[idx].data.clone()
                } else {
                    let pattern = format_patterns.choose(&mut rng).unwrap();
                    pattern.generate(rng.gen_range(64..1024), &mut rng)
                };
                
                let ioctl = if !interesting_inputs.is_empty() && rng.gen_bool(0.7) {
                    interesting_inputs[rng.gen_range(0..interesting_inputs.len())].ioctl
                } else {
                    ioctls[rng.gen_range(0..ioctls.len().max(1))]
                };
                
                // Apply random mutations to promising inputs
                let mut mutated = base_input.clone();
                let mutations = rng.gen_range(1..5);
                for _ in 0..mutations {
                    if !mutated.is_empty() {
                        let idx = rng.gen_range(0..mutated.len());
                        mutated[idx] = rng.gen();
                    }
                }
                
                (ioctl, mutated, "INTENSIVE")
            }
            4 => {
                // ADAPTIVE: Choose best technique based on stats
                let best_technique = technique_stats.iter()
                    .max_by(|a, b| {
                        let score_a = a.1.2 as f64 * 1000.0 + a.1.1 as f64;
                        let score_b = b.1.2 as f64 * 1000.0 + b.1.1 as f64;
                        score_a.partial_cmp(&score_b).unwrap_or(CmpOrdering::Equal)
                    })
                    .map(|(k, _)| *k)
                    .unwrap_or("FORMAT-RL");
                
                // Use the best technique
                match best_technique {
                    "GENETIC" | "GENETIC-INT" | "GENETIC-NEW" if population.len() >= 2 => {
                        let idx = rng.gen_range(0..population.len());
                        let mut ind = population[idx].clone();
                        ind.mutate(&mut rng);
                        (ind.ioctl, ind.data.clone(), "ADAPTIVE-GEN")
                    }
                    "UAF-HUNT" if !interesting_inputs.is_empty() => {
                        let idx = rng.gen_range(0..interesting_inputs.len());
                        let corrupted = apply_uaf_mutation(&interesting_inputs[idx].data, &mut rng);
                        (interesting_inputs[idx].ioctl, corrupted, "ADAPTIVE-UAF")
                    }
                    _ => {
                        let pattern = format_patterns.choose(&mut rng).unwrap();
                        let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                        (ioctl, pattern.generate(rng.gen_range(32..1024), &mut rng), "ADAPTIVE-FMT")
                    }
                }
            }
            _ => {
                // SMART: Use learned constraints and dependencies (MSFuzz-style)
                // This phase uses SmartDedup to generate inputs based on learned patterns
                
                // 30% chance: Try a dependent sequence (if we've learned any)
                if rng.gen_bool(0.3) {
                    if let Some((prereq_ioctl, prereq_data, target_ioctl)) = fuzzer_state.smart_dedup.generate_dependent_sequence(&mut rng) {
                        // Execute prerequisite first (don't count as main iteration)
                        let prereq_input = if prereq_data.len() > args.max_size {
                            prereq_data[..args.max_size].to_vec()
                        } else {
                            prereq_data
                        };
                        
                        // Fire prerequisite IOCTL (ignore result)
                        let mut prereq_out = vec![0u8; args.max_size];
                        let _ = driver.send_ioctl(prereq_ioctl, &prereq_input, &mut prereq_out);
                        
                        // Now generate smart input for target
                        let target_input = fuzzer_state.smart_dedup.generate_smart_input(target_ioctl, &mut rng);
                        (target_ioctl, target_input, "SMART-DEP")
                    } else {
                        // No dependencies learned yet, use smart input generation
                        let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                        let input = fuzzer_state.smart_dedup.generate_smart_input(ioctl, &mut rng);
                        (ioctl, input, "SMART-GEN")
                    }
                }
                // 40% chance: Use smart input generation based on learned constraints
                else if rng.gen_bool(0.67) { // 0.4 / 0.7 remaining = ~0.57
                    let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                    let input = fuzzer_state.smart_dedup.generate_smart_input(ioctl, &mut rng);
                    (ioctl, input, "SMART-GEN")
                }
                // 30% chance: Replay promising inputs with mutations
                else if !interesting_inputs.is_empty() {
                    let idx = rng.gen_range(0..interesting_inputs.len());
                    let base = &interesting_inputs[idx];
                    let mut mutated = base.data.clone();
                    
                    // Apply targeted mutations based on what we've learned
                    let hint = fuzzer_state.smart_dedup.get_hint_for_ioctl(base.ioctl);
                    match hint {
                        learner::NtStatusHint::BufferTooSmall => {
                            // Double the size and add more data
                            let extra: Vec<u8> = (0..mutated.len()).map(|_| rng.gen::<u8>()).collect();
                            mutated.extend(extra);
                        }
                        learner::NtStatusHint::InvalidParameter => {
                            // Try different magic values at the start
                            if mutated.len() >= 4 {
                                let magic = [0x00u32, 0x01, 0x02, 0xFF, 0xFFFFFFFF, 0x80000000];
                                let m = magic[rng.gen_range(0..magic.len())];
                                mutated[0..4].copy_from_slice(&m.to_le_bytes());
                            }
                        }
                        _ => {
                            // Random mutation
                            for _ in 0..rng.gen_range(1..5) {
                                if !mutated.is_empty() {
                                    let idx = rng.gen_range(0..mutated.len());
                                    mutated[idx] = rng.gen();
                                }
                            }
                        }
                    }
                    (base.ioctl, mutated, "SMART-MUT")
                }
                else {
                    // Fallback: smart generation
                    let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                    let input = fuzzer_state.smart_dedup.generate_smart_input(ioctl, &mut rng);
                    (ioctl, input, "SMART-FB")
                }
            }
        };
        
        // Safety: cap input size to prevent issues
        let safe_input = if input.len() > args.max_size {
            input[..args.max_size].to_vec()
        } else {
            input
        };
        
        // Save last input BEFORE the IOCTL call (critical for crash analysis!)
        // If kernel BSODs, this file tells us what input caused it
        let last_input_path = args.output.join("last_input.bin");
        let last_info_path = args.output.join("last_ioctl_info.txt");
        let _ = std::fs::write(&last_input_path, &safe_input);
        // Save IOCTL info for debugging crashes
        let info = format!("IOCTL: 0x{:08X}\nTech: {}\nIter: {}\nSize: {}\nHex: {}\n",
            ioctl, technique, iterations, safe_input.len(),
            safe_input.iter().take(128).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "));
        let _ = std::fs::write(&last_info_path, &info);
        // Also save to current directory for crash analysis
        let _ = std::fs::write("last_input.bin", &safe_input);
        let _ = std::fs::write("last_ioctl_info.txt", &info);
        
        // FRESH output buffer each iteration to avoid accumulated corruption
        let mut local_output = vec![0u8; args.max_size];
        
        // Execute IOCTL with catch_unwind for safety
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            driver.send_ioctl(ioctl, &safe_input, &mut local_output)
        }));
        
        // Copy to main buffer only if IOCTL succeeded
        if result.is_ok() {
            output_buffer[..args.max_size].copy_from_slice(&local_output);
        }
        // local_output is dropped here - if corrupted, it's isolated
        
        // CHECKPOINT 1: IOCTL returned
        let _ = std::fs::write("checkpoint.txt", "1_ioctl_returned");
        
        iterations += 1;
        
        // Debug heartbeat - print every 500 iterations to track crashes
        if args.debug && iterations % 500 == 0 {
            eprintln!("[HEARTBEAT] iter={} phase={} ioctl=0x{:08X}", iterations, technique, ioctl);
            let _ = std::io::stderr().flush();
        }
        
        // Handle panic during IOCTL
        let result = match result {
            Ok(r) => r,
            Err(_) => {
                eprintln!("\n[!] Panic during IOCTL 0x{:08X} in {} phase - continuing", ioctl, technique);
                Err(-1)
            }
        };
        
        // CHECKPOINT 2: Result matched
        let _ = std::fs::write("checkpoint.txt", "2_result_matched");
        
        // Update technique stats
        let stat = technique_stats.entry(technique).or_insert((0, 0, 0));
        stat.0 += 1;
        
        let (success, error_code, bytes_ret) = match result {
            Ok(bytes) => {
                successes += 1;
                stat.1 += 1;
                (true, 0u32, bytes)
            }
            Err(code) => (false, code as u32, 0u32),
        };
        
        // ═══ SMART LEARNING (MSFuzz-style) ═══
        // Record result for NTSTATUS-guided mutation and dependency learning
        let safe_output_len = (bytes_ret as usize).min(output_buffer.len());
        fuzzer_state.smart_dedup.record_result(ioctl, &safe_input, &output_buffer[..safe_output_len], error_code);
        
        // Track dependencies between IOCTLs
        if let Some(prev_ioctl) = last_ioctl_called {
            fuzzer_state.smart_dedup.record_sequence(prev_ioctl, ioctl, &output_buffer[..safe_output_len], error_code);
        }
        last_ioctl_called = Some(ioctl);
        
        // CHECKPOINT 3: Stats updated
        let _ = std::fs::write("checkpoint.txt", format!("3_stats_ok_err={}", error_code));
        
        // Note: Error codes like 0xC0000008 (STATUS_INVALID_HANDLE) or 0x80070006 
        // are normal driver rejections - NOT reasons to stop fuzzing!
        // The handle is still valid, the driver just rejected that specific input.
        // We only stop if we literally cannot communicate with the driver anymore.
        
        // Track coverage (unique error codes)
        let is_new_error = !error_coverage.contains_key(&error_code);
        *error_coverage.entry(error_code).or_insert(0) += 1;
        
        // Calculate fitness for genetic algorithm
        let fitness = calculate_fitness(success, error_code, is_new_error, bytes_ret);
        
        // Add to population if interesting
        if fitness > 5.0 || success || is_new_error {
            let mut individual = GeneticIndividual::new(ioctl, safe_input.clone(), technique);
            individual.fitness = fitness;
            individual.error_code = error_code;
            individual.generation = generation;
            
            population.push(individual.clone());
            
            // Also track as interesting
            if is_new_error || success {
                interesting_inputs.push(individual);
                if interesting_inputs.len() > 500 {
                    interesting_inputs.remove(0);
                }
            }
            
            // Trim population
            if population.len() > population_max * 2 {
                population.sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap_or(CmpOrdering::Equal));
                population.truncate(population_max);
            }
        }
        
        // CHECKPOINT 4: Population updated
        let _ = std::fs::write("checkpoint.txt", "4_population_ok");
        
        // Update RL if in learning phase
        if phase == 0 {
            let action = rl.choose_action();
            let safe_bytes = std::cmp::min(bytes_ret as usize, output_buffer.len());
            let _ = rl.process_result(action, ioctl, error_code, success, &output_buffer[..safe_bytes], bytes_ret, false);
        }
        
        // CHECKPOINT 5: RL updated
        let _ = std::fs::write("checkpoint.txt", "5_rl_ok");
        
        // CHECKPOINT 5A: Before is_crash check
        let _ = std::fs::write("checkpoint.txt", "5a_before_crash_check");
        
        // IMPORTANT: Error codes RETURNED by DeviceIoControl are NOT crashes!
        // They just mean the driver rejected the input (which is NORMAL and SAFE).
        // A REAL driver crash would either:
        //   1. BSOD the system (kernel crash)
        //   2. Cause SEH exception in OUR process (caught by our SEH handler)
        // 
        // So we DON'T treat returned error codes as crashes - the driver is working fine!
        // We only log them as "interesting" for coverage purposes.
        let is_crash = false; // Driver returning an error code = driver handled it safely!
        
        if is_crash {
            crashes += 1;
            stat.2 += 1;
            let is_unique = unique_crashes.insert((ioctl, error_code));
            
            // Simple crash notification
            if is_unique {
                println!("\n[!] 💀 CRASH | IOCTL 0x{:08X} | {} | {} | {}b | UNIQUE 🆕",
                         ioctl, error_name(error_code), technique, safe_input.len());
                save_crash(&args.output, ioctl, &safe_input, error_code);
                
                // Save PoC
                let poc = poc_gen.generate_single_poc(ioctl, &safe_input);
                let poc_path = args.output.join(format!("ultimate_crash_0x{:08X}_{}_poc.py", ioctl, technique));
                if let Ok(mut f) = std::fs::File::create(&poc_path) {
                    let _ = f.write_all(poc.as_bytes());
                }
                
                // Add to race candidates for further testing
                race_candidates.push((ioctl, safe_input.clone()));
            }
        }
        
        // Silent new coverage - shown in status line (no spam)
        
        // CHECKPOINT 6: Before status print
        let _ = std::fs::write("checkpoint.txt", "6_before_status");
        
        // Status update - single line with \r
        if last_print.elapsed().as_secs() >= 1 {
            let elapsed = start_time.elapsed();
            // Protect against divide-by-zero in early iterations
            let eps = iterations as f64 / elapsed.as_secs_f64().max(0.001);
            let (dedup_crashes, _, dedup_deps) = fuzzer_state.smart_dedup.stats();
            
            print!("\r[{}] ⚡{:<10} | {:>10} iter | 💀{} ({} uniq/{} dedup) | ✓{} | {}cov | {}deps | gen{} | pop{} | {:.0}/s          ",
                   format!("{:02}:{:02}:{:02}", 
                           elapsed.as_secs() / 3600,
                           (elapsed.as_secs() % 3600) / 60,
                           elapsed.as_secs() % 60).cyan(),
                   phases[phase],
                   iterations,
                   crashes,
                   unique_crashes.len(),
                   dedup_crashes,
                   successes,
                   error_coverage.len(),
                   dedup_deps,
                   generation,
                   population.len(),
                   eps);
            
            let _ = std::io::stdout().flush();
            last_print = Instant::now();
        }
        
        // CHECKPOINT 7: After status print
        let _ = std::fs::write("checkpoint.txt", "7_after_status");
        
        // Auto-save ALL learning periodically (silent)
        if args.save_interval > 0 && iterations % args.save_interval == 0 && iterations > 0 {
            // Also save every 5 minutes regardless
            if last_save.elapsed().as_secs() >= 300 || iterations % args.save_interval == 0 {
                // Save RL model (separate for backwards compat)
                if let Err(e) = rl.save_model(&model_save_path) {
                    eprintln!("\n{} Failed to save RL model: {}", "[!]".yellow(), e);
                }
                // Save ALL learning to one file
                fuzzer_state.iterations = iterations;
                fuzzer_state.generation = generation;
                fuzzer_state.population = population.iter().map(|ind| learner::SavedIndividual {
                    ioctl: ind.ioctl,
                    data: ind.data.clone(),
                    pattern: ind.pattern.clone(),
                    fitness: ind.fitness,
                    generation: ind.generation,
                    error_code: ind.error_code,
                }).collect();
                fuzzer_state.interesting_inputs = interesting_inputs.iter().map(|ind| learner::SavedIndividual {
                    ioctl: ind.ioctl,
                    data: ind.data.clone(),
                    pattern: ind.pattern.clone(),
                    fitness: ind.fitness,
                    generation: ind.generation,
                    error_code: ind.error_code,
                }).collect();
                if let Err(e) = fuzzer_state.save(&state_path) {
                    eprintln!("\n{} Failed to save FuzzerState: {}", "[!]".yellow(), e);
                }
                last_save = Instant::now();
            }
        }
        
        // CHECKPOINT 8: End of iteration
        let _ = std::fs::write("checkpoint.txt", format!("8_iter_end_{}", iterations));
        
        None // No exit reason, continue looping
        })); // End of catch_unwind closure
        
        // CHECKPOINT 9: After catch_unwind
        let _ = std::fs::write("checkpoint.txt", "9_after_catch_unwind");
        
        // Handle iteration result
        match iteration_result {
            Ok(Some(reason)) => {
                exit_reason = reason;
                break;
            }
            Ok(None) => {
                // Normal iteration, continue
            }
            Err(panic_info) => {
                // Panic occurred - log it and continue
                eprintln!("\n[!] PANIC in iteration {} - recovering and continuing", iterations);
                iterations += 1;
                // Don't break - try to continue fuzzing
            }
        }
    }
    
    // DEBUG: We exited the loop - print immediately!
    eprintln!("\n[DEBUG] Exited main loop at iteration {}", iterations);
    eprintln!("[DEBUG] running={}, exit_reason={}", running.load(Ordering::SeqCst), exit_reason);
    
    // Determine exit reason
    if !running.load(Ordering::SeqCst) && exit_reason == "unknown" {
        exit_reason = "ctrl_c_or_signal";
    }
    
    // Save model silently on exit
    let _ = rl.save_model(&model_save_path);
    
    // Compact final report
    let elapsed = start_time.elapsed();
    let eps = iterations as f64 / elapsed.as_secs_f64();
    println!("\n\n[+] DONE ({}) | {:02}:{:02}:{:02} | {} iter | 💀{} ({} uniq) | ✓{} | {}cov | {:.0}/s",
             exit_reason.yellow(),
             elapsed.as_secs() / 3600,
             (elapsed.as_secs() % 3600) / 60,
             elapsed.as_secs() % 60,
             iterations, crashes, unique_crashes.len(), successes, error_coverage.len(), eps);
    
    if !unique_crashes.is_empty() {
        println!("\n[!] 💀 UNIQUE CRASHES:");
        for (ioctl, err) in &unique_crashes {
            println!("    IOCTL 0x{:08X} → 0x{:08X} ({})", ioctl, err, error_name(*err));
        }
        println!("    Saved to: {}", args.output.display());
    }
}

/// Apply UAF/memory corruption mutations
fn apply_uaf_mutation(input: &[u8], rng: &mut rand::rngs::StdRng) -> Vec<u8> {
    use rand::Rng;
    let mut data = input.to_vec();
    if data.is_empty() {
        return data;
    }
    
    // Apply corruption
    match rng.gen_range(0..10) {
        0 if data.len() >= 4 => {
            // Huge size (integer overflow)
            data[0..4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        }
        1 if data.len() >= 4 => {
            // Negative size
            data[0..4].copy_from_slice(&0x80000000u32.to_le_bytes());
        }
        2 if data.len() >= 8 => {
            // Null pointer
            let idx = (rng.gen_range(0..data.len()) / 8) * 8;
            if idx + 8 <= data.len() {
                data[idx..idx+8].fill(0);
            }
        }
        3 if data.len() >= 8 => {
            // Dangling pointer (user-mode address)
            let idx = (rng.gen_range(0..data.len()) / 8) * 8;
            if idx + 8 <= data.len() {
                data[idx..idx+8].copy_from_slice(&0x0000000041414141u64.to_le_bytes());
            }
        }
        4 if data.len() >= 8 => {
            // Kernel address (invalid)
            let idx = (rng.gen_range(0..data.len()) / 8) * 8;
            if idx + 8 <= data.len() {
                data[idx..idx+8].copy_from_slice(&0xFFFF800000000000u64.to_le_bytes());
            }
        }
        5 if data.len() >= 4 => {
            // Zero count/size
            let idx = (rng.gen_range(0..data.len()) / 4) * 4;
            if idx + 4 <= data.len() {
                data[idx..idx+4].fill(0);
            }
        }
        6 => {
            // Double-free pattern: duplicate handle-like values
            if data.len() >= 16 {
                let handle: u64 = 0x0000000000000100;
                data[0..8].copy_from_slice(&handle.to_le_bytes());
                data[8..16].copy_from_slice(&handle.to_le_bytes());
            }
        }
        7 if data.len() >= 8 => {
            // Type confusion: set type to invalid
            let len = data.len();
            if len >= 8 {
                data[4..8].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
            }
        }
        8 => {
            // Overflow buffer
            data.extend(vec![0x41u8; 1024]);
        }
        _ => {
            // Random corruption at multiple points
            for _ in 0..rng.gen_range(1..4) {
                let idx = rng.gen_range(0..data.len());
                data[idx] = rng.gen();
            }
        }
    }
    
    data
}

/// Calculate fitness for genetic algorithm
fn calculate_fitness(success: bool, error_code: u32, is_new_error: bool, bytes_ret: u32) -> f64 {
    let mut fitness = 0.0;
    
    if success {
        fitness += 50.0;
        fitness += (bytes_ret as f64).min(100.0) * 0.5; // More output = more interesting
    }
    
    if is_new_error {
        fitness += 100.0;
    }
    
    // Interesting error codes get bonus
    match error_code {
        0xC0000005 => fitness += 1000.0, // ACCESS_VIOLATION
        0xC0000374 => fitness += 1000.0, // HEAP_CORRUPTION
        0xC0000409 => fitness += 1000.0, // STACK_BUFFER_OVERRUN
        0xC000001D => fitness += 500.0,  // ILLEGAL_INSTRUCTION
        0x80070057 => fitness += 20.0,   // INVALID_PARAMETER (got past validation)
        0x8007007A => fitness += 30.0,   // BUFFER_TOO_SMALL (got past validation)
        _ => {}
    }
    
    fitness
}

/// Evolve genetic population
fn evolve_population(
    population: &mut Vec<GeneticIndividual>,
    rng: &mut rand::rngs::StdRng,
    max_size: usize
) {
    use rand::Rng;
    use std::cmp::Ordering as CmpOrdering;
    
    // Safety: need at least 2 for crossover
    if population.len() < 2 {
        return;
    }
    
    // Sort by fitness (handle NaN safely)
    population.sort_by(|a, b| {
        match (a.fitness.is_nan(), b.fitness.is_nan()) {
            (true, true) => CmpOrdering::Equal,
            (true, false) => CmpOrdering::Less,
            (false, true) => CmpOrdering::Greater,
            (false, false) => b.fitness.partial_cmp(&a.fitness).unwrap_or(CmpOrdering::Equal),
        }
    });
    
    // Keep top 50% but at least 2, and ensure we don't exceed current size
    let keep = (population.len() / 2).max(2).min(population.len());
    population.truncate(keep);
    
    // Generate children (with safety checks)
    let mut children = Vec::new();
    let target_size = max_size.min(500); // Cap population size
    
    let mut child_count = 0;
    while population.len() + children.len() < target_size {
        // Safety: double-check we have parents
        if population.is_empty() {
            break;
        }
        
        // Safe index generation
        let pop_len = population.len();
        if pop_len < 2 {
            break;
        }
        
        let idx1 = rng.gen_range(0..pop_len);
        let idx2 = rng.gen_range(0..pop_len);
        let parent1 = &population[idx1.min(idx2)];
        
        let idx3 = rng.gen_range(0..pop_len);
        let idx4 = rng.gen_range(0..pop_len);
        let parent2 = &population[idx3.min(idx4)];
        
        // Safe crossover
        let mut child = parent1.crossover(parent2, rng);
        
        // Mutate with 80% probability
        if rng.gen_bool(0.8) {
            child.mutate(rng);
        }
        
        children.push(child);
        child_count += 1;
        
        // Safety: don't loop forever
        if children.len() > 1000 {
            break;
        }
    }
    
    population.extend(children);
    
    // Final safety: cap size
    if population.len() > 500 {
        population.truncate(500);
    }
}

/// Get human-readable error name
fn error_name(code: u32) -> &'static str {
    match code {
        0 => "SUCCESS",
        0xC0000005 => "ACCESS_VIOLATION",
        0xC0000374 => "HEAP_CORRUPTION",
        0xC0000409 => "STACK_BUFFER_OVERRUN",
        0xC000001D => "ILLEGAL_INSTRUCTION",
        0xC0000420 => "ASSERTION_FAILURE",
        0x80000002 => "DATATYPE_MISALIGN",
        0xC000009D => "DEVICE_NOT_CONNECTED",
        0xC0000008 => "INVALID_HANDLE",
        0xC0000006 => "IN_PAGE_ERROR",
        0x80070005 => "ACCESS_DENIED",
        0x80070057 => "INVALID_PARAMETER",
        0x8007007A => "BUFFER_TOO_SMALL",
        0x800703E6 => "NOACCESS",
        0x80070006 => "INVALID_HANDLE_VALUE",
        0x80070001 => "INVALID_FUNCTION",
        _ => "UNKNOWN",
    }
}

// ============================================================================
// TCP TWO-AGENT FUZZING
// ============================================================================

/// Deep scan IOCTLs via TCP (connects to executor in VM)
/// Uses BATCH SCANNING for 10-50x speedup!
fn deep_scan_ioctls_tcp(tcp: &mut TcpDriverIO) -> Vec<u32> {
    println!("[TCP] 🚀 FAST BATCH SCAN: Scanning IOCTL space with batching...");
    
    let mut found = Vec::new();
    let test_input = vec![0u8; 64];
    
    let device_types: Vec<u32> = vec![
        0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A,
        0x000B, 0x000C, 0x000D, 0x000E, 0x000F, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014,
        0x0015, 0x0016, 0x0017, 0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E,
        0x001F, 0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027, 0x0028,
        0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F, 0x0030, 0x0031, 0x0032,
        0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003A, 0x003B, 0x003C,
        0x8000, 0x8001, 0x8002, 0x8003, 0x8004, 0x8005, 0x8010, 0x8020, 0x8050,
    ];
    
    let total_device_types = device_types.len();
    let start_time = std::time::Instant::now();
    let mut total_scanned: u64 = 0;
    
    // Batch size - send 500 IOCTLs per request
    const BATCH_SIZE: usize = 500;
    
    for (dt_idx, &device_type) in device_types.iter().enumerate() {
        // Build all IOCTLs for this device type
        let mut batch: Vec<u32> = Vec::with_capacity(BATCH_SIZE);
        
        for function in 0u32..=0x0FFF {
            for method in 0u32..=3 {
                for access in 0u32..=3 {
                    let ioctl = (device_type << 16) | (access << 14) | (function << 2) | method;
                    batch.push(ioctl);
                    
                    // Send batch when full
                    if batch.len() >= BATCH_SIZE {
                        total_scanned += batch.len() as u64;
                        
                        match tcp.batch_scan(&batch, &test_input) {
                            Ok(successes) => {
                                for ioctl in successes {
                                    if !found.contains(&ioctl) {
                                        found.push(ioctl);
                                    }
                                }
                            }
                            Err(e) => {
                                // Batch failed - executor may have crashed
                                println!("\n[TCP] 💥 Batch scan failed: {} - reconnecting...", e);
                                if !tcp.reconnect() {
                                    println!("[TCP] Failed to reconnect, returning partial results");
                                    return found;
                                }
                            }
                        }
                        
                        batch.clear();
                        
                        // Progress update
                        let elapsed = start_time.elapsed().as_secs_f32();
                        let rate = total_scanned as f32 / elapsed.max(0.001);
                        print!("\r[TCP] DevType {}/{} | Scanned: {} | Found: {} | {:.0}/sec          ", 
                               dt_idx + 1, total_device_types, total_scanned, found.len(), rate);
                        let _ = std::io::stdout().flush();
                    }
                }
            }
        }
        
        // Send remaining IOCTLs in batch
        if !batch.is_empty() {
            total_scanned += batch.len() as u64;
            if let Ok(successes) = tcp.batch_scan(&batch, &test_input) {
                for ioctl in successes {
                    if !found.contains(&ioctl) {
                        found.push(ioctl);
                    }
                }
            }
        }
    }
    
    let elapsed = start_time.elapsed();
    let rate = total_scanned as f32 / elapsed.as_secs_f32().max(0.001);
    println!("\r[TCP] FAST SCAN complete: {} IOCTLs found | {} scanned in {:.1}s ({:.0}/s)          ", 
             found.len(), total_scanned, elapsed.as_secs_f32(), rate);
    
    found.sort();
    found
}

/// Ultimate fuzzing via TCP (two-agent: controller on host, executor in VM)
fn run_ultimate_fuzzing_tcp(tcp: &mut TcpDriverIO, ioctls: &[u32], args: &Args) {
    use rand::{Rng, SeedableRng};
    use rand::seq::SliceRandom;
    use rl_fuzzer::{RLFuzzer, PatternType};
    use std::collections::{HashMap, HashSet};
    use std::cmp::Ordering as CmpOrdering;
    
    println!("\n[TCP] ⚡ ULTIMATE FUZZER (TCP) | {} IOCTLs | Crash detection via disconnect", ioctls.len());
    
    // Detect target and get format patterns
    let device = args.device.clone().unwrap_or_default().to_lowercase();
    let format_patterns: Vec<PatternType> = if device.contains("ahcache") {
        vec![
            PatternType::AhcacheQuery, 
            PatternType::AhcacheLookup, 
            PatternType::AhcacheNotify,
            PatternType::UnicodeString,
            PatternType::SdbHeader, 
            PatternType::SdbMalformed, 
            PatternType::SdbTagFuzz,
            PatternType::StructuredHeader,
            PatternType::SizePrefix,
        ]
    } else {
        PatternType::all()
    };
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        if r.swap(false, Ordering::SeqCst) {
            println!("\n{}", "[!] Stopping TCP fuzzer...".yellow());
        }
    }).ok();
    
    let mut rl = RLFuzzer::new(ioctls.to_vec());
    let device_str = args.device.clone().unwrap_or_default();
    let poc_gen = PocGenerator::new(&device_str, None);
    let mut rng = rand::rngs::StdRng::seed_from_u64(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    );
    
    std::fs::create_dir_all(&args.output).ok();
    
    // Setup model save path for RL learning persistence
    let model_save_path = args.output.join("rl_model.bin");
    let mut last_save = Instant::now();
    
    // Load saved model if provided
    if let Some(ref model_path) = args.load_model {
        if rl.load_model(model_path).is_ok() {
            println!("[TCP] Loaded RL model from: {}", model_path.display());
        }
    }
    
    let start_time = Instant::now();
    let mut last_print = Instant::now();
    
    let mut iterations = 0u64;
    let mut crashes = 0u64;
    let mut successes = 0u64;
    let mut executor_crashes = 0u64;
    let mut info_leaks = 0u64;  // NEW: Track info leak discoveries
    let mut unique_crashes: HashSet<String> = HashSet::new();
    let mut error_coverage: HashMap<u32, u64> = HashMap::new();
    
    let mut population: Vec<GeneticIndividual> = Vec::new();
    let population_max = 100;
    let mut generation = 0u32;
    let mut interesting_inputs: Vec<GeneticIndividual> = Vec::new();
    
    let mut phase = 0;
    let phase_duration = 50000u64;
    let mut phase_start = 0u64;
    let phases = ["FORMAT-RL", "GENETIC", "UAF-HUNT", "INTENSIVE", "ADAPTIVE", "SMART"];
    
    // FuzzerState - ALL learning in ONE file (auto-load if exists)
    let state_path = args.output.join("fuzzer_state.bin");
    let mut fuzzer_state = if state_path.exists() {
        match learner::FuzzerState::load(&state_path) {
            Ok(loaded) => {
                println!("[TCP] Loaded FuzzerState: {}", loaded.stats());
                loaded
            }
            Err(e) => {
                eprintln!("[TCP] Failed to load FuzzerState ({}), starting fresh", e);
                learner::FuzzerState::new()
            }
        }
    } else {
        learner::FuzzerState::new()
    };
    fuzzer_state.smart_dedup.init_ioctls(ioctls);
    let mut last_ioctl_called: Option<u32> = None;
    
    // Current IOCTL being tested (for crash tracking)
    let mut current_ioctl: u32 = 0;
    let mut current_input: Vec<u8> = Vec::new();
    let mut current_technique: &str = "";
    
    while running.load(Ordering::SeqCst) {
        if args.iterations > 0 && iterations >= args.iterations {
            break;
        }
        
        // Phase transitions
        if iterations >= phase_start + phase_duration {
            phase = (phase + 1) % phases.len();
            phase_start = iterations;
            
            if phase == 1 && population.len() >= 2 {
                generation += 1;
                if population.len() > 150 {
                    population.sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap_or(CmpOrdering::Equal));
                    population.truncate(100);
                }
                evolve_population(&mut population, &mut rng, population_max);
            }
        }
        
        // Generate input based on phase (same as local version)
        let (ioctl, input, technique) = match phase {
            0 => {
                let action = rl.choose_action();
                let (ioctl, mut input) = rl.action_to_input(&action);
                if rng.gen_bool(0.7) {
                    let pattern = format_patterns.choose(&mut rng).unwrap();
                    input = pattern.generate(rng.gen_range(32..1024), &mut rng);
                }
                (ioctl, input, "FORMAT-RL")
            }
            1 => {
                if population.is_empty() {
                    let pattern = format_patterns.choose(&mut rng).unwrap();
                    let ioctl = ioctls.get(0).copied().unwrap_or(0x220000);
                    (ioctl, pattern.generate(256, &mut rng), "GENETIC")
                } else if population.len() >= 2 && rng.gen_bool(0.6) {
                    let idx1 = rng.gen_range(0..population.len());
                    let idx2 = rng.gen_range(0..population.len());
                    let mut child = population[idx1].crossover(&population[idx2], &mut rng);
                    if rng.gen_bool(0.8) { child.mutate(&mut rng); }
                    if child.data.is_empty() { child.data = vec![0u8; 64]; }
                    (child.ioctl, child.data.clone(), "GENETIC")
                } else {
                    let pattern = format_patterns.choose(&mut rng).unwrap();
                    let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                    (ioctl, pattern.generate(rng.gen_range(32..512), &mut rng), "GENETIC")
                }
            }
            2 => {
                // UAF-HUNT: HEVD-specific sequence or generic UAF mutations
                if device.contains("hacksys") || device.contains("hevd") {
                    // HEVD NonPagedPoolNx UAF IOCTLs
                    const HEVD_ALLOC: u32 = 0x22201F;
                    const HEVD_FREE: u32 = 0x222027;
                    const HEVD_USE: u32 = 0x222023;
                    
                    let alloc_input = vec![0x41u8; 64];
                    let free_input = vec![0x42u8; 64];
                    let use_input: Vec<u8> = (0..64).map(|_| rng.gen::<u8>()).collect();
                    
                    // Execute Allocate→Free sequence via TCP
                    let _ = tcp.send_ioctl(HEVD_ALLOC, &alloc_input);
                    let _ = tcp.send_ioctl(HEVD_FREE, &free_input);
                    // Return Use IOCTL for crash detection
                    (HEVD_USE, use_input, "UAF-HEVD")
                } else {
                    let base = if !interesting_inputs.is_empty() && rng.gen_bool(0.7) {
                        interesting_inputs[rng.gen_range(0..interesting_inputs.len())].data.clone()
                    } else {
                        format_patterns.choose(&mut rng).unwrap().generate(256, &mut rng)
                    };
                    let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                    (ioctl, apply_uaf_mutation(&base, &mut rng), "UAF-HUNT")
                }
            }
            3 => {
                let base = if !interesting_inputs.is_empty() {
                    interesting_inputs[rng.gen_range(0..interesting_inputs.len())].data.clone()
                } else {
                    format_patterns.choose(&mut rng).unwrap().generate(256, &mut rng)
                };
                let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                let mut mutated = base;
                for _ in 0..rng.gen_range(1..5) {
                    if !mutated.is_empty() {
                        let idx = rng.gen_range(0..mutated.len());
                        mutated[idx] = rng.gen();
                    }
                }
                (ioctl, mutated, "INTENSIVE")
            }
            4 => {
                let pattern = format_patterns.choose(&mut rng).unwrap();
                let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                (ioctl, pattern.generate(rng.gen_range(32..1024), &mut rng), "ADAPTIVE")
            }
            _ => {
                // SMART phase: MSFuzz-style learned fuzzing
                if rng.gen_bool(0.3) {
                    if let Some((prereq_ioctl, prereq_data, target_ioctl)) = fuzzer_state.smart_dedup.generate_dependent_sequence(&mut rng) {
                        // Execute prerequisite first
                        let _ = tcp.send_ioctl(prereq_ioctl, &prereq_data);
                        let target_input = fuzzer_state.smart_dedup.generate_smart_input(target_ioctl, &mut rng);
                        (target_ioctl, target_input, "SMART-DEP")
                    } else {
                        let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                        (ioctl, fuzzer_state.smart_dedup.generate_smart_input(ioctl, &mut rng), "SMART-GEN")
                    }
                } else if rng.gen_bool(0.67) {
                    let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                    (ioctl, fuzzer_state.smart_dedup.generate_smart_input(ioctl, &mut rng), "SMART-GEN")
                } else if !interesting_inputs.is_empty() {
                    let idx = rng.gen_range(0..interesting_inputs.len());
                    let base = &interesting_inputs[idx];
                    let mut mutated = base.data.clone();
                    for _ in 0..rng.gen_range(1..3) {
                        if !mutated.is_empty() {
                            let idx = rng.gen_range(0..mutated.len());
                            mutated[idx] = rng.gen();
                        }
                    }
                    (base.ioctl, mutated, "SMART-MUT")
                } else {
                    let ioctl = ioctls[rng.gen_range(0..ioctls.len().max(1))];
                    (ioctl, fuzzer_state.smart_dedup.generate_smart_input(ioctl, &mut rng), "SMART-FB")
                }
            }
        };
        
        // Cap input size
        let safe_input = if input.len() > args.max_size {
            input[..args.max_size].to_vec()
        } else {
            input
        };
        
        // Save current state BEFORE sending (for crash tracking)
        current_ioctl = ioctl;
        current_input = safe_input.clone();
        current_technique = technique;
        
        // Save to disk
        let info = format!("IOCTL: 0x{:08X}\nTech: {}\nIter: {}\nSize: {}\nHex: {}\n",
            ioctl, technique, iterations, safe_input.len(),
            safe_input.iter().take(128).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "));
        let _ = std::fs::write(args.output.join("last_ioctl_info.txt"), &info);
        let _ = std::fs::write(args.output.join("last_input.bin"), &safe_input);
        
        // Send IOCTL via TCP
        let result = tcp.send_ioctl(ioctl, &safe_input);
        iterations += 1;
        
        // CHECK FOR EXECUTOR CRASH (connection dropped)
        if result.executor_crashed {
            executor_crashes += 1;
            
            // Wait for executor to restart FIRST to measure time
            // Use \n first to clear the status line that uses \r
            println!("\n[TCP] Waiting for executor to restart...");
            let reconnected = tcp.reconnect_with_flag(Some(&running));
            
            // Classify: fast reconnect = executor crash, slow = BSOD
            let is_bsod = tcp.was_likely_bsod();
            let reconnect_secs = tcp.last_reconnect_time_secs;
            
            // Only count as real crash if it looks like BSOD
            let crash_id = format!("0x{:08X}_{}", current_ioctl, current_input.len());
            let is_unique = !unique_crashes.contains(&crash_id);
            
            if is_bsod && is_unique {
                unique_crashes.insert(crash_id.clone());
                crashes += 1;
                
                println!("\n");
                println!("╔══════════════════════════════════════════════════════════════╗");
                println!("║              ☠️  KERNEL BSOD DETECTED! ☠️                      ║");
                println!("╚══════════════════════════════════════════════════════════════╝");
                println!("[!] IOCTL: 0x{:08X}", current_ioctl);
                println!("[!] Tech:  {}", current_technique);
                println!("[!] Size:  {} bytes", current_input.len());
                println!("[!] Iter:  {}", iterations);
                println!("[!] Reconnect time: {}s (>15s = BSOD)", reconnect_secs);
                
                // Save crash
                let crash_dir = args.output.join(format!("BSOD_{}", crash_id));
                std::fs::create_dir_all(&crash_dir).ok();
                let _ = std::fs::write(crash_dir.join("input.bin"), &current_input);
                let info = format!(
                    "KERNEL BSOD\nIOCTL: 0x{:08X}\nTechnique: {}\nSize: {} bytes\nIteration: {}\nReconnect: {}s\n",
                    current_ioctl, current_technique, current_input.len(), iterations, reconnect_secs
                );
                let _ = std::fs::write(crash_dir.join("info.txt"), &info);
                
                // Generate PoC
                let poc = poc_gen.generate_single_poc(current_ioctl, &current_input);
                let _ = std::fs::write(crash_dir.join("poc.py"), &poc);
                
                println!("[+] 🔥 REAL CRASH saved to: {}", crash_dir.display());
            } else if !is_bsod {
                // False positive - executor crashed, not kernel
                println!("\n[~] Executor crash (not BSOD) - reconnected in {}s", reconnect_secs);
            } else {
                println!("\n[!] Duplicate BSOD: IOCTL 0x{:08X}", current_ioctl);
            }
            
            if !reconnected {
                println!("[TCP] Failed to reconnect after {} attempts, stopping", 100);
                break;
            }
            println!("[TCP] Reconnected! Continuing fuzzing...\n");
            continue;
        }
        
        // Process normal result
        let (success, error_code) = (result.success, result.ntstatus);
        
        if success {
            successes += 1;
        }
        
        // 🔍 CHECK FOR INFO LEAKS (kernel pointers in output)
        if let Some(leak) = result.check_info_leak(&safe_input) {
            info_leaks += 1;
            println!("\n");
            println!("╔══════════════════════════════════════════════════════════════╗");
            println!("║              🔓 INFO LEAK DETECTED! 🔓                       ║");
            println!("╚══════════════════════════════════════════════════════════════╝");
            println!("[!] IOCTL: 0x{:08X}", ioctl);
            println!("[!] Leak offset: 0x{:X}", leak.offset);
            println!("[!] Value: 0x{:016X}", leak.value);
            println!("[!] Type: {}", leak.likely_type);
            println!("[!] This is an EXPLOITABLE primitive (ASLR bypass)!");
            
            // Save info leak
            let leak_dir = args.output.join(format!("LEAK_0x{:08X}_{}", ioctl, leak.offset));
            std::fs::create_dir_all(&leak_dir).ok();
            let _ = std::fs::write(leak_dir.join("input.bin"), &safe_input);
            let _ = std::fs::write(leak_dir.join("output.bin"), &result.output);
            let info = format!(
                "INFO LEAK\nIOCTL: 0x{:08X}\nLeak offset: 0x{:X}\nLeak value: 0x{:016X}\nLeak type: {}\nOutput size: {} bytes\n",
                ioctl, leak.offset, leak.value, leak.likely_type, result.bytes_returned
            );
            let _ = std::fs::write(leak_dir.join("info.txt"), &info);
            
            // Generate PoC
            let poc = poc_gen.generate_single_poc(ioctl, &safe_input);
            let _ = std::fs::write(leak_dir.join("poc.py"), &poc);
            
            println!("[+] 🔑 Info leak saved to: {}", leak_dir.display());
        }
        
        let is_new_error = !error_coverage.contains_key(&error_code);
        *error_coverage.entry(error_code).or_insert(0) += 1;
        
        let fitness = calculate_fitness(success, error_code, is_new_error, result.bytes_returned);
        
        if fitness > 5.0 || success || is_new_error {
            let mut individual = GeneticIndividual::new(ioctl, safe_input.clone(), technique);
            individual.fitness = fitness;
            individual.error_code = error_code;
            individual.generation = generation;
            
            population.push(individual.clone());
            
            if is_new_error || success {
                interesting_inputs.push(individual);
                if interesting_inputs.len() > 500 {
                    interesting_inputs.remove(0);
                }
            }
            
            if population.len() > population_max * 2 {
                population.sort_by(|a, b| b.fitness.partial_cmp(&a.fitness).unwrap_or(CmpOrdering::Equal));
                population.truncate(population_max);
            }
        }
        
        // Update RL
        if phase == 0 {
            let action = rl.choose_action();
            let _ = rl.process_result(action, ioctl, error_code, success, &result.output, result.bytes_returned, false);
        }
        
        // Update SmartDedup learning
        fuzzer_state.smart_dedup.record_result(ioctl, &safe_input, &result.output, error_code);
        if let Some(prev_ioctl) = last_ioctl_called {
            fuzzer_state.smart_dedup.record_sequence(prev_ioctl, ioctl, &result.output, error_code);
        }
        last_ioctl_called = Some(ioctl);
        
        // Auto-save ALL learning periodically
        if last_save.elapsed().as_secs() >= 300 {
            // Save RL model (separate for backwards compat)
            if let Err(e) = rl.save_model(&model_save_path) {
                eprintln!("\n[!] Failed to save RL model: {}", e);
            }
            // Save ALL learning to one file
            fuzzer_state.iterations = iterations;
            fuzzer_state.generation = generation;
            fuzzer_state.population = population.iter().map(|ind| learner::SavedIndividual {
                ioctl: ind.ioctl,
                data: ind.data.clone(),
                pattern: ind.pattern.clone(),
                fitness: ind.fitness,
                generation: ind.generation,
                error_code: ind.error_code,
            }).collect();
            fuzzer_state.interesting_inputs = interesting_inputs.iter().map(|ind| learner::SavedIndividual {
                ioctl: ind.ioctl,
                data: ind.data.clone(),
                pattern: ind.pattern.clone(),
                fitness: ind.fitness,
                generation: ind.generation,
                error_code: ind.error_code,
            }).collect();
            if let Err(e) = fuzzer_state.save(&state_path) {
                eprintln!("\n[!] Failed to save FuzzerState: {}", e);
            }
            last_save = Instant::now();
        }
        
        // Status update
        if last_print.elapsed().as_secs() >= 1 {
            let elapsed = start_time.elapsed();
            let eps = iterations as f64 / elapsed.as_secs_f64().max(0.001);
            
            print!("\r[TCP] ⚡{:<10} | {:>10} iter | 💥{} crash | 💀{} BSOD | 🔓{} leaks | ✓{} | {}cov | {:.0}/s          ",
                   phases[phase],
                   iterations,
                   executor_crashes,
                   unique_crashes.len(),
                   info_leaks,
                   successes,
                   error_coverage.len(),
                   eps);
            let _ = std::io::stdout().flush();
            last_print = Instant::now();
        }
    }
    
    // Final report
    let elapsed = start_time.elapsed();
    let eps = iterations as f64 / elapsed.as_secs_f64().max(0.001);
    println!("\n\n[TCP] DONE | {:02}:{:02}:{:02} | {} iter | 💥{} crash | 💀{} BSOD | 🔓{} leaks | ✓{} | {:.0}/s",
             elapsed.as_secs() / 3600,
             (elapsed.as_secs() % 3600) / 60,
             elapsed.as_secs() % 60,
             iterations, executor_crashes, unique_crashes.len(), info_leaks, successes, eps);
    
    if !unique_crashes.is_empty() {
        println!("\n[!] 💥 UNIQUE CRASHES (driver killed executor):");
        for crash_id in &unique_crashes {
            println!("    {}", crash_id);
        }
        println!("    Saved to: {}", args.output.display());
    }
    
    // Save RL model on exit
    if let Err(e) = rl.save_model(&model_save_path) {
        eprintln!("[!] Failed to save RL model: {}", e);
    } else {
        println!("[+] RL model saved to: {}", model_save_path.display());
    }
}