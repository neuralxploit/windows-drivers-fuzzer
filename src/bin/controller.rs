//! Controller - Runs on HOST, sends IOCTL commands to executor in VM, tracks crashes
//! 
//! Usage: controller.exe --target 192.168.1.100:9999 --ioctls ioctls.txt

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use std::fs;
use rand::Rng;
use rand::seq::SliceRandom;

const PROTOCOL_VERSION: u8 = 1;
const CMD_PING: u8 = 0x01;
const CMD_IOCTL: u8 = 0x02;
const CMD_SHUTDOWN: u8 = 0xFF;

const RESP_OK: u8 = 0x00;
const RESP_ERROR: u8 = 0x01;
const RESP_PONG: u8 = 0x02;

// Fuzzing configuration
const MAX_INPUT_SIZE: usize = 4096;
const MUTATION_ROUNDS: usize = 10;
const RECONNECT_DELAY_MS: u64 = 2000;
const MAX_RECONNECT_ATTEMPTS: u32 = 100;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    let mut target = String::from("192.168.1.100:9999");
    let mut ioctls_file = String::from("ioctls.txt");
    let mut output_dir = String::from("crashes");
    let mut mode = String::from("smart");
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" | "-t" => {
                if i + 1 < args.len() {
                    target = args[i + 1].clone();
                    i += 1;
                }
            }
            "--ioctls" | "-i" => {
                if i + 1 < args.len() {
                    ioctls_file = args[i + 1].clone();
                    i += 1;
                }
            }
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    output_dir = args[i + 1].clone();
                    i += 1;
                }
            }
            "--mode" | "-m" => {
                if i + 1 < args.len() {
                    mode = args[i + 1].clone();
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("Controller - IOCTL Fuzzer Master");
                println!("Runs on host, controls executor in VM\n");
                println!("Usage: controller.exe [OPTIONS]");
                println!("  --target, -t <IP:PORT>   Executor address (default: 192.168.1.100:9999)");
                println!("  --ioctls, -i <FILE>      IOCTL list file (default: ioctls.txt)");
                println!("  --output, -o <DIR>       Crash output directory (default: crashes)");
                println!("  --mode, -m <MODE>        Fuzzing mode: smart, random, sequential (default: smart)");
                println!("  --help, -h               Show this help");
                return;
            }
            _ => {}
        }
        i += 1;
    }
    
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║          CONTROLLER - Kernel Driver Fuzzing Master         ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    
    // Load IOCTLs
    let ioctls = match load_ioctls(&ioctls_file) {
        Ok(list) => list,
        Err(e) => {
            eprintln!("[!] Failed to load IOCTLs from {}: {}", ioctls_file, e);
            std::process::exit(1);
        }
    };
    
    println!("[+] Loaded {} IOCTLs from {}", ioctls.len(), ioctls_file);
    println!("[*] Target: {}", target);
    println!("[*] Mode: {}", mode);
    println!("[*] Output: {}", output_dir);
    println!();
    
    // Create output directory
    fs::create_dir_all(&output_dir).ok();
    
    // Start fuzzing
    let mut fuzzer = Fuzzer::new(target, ioctls, output_dir, mode);
    fuzzer.run();
}

fn load_ioctls(path: &str) -> Result<Vec<u32>, String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    
    let mut ioctls = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        // Parse hex (0x...) or decimal
        let value = if line.starts_with("0x") || line.starts_with("0X") {
            u32::from_str_radix(&line[2..], 16)
        } else {
            line.parse::<u32>()
        };
        
        if let Ok(v) = value {
            ioctls.push(v);
        }
    }
    
    Ok(ioctls)
}

struct Fuzzer {
    target: String,
    ioctls: Vec<u32>,
    output_dir: String,
    mode: String,
    
    // Stats
    total_execs: u64,
    crashes: u64,
    unique_crashes: HashSet<String>,
    interesting: HashSet<u32>,
    
    // Current state (for crash tracking)
    current_ioctl: u32,
    current_input: Vec<u8>,
    
    // Corpus of interesting inputs per IOCTL
    corpus: HashMap<u32, Vec<Vec<u8>>>,
    
    // IOCTL response patterns
    response_patterns: HashMap<u32, Vec<u32>>,
}

impl Fuzzer {
    fn new(target: String, ioctls: Vec<u32>, output_dir: String, mode: String) -> Self {
        Self {
            target,
            ioctls,
            output_dir,
            mode,
            total_execs: 0,
            crashes: 0,
            unique_crashes: HashSet::new(),
            interesting: HashSet::new(),
            current_ioctl: 0,
            current_input: Vec::new(),
            corpus: HashMap::new(),
            response_patterns: HashMap::new(),
        }
    }
    
    fn run(&mut self) {
        let start = Instant::now();
        
        loop {
            // Connect to executor
            println!("[*] Connecting to executor at {}...", self.target);
            
            let mut stream = match self.connect_with_retry() {
                Some(s) => s,
                None => {
                    eprintln!("[!] Failed to connect after max retries. Exiting.");
                    break;
                }
            };
            
            // Ping to verify connection
            if !self.ping(&mut stream) {
                eprintln!("[!] Ping failed, reconnecting...");
                continue;
            }
            
            println!("[+] Connected and verified");
            println!();
            
            // Fuzzing loop
            let session_start = Instant::now();
            let mut session_execs: u64 = 0;
            
            loop {
                // Generate test case
                let (ioctl, input) = self.generate_testcase();
                
                // Save current state for crash tracking
                self.current_ioctl = ioctl;
                self.current_input = input.clone();
                
                // Execute
                match self.send_ioctl(&mut stream, ioctl, &input) {
                    Ok(result) => {
                        self.total_execs += 1;
                        session_execs += 1;
                        
                        // Analyze result
                        self.analyze_result(ioctl, &input, &result);
                        
                        // Status update
                        if self.total_execs % 100 == 0 {
                            let elapsed = start.elapsed().as_secs_f64();
                            let eps = self.total_execs as f64 / elapsed.max(0.001);
                            print!("\r[FUZZ] Execs: {} | Crashes: {} | Unique: {} | Interesting: {} | {:.0} exec/s    ",
                                   self.total_execs, self.crashes, self.unique_crashes.len(), 
                                   self.interesting.len(), eps);
                            std::io::stdout().flush().ok();
                        }
                    }
                    Err(_) => {
                        // Connection lost - executor probably crashed!
                        println!("\n");
                        println!("╔══════════════════════════════════════════════════════════════╗");
                        println!("║                    💥 CRASH DETECTED! 💥                     ║");
                        println!("╚══════════════════════════════════════════════════════════════╝");
                        println!();
                        println!("[!] Executor disconnected during IOCTL execution!");
                        println!("[!] IOCTL: 0x{:08X}", self.current_ioctl);
                        println!("[!] Input size: {} bytes", self.current_input.len());
                        println!();
                        
                        self.crashes += 1;
                        self.save_crash();
                        
                        // Wait for executor to restart
                        println!("[*] Waiting {}ms for executor to restart...", RECONNECT_DELAY_MS);
                        std::thread::sleep(Duration::from_millis(RECONNECT_DELAY_MS));
                        break; // Reconnect
                    }
                }
            }
            
            let session_elapsed = session_start.elapsed().as_secs_f64();
            println!("\n[*] Session ended: {} execs in {:.1}s", session_execs, session_elapsed);
        }
        
        // Final stats
        let elapsed = start.elapsed().as_secs_f64();
        println!();
        println!("╔════════════════════════════════════════════════════════════╗");
        println!("║                    FUZZING COMPLETE                        ║");
        println!("╚════════════════════════════════════════════════════════════╝");
        println!("Total executions: {}", self.total_execs);
        println!("Total crashes: {}", self.crashes);
        println!("Unique crashes: {}", self.unique_crashes.len());
        println!("Duration: {:.1}s", elapsed);
        println!("Speed: {:.0} exec/s", self.total_execs as f64 / elapsed.max(0.001));
    }
    
    fn connect_with_retry(&self) -> Option<TcpStream> {
        for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
            match TcpStream::connect(&self.target) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
                    stream.set_nodelay(true).ok();
                    return Some(stream);
                }
                Err(e) => {
                    if attempt % 10 == 1 {
                        println!("[*] Connection attempt {}/{}: {}", attempt, MAX_RECONNECT_ATTEMPTS, e);
                    }
                    std::thread::sleep(Duration::from_millis(RECONNECT_DELAY_MS));
                }
            }
        }
        None
    }
    
    fn ping(&self, stream: &mut TcpStream) -> bool {
        let cmd = [PROTOCOL_VERSION, CMD_PING, 0, 0, 0, 0];
        if stream.write_all(&cmd).is_err() {
            return false;
        }
        
        let mut response = [0u8; 6];
        if stream.read_exact(&mut response).is_err() {
            return false;
        }
        
        response[1] == RESP_PONG
    }
    
    fn send_ioctl(&self, stream: &mut TcpStream, ioctl: u32, input: &[u8]) -> Result<IoctlResult, ()> {
        // Build command: [version:1][cmd:1][len:4][ioctl:4][input_size:4][input:N]
        let payload_len = (8 + input.len()) as u32;
        let mut cmd = Vec::with_capacity(6 + payload_len as usize);
        cmd.push(PROTOCOL_VERSION);
        cmd.push(CMD_IOCTL);
        cmd.extend_from_slice(&payload_len.to_le_bytes());
        cmd.extend_from_slice(&ioctl.to_le_bytes());
        cmd.extend_from_slice(&(input.len() as u32).to_le_bytes());
        cmd.extend_from_slice(input);
        
        // Send
        stream.write_all(&cmd).map_err(|_| ())?;
        
        // Read response header
        let mut header = [0u8; 6];
        stream.read_exact(&mut header).map_err(|_| ())?;
        
        if header[1] == RESP_ERROR {
            let resp_len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
            let mut msg = vec![0u8; resp_len];
            stream.read_exact(&mut msg).ok();
            return Err(());
        }
        
        // Read response payload
        let resp_len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let mut payload = vec![0u8; resp_len];
        stream.read_exact(&mut payload).map_err(|_| ())?;
        
        if payload.len() < 8 {
            return Err(());
        }
        
        let ntstatus = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let bytes_returned = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let output = if payload.len() > 8 { payload[8..].to_vec() } else { Vec::new() };
        
        Ok(IoctlResult {
            ntstatus,
            bytes_returned,
            output,
        })
    }
    
    fn generate_testcase(&mut self) -> (u32, Vec<u8>) {
        let mut rng = rand::thread_rng();
        
        match self.mode.as_str() {
            "sequential" => {
                // Sequential through all IOCTLs
                let idx = (self.total_execs as usize) % self.ioctls.len();
                let ioctl = self.ioctls[idx];
                let input = self.generate_smart_input(ioctl);
                (ioctl, input)
            }
            "random" => {
                // Pure random
                let ioctl = *self.ioctls.choose(&mut rng).unwrap_or(&0);
                let size = rng.gen_range(0..MAX_INPUT_SIZE);
                let input: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
                (ioctl, input)
            }
            _ => {
                // Smart mode - prioritize interesting IOCTLs, mutate corpus
                self.generate_smart_testcase()
            }
        }
    }
    
    fn generate_smart_testcase(&mut self) -> (u32, Vec<u8>) {
        let mut rng = rand::thread_rng();
        
        // 70% chance to fuzz interesting IOCTLs, 30% explore new ones
        let ioctl = if !self.interesting.is_empty() && rng.gen_bool(0.7) {
            let interesting_vec: Vec<u32> = self.interesting.iter().copied().collect();
            *interesting_vec.choose(&mut rng).unwrap()
        } else {
            *self.ioctls.choose(&mut rng).unwrap_or(&0)
        };
        
        // Check if we have corpus for this IOCTL
        let input = if let Some(corpus_inputs) = self.corpus.get(&ioctl) {
            if !corpus_inputs.is_empty() && rng.gen_bool(0.8) {
                // Mutate existing input
                let base = corpus_inputs.choose(&mut rng).unwrap();
                self.mutate_input(base)
            } else {
                self.generate_smart_input(ioctl)
            }
        } else {
            self.generate_smart_input(ioctl)
        };
        
        (ioctl, input)
    }
    
    fn generate_smart_input(&self, _ioctl: u32) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        
        // Mix of different input strategies
        let strategy = rng.gen_range(0..10);
        
        match strategy {
            0 => vec![], // Empty
            1 => vec![0u8; rng.gen_range(1..256)], // Null bytes
            2 => vec![0xFF; rng.gen_range(1..256)], // All 0xFF
            3 => vec![0x41; rng.gen_range(1..256)], // Pattern
            4 => {
                // Pointers/addresses
                let count = rng.gen_range(1..16);
                let mut buf = Vec::with_capacity(count * 8);
                for _ in 0..count {
                    let addr: u64 = match rng.gen_range(0..5) {
                        0 => 0,
                        1 => 0xFFFFFFFFFFFFFFFF,
                        2 => 0x00007FFE00000000 + rng.gen_range(0..0x10000) as u64, // User space
                        3 => 0xFFFFF80000000000 + rng.gen_range(0..0x10000000) as u64, // Kernel space
                        _ => rng.gen(),
                    };
                    buf.extend_from_slice(&addr.to_le_bytes());
                }
                buf
            }
            5 => {
                // Length fields
                let mut buf = vec![0u8; rng.gen_range(16..128)];
                // Set various length patterns
                if buf.len() >= 4 {
                    let sizes = [0u32, 1, 0xFFFFFFFF, 0x7FFFFFFF, buf.len() as u32];
                    let size = *sizes.choose(&mut rng).unwrap();
                    buf[0..4].copy_from_slice(&size.to_le_bytes());
                }
                buf
            }
            6 => {
                // String buffer
                let len = rng.gen_range(16..256);
                let mut buf = vec![0x41u8; len];
                buf[len - 1] = 0; // Null terminator
                buf
            }
            7 => {
                // Unicode string
                let chars = rng.gen_range(8..64);
                let mut buf = Vec::with_capacity(chars * 2 + 4);
                buf.extend_from_slice(&((chars * 2) as u16).to_le_bytes()); // Length
                buf.extend_from_slice(&((chars * 2) as u16).to_le_bytes()); // MaxLength
                for _ in 0..chars {
                    buf.extend_from_slice(&[0x41, 0x00]); // 'A' in UTF-16
                }
                buf
            }
            _ => {
                // Random
                let size = rng.gen_range(1..MAX_INPUT_SIZE);
                (0..size).map(|_| rng.gen()).collect()
            }
        }
    }
    
    fn mutate_input(&self, base: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut input = base.to_vec();
        
        if input.is_empty() {
            return self.generate_smart_input(0);
        }
        
        let mutations = rng.gen_range(1..MUTATION_ROUNDS);
        
        for _ in 0..mutations {
            let mutation = rng.gen_range(0..8);
            
            match mutation {
                0 if !input.is_empty() => {
                    // Bit flip
                    let idx = rng.gen_range(0..input.len());
                    let bit = rng.gen_range(0..8);
                    input[idx] ^= 1 << bit;
                }
                1 if !input.is_empty() => {
                    // Byte flip
                    let idx = rng.gen_range(0..input.len());
                    input[idx] = input[idx].wrapping_add(rng.gen_range(1..=255));
                }
                2 if input.len() >= 4 => {
                    // DWORD change
                    let idx = rng.gen_range(0..input.len() - 3);
                    let values = [0u32, 1, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, rng.gen()];
                    let val = *values.choose(&mut rng).unwrap();
                    input[idx..idx+4].copy_from_slice(&val.to_le_bytes());
                }
                3 if !input.is_empty() => {
                    // Insert bytes
                    let idx = rng.gen_range(0..=input.len());
                    let count = rng.gen_range(1..16);
                    for _ in 0..count {
                        input.insert(idx.min(input.len()), rng.gen());
                    }
                }
                4 if !input.is_empty() => {
                    // Delete bytes
                    let idx = rng.gen_range(0..input.len());
                    let count = rng.gen_range(1..16).min(input.len() - idx);
                    input.drain(idx..idx+count);
                }
                5 if input.len() >= 2 => {
                    // Swap bytes
                    let i1 = rng.gen_range(0..input.len());
                    let i2 = rng.gen_range(0..input.len());
                    input.swap(i1, i2);
                }
                6 if !input.is_empty() => {
                    // Set to interesting value
                    let idx = rng.gen_range(0..input.len());
                    let vals = [0x00, 0x01, 0x7F, 0x80, 0xFF];
                    input[idx] = *vals.choose(&mut rng).unwrap();
                }
                _ => {
                    // Resize
                    let new_size = rng.gen_range(1..MAX_INPUT_SIZE);
                    input.resize(new_size, rng.gen());
                }
            }
        }
        
        // Limit size
        if input.len() > MAX_INPUT_SIZE {
            input.truncate(MAX_INPUT_SIZE);
        }
        
        input
    }
    
    fn analyze_result(&mut self, ioctl: u32, input: &[u8], result: &IoctlResult) {
        // Track response patterns
        self.response_patterns
            .entry(ioctl)
            .or_insert_with(Vec::new)
            .push(result.ntstatus);
        
        // Check for interesting responses
        let is_interesting = match result.ntstatus {
            0 => true, // Success is interesting!
            0xC0000005 => false, // Access violation - common rejection
            0xC000000D => false, // Invalid parameter - common
            0xC0000010 => false, // Invalid device request - common
            _ if result.bytes_returned > 0 => true, // Got output data
            _ if result.ntstatus & 0xC0000000 != 0xC0000000 => true, // Non-error status
            _ => false,
        };
        
        if is_interesting {
            self.interesting.insert(ioctl);
            
            // Add to corpus
            let corpus_entry = self.corpus.entry(ioctl).or_insert_with(Vec::new);
            if corpus_entry.len() < 100 {
                corpus_entry.push(input.to_vec());
            }
        }
    }
    
    fn save_crash(&mut self) {
        // Create unique crash ID
        let crash_hash = format!("{:08X}_{}", self.current_ioctl, 
                                  self.current_input.len());
        
        if self.unique_crashes.contains(&crash_hash) {
            println!("[*] Duplicate crash, skipping save");
            return;
        }
        
        self.unique_crashes.insert(crash_hash.clone());
        
        // Save crash info
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let crash_dir = format!("{}/crash_{}_{}", self.output_dir, crash_hash, timestamp);
        fs::create_dir_all(&crash_dir).ok();
        
        // Save input
        let input_path = format!("{}/input.bin", crash_dir);
        fs::write(&input_path, &self.current_input).ok();
        
        // Save info
        let info = format!(
            "IOCTL: 0x{:08X}\n\
             Input Size: {} bytes\n\
             Timestamp: {}\n\
             Total Executions: {}\n\
             Input Hex: {}\n",
            self.current_ioctl,
            self.current_input.len(),
            timestamp,
            self.total_execs,
            self.current_input.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
        );
        
        let info_path = format!("{}/info.txt", crash_dir);
        fs::write(&info_path, info).ok();
        
        // Save reproduction script
        let repro = format!(
            "// Reproduction for crash {}\n\
             // IOCTL: 0x{:08X}\n\n\
             let ioctl_code: u32 = 0x{:08X};\n\
             let input: &[u8] = &{:?};\n\n\
             // Execute:\n\
             // DeviceIoControl(handle, ioctl_code, input.as_ptr(), input.len(), ...);\n",
            crash_hash,
            self.current_ioctl,
            self.current_ioctl,
            self.current_input
        );
        
        let repro_path = format!("{}/repro.rs", crash_dir);
        fs::write(&repro_path, repro).ok();
        
        println!("[+] Crash saved to: {}", crash_dir);
    }
}

struct IoctlResult {
    ntstatus: u32,
    bytes_returned: u32,
    #[allow(dead_code)]
    output: Vec<u8>,
}
