//! TCP Client for two-agent fuzzing
//! 
//! Connects to executor running in VM, sends IOCTL commands, receives results.
//! If executor crashes (connection drops), we know exactly which IOCTL caused it.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const PROTOCOL_VERSION: u8 = 1;
const CMD_PING: u8 = 0x01;
const CMD_IOCTL: u8 = 0x02;
const CMD_BATCH_SCAN: u8 = 0x03;  // Batch IOCTL scanning for speed

const RESP_OK: u8 = 0x00;
const RESP_PONG: u8 = 0x02;

/// Threshold for classifying crashes
/// < 15 seconds = executor crash (false positive)
/// > 15 seconds = likely kernel BSOD (VM rebooting)
const BSOD_THRESHOLD_SECS: u64 = 15;

/// TCP-based driver I/O (connects to executor in VM)
pub struct TcpDriverIO {
    target: String,
    stream: Option<TcpStream>,
    reconnect_attempts: u32,
    max_reconnect_attempts: u32,
    reconnect_delay_ms: u64,
    /// Last reconnect time in seconds (for crash classification)
    pub last_reconnect_time_secs: u64,
}

/// Result from IOCTL execution
#[derive(Debug, Clone)]
pub struct IoctlResult {
    pub success: bool,
    pub ntstatus: u32,
    pub bytes_returned: u32,
    pub output: Vec<u8>,
    pub executor_crashed: bool,
}

impl IoctlResult {
    /// Check if output buffer contains potential kernel pointer leaks
    pub fn check_info_leak(&self, input: &[u8]) -> Option<InfoLeak> {
        if self.output.len() < 8 {
            return None;
        }
        
        for i in (0..self.output.len().saturating_sub(7)).step_by(8) {
            let val = u64::from_le_bytes([
                self.output[i], self.output[i+1], self.output[i+2], self.output[i+3],
                self.output[i+4], self.output[i+5], self.output[i+6], self.output[i+7],
            ]);
            
            // Check for kernel addresses (Windows x64: 0xFFFF8000'00000000+)
            if val >= 0xFFFF800000000000 && val <= 0xFFFFFFFFFFFFFFFE {
                // Make sure it's not in our input (false positive)
                let mut in_input = false;
                for j in (0..input.len().saturating_sub(7)).step_by(8) {
                    if j + 8 <= input.len() {
                        let input_val = u64::from_le_bytes([
                            input[j], input[j+1], input[j+2], input[j+3],
                            input[j+4], input[j+5], input[j+6], input[j+7],
                        ]);
                        if input_val == val {
                            in_input = true;
                            break;
                        }
                    }
                }
                
                // Skip common false positives
                if !in_input && val != 0xFFFFFFFFFFFFFFFF && val != 0xCCCCCCCCCCCCCCCC {
                    return Some(InfoLeak {
                        offset: i,
                        value: val,
                        likely_type: if val >= 0xFFFFF80000000000 && val < 0xFFFFF88000000000 {
                            "ntoskrnl pointer"
                        } else if val >= 0xFFFFFA8000000000 {
                            "pool pointer"
                        } else {
                            "kernel address"
                        },
                    });
                }
            }
        }
        None
    }
}

/// Detected information leak
#[derive(Debug, Clone)]
pub struct InfoLeak {
    pub offset: usize,
    pub value: u64,
    pub likely_type: &'static str,
}

impl TcpDriverIO {
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            stream: None,
            reconnect_attempts: 0,
            max_reconnect_attempts: 100,
            reconnect_delay_ms: 1000,  // Reduced from 2000 for faster recovery
            last_reconnect_time_secs: 0,
        }
    }

    /// Connect to executor
    pub fn connect(&mut self) -> Result<(), String> {
        use std::io::Write;
        use std::net::{SocketAddr, ToSocketAddrs};
        
        // Use println! instead of print! - Windows doesn't flush print! properly
        println!("[TCP] Connecting to executor at {}...", self.target);
        
        // Parse address and connect with timeout
        let addr: SocketAddr = match self.target.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => return Err("Could not resolve address".to_string()),
            },
            Err(e) => return Err(format!("Invalid address: {}", e)),
        };
        
        // Connect with 2 second timeout (don't block forever!)
        match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
            Ok(mut stream) => {
                // SHORT read timeout - detect disconnects quickly!
                stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(3))).ok();
                stream.set_nodelay(true).ok();
                
                // Test connection with ping
                let ping = [PROTOCOL_VERSION, CMD_PING, 0, 0, 0, 0];
                if stream.write_all(&ping).is_err() {
                    return Err("Failed to send ping".to_string());
                }
                
                let mut response = [0u8; 6];
                if stream.read_exact(&mut response).is_err() {
                    return Err("Failed to receive pong".to_string());
                }
                
                if response[1] != RESP_PONG {
                    return Err("Invalid pong response".to_string());
                }
                
                self.stream = Some(stream);
                self.reconnect_attempts = 0;
                println!("[TCP] Connected successfully!");
                Ok(())
            }
            Err(e) => Err(format!("Connection failed: {}", e)),
        }
    }

    /// Try to reconnect after crash
    /// Returns true if reconnected, tracks time for crash classification
    /// Pass a running flag to allow Ctrl+C to interrupt
    pub fn reconnect(&mut self) -> bool {
        self.reconnect_with_flag(None)
    }
    
    /// Reconnect with optional running flag for Ctrl+C support
    pub fn reconnect_with_flag(&mut self, running: Option<&std::sync::atomic::AtomicBool>) -> bool {
        use std::io::Write;
        use std::sync::atomic::Ordering;
        
        self.stream = None;
        let start = Instant::now();
        
        // Force flush before reconnect loop
        println!("[TCP] Starting reconnection...");
        let _ = std::io::stdout().flush();
        
        for attempt in 1..=self.max_reconnect_attempts {
            // Check if user pressed Ctrl+C
            if let Some(r) = running {
                if !r.load(Ordering::SeqCst) {
                    println!("[TCP] Interrupted by user");
                    self.last_reconnect_time_secs = start.elapsed().as_secs();
                    return false;
                }
            }
            
            // Use println instead of print to force flush on Windows
            println!("[TCP] Reconnection attempt {}/{}...", attempt, self.max_reconnect_attempts);
            
            // TRY TO CONNECT FIRST (don't sleep before first attempt!)
            if self.connect().is_ok() {
                self.last_reconnect_time_secs = start.elapsed().as_secs();
                return true;
            }
            
            // Only sleep AFTER failed attempt - reduced to 500ms
            std::thread::sleep(Duration::from_millis(500));
            
            // Check Ctrl+C after sleep
            if let Some(r) = running {
                if !r.load(Ordering::SeqCst) {
                    println!("[TCP] Interrupted by user");
                    self.last_reconnect_time_secs = start.elapsed().as_secs();
                    return false;
                }
            }
        }
        
        self.last_reconnect_time_secs = start.elapsed().as_secs();
        false
    }

    /// Check if last crash was likely a kernel BSOD (based on reconnect time)
    pub fn was_likely_bsod(&self) -> bool {
        self.last_reconnect_time_secs >= BSOD_THRESHOLD_SECS
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Send IOCTL to executor
    /// Returns IoctlResult with executor_crashed=true if connection dropped
    pub fn send_ioctl(&mut self, ioctl_code: u32, input: &[u8]) -> IoctlResult {
        let stream = match &mut self.stream {
            Some(s) => s,
            None => {
                return IoctlResult {
                    success: false,
                    ntstatus: 0xFFFFFFFF,
                    bytes_returned: 0,
                    output: Vec::new(),
                    executor_crashed: true,
                };
            }
        };

        // Build command: [version:1][cmd:1][len:4][ioctl:4][input_size:4][input:N]
        let payload_len = (8 + input.len()) as u32;
        let mut cmd = Vec::with_capacity(6 + payload_len as usize);
        cmd.push(PROTOCOL_VERSION);
        cmd.push(CMD_IOCTL);
        cmd.extend_from_slice(&payload_len.to_le_bytes());
        cmd.extend_from_slice(&ioctl_code.to_le_bytes());
        cmd.extend_from_slice(&(input.len() as u32).to_le_bytes());
        cmd.extend_from_slice(input);

        // Send command
        if stream.write_all(&cmd).is_err() {
            self.stream = None;
            return IoctlResult {
                success: false,
                ntstatus: 0xFFFFFFFF,
                bytes_returned: 0,
                output: Vec::new(),
                executor_crashed: true,
            };
        }

        // Read response header
        let mut header = [0u8; 6];
        if stream.read_exact(&mut header).is_err() {
            self.stream = None;
            return IoctlResult {
                success: false,
                ntstatus: 0xFFFFFFFF,
                bytes_returned: 0,
                output: Vec::new(),
                executor_crashed: true,
            };
        }

        // Check for error response
        if header[1] != RESP_OK {
            let resp_len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
            let mut msg = vec![0u8; resp_len];
            stream.read_exact(&mut msg).ok();
            return IoctlResult {
                success: false,
                ntstatus: 0xFFFFFFFF,
                bytes_returned: 0,
                output: Vec::new(),
                executor_crashed: false,
            };
        }

        // Read response payload
        let resp_len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let mut payload = vec![0u8; resp_len];
        if stream.read_exact(&mut payload).is_err() {
            self.stream = None;
            return IoctlResult {
                success: false,
                ntstatus: 0xFFFFFFFF,
                bytes_returned: 0,
                output: Vec::new(),
                executor_crashed: true,
            };
        }

        if payload.len() < 8 {
            return IoctlResult {
                success: false,
                ntstatus: 0xFFFFFFFF,
                bytes_returned: 0,
                output: Vec::new(),
                executor_crashed: false,
            };
        }

        let ntstatus = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let bytes_returned = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let output = if payload.len() > 8 { payload[8..].to_vec() } else { Vec::new() };

        IoctlResult {
            success: ntstatus == 0,
            ntstatus,
            bytes_returned,
            output,
            executor_crashed: false,
        }
    }

    /// Send IOCTL compatible with DriverIO interface
    /// Returns bytes_returned on success, error code on failure
    pub fn send_ioctl_compat(&mut self, ioctl_code: u32, input: &[u8], output: &mut [u8]) -> Result<u32, i32> {
        let result = self.send_ioctl(ioctl_code, input);
        
        if result.executor_crashed {
            return Err(-1); // Special error code for crash
        }
        
        // Copy output
        let copy_len = result.output.len().min(output.len());
        output[..copy_len].copy_from_slice(&result.output[..copy_len]);
        
        if result.success {
            Ok(result.bytes_returned)
        } else {
            Err(result.ntstatus as i32)
        }
    }

    /// Batch scan multiple IOCTLs at once - returns only successful ones
    /// MUCH faster than individual scans (reduces network round-trips)
    pub fn batch_scan(&mut self, ioctls: &[u32], test_input: &[u8]) -> Result<Vec<u32>, String> {
        let stream = match &mut self.stream {
            Some(s) => s,
            None => return Err("Not connected".to_string()),
        };

        // Build command: [version:1][cmd:1][len:4][count:4][ioctl1:4]...[input_size:4][input:N]
        let payload_len = (4 + ioctls.len() * 4 + 4 + test_input.len()) as u32;
        let mut cmd = Vec::with_capacity(6 + payload_len as usize);
        cmd.push(PROTOCOL_VERSION);
        cmd.push(CMD_BATCH_SCAN);
        cmd.extend_from_slice(&payload_len.to_le_bytes());
        cmd.extend_from_slice(&(ioctls.len() as u32).to_le_bytes());
        for ioctl in ioctls {
            cmd.extend_from_slice(&ioctl.to_le_bytes());
        }
        cmd.extend_from_slice(&(test_input.len() as u32).to_le_bytes());
        cmd.extend_from_slice(test_input);

        // Send
        if stream.write_all(&cmd).is_err() {
            self.stream = None;
            return Err("Send failed - executor crashed?".to_string());
        }

        // Read response header
        let mut header = [0u8; 6];
        if stream.read_exact(&mut header).is_err() {
            self.stream = None;
            return Err("Read failed - executor crashed?".to_string());
        }

        if header[1] != RESP_OK {
            return Err("Batch scan failed".to_string());
        }

        // Read response payload
        let resp_len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let mut payload = vec![0u8; resp_len];
        if stream.read_exact(&mut payload).is_err() {
            self.stream = None;
            return Err("Payload read failed".to_string());
        }

        if payload.len() < 4 {
            return Ok(Vec::new());
        }

        // Parse successes
        let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        let mut successes = Vec::with_capacity(count);
        for i in 0..count {
            let offset = 4 + i * 4;
            if offset + 4 <= payload.len() {
                let ioctl = u32::from_le_bytes([
                    payload[offset], payload[offset+1], payload[offset+2], payload[offset+3]
                ]);
                successes.push(ioctl);
            }
        }

        Ok(successes)
    }
}
