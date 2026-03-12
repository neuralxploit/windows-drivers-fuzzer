//! Executor - Runs in VM, receives IOCTL commands via TCP, executes against driver
//! 
//! Usage: executor.exe --port 9999 --device \\.\ahcache

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ptr;
use std::time::Instant;
use std::panic;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::Networking::WinSock::{
    WSAStartup, WSASocketW, WSAGetLastError, closesocket, bind, listen,
    WSADATA, AF_INET, SOCK_STREAM, SOCK_DGRAM, IPPROTO_TCP, IPPROTO_UDP,
    SOCKET, INVALID_SOCKET, SOCKADDR, SOCKADDR_IN,
};
use windows::Win32::System::Memory::{VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_READWRITE};

// SEH for catching access violations
#[cfg(windows)]
use std::arch::asm;

#[repr(C)]
struct EXCEPTION_POINTERS {
    exception_record: *const EXCEPTION_RECORD,
    context_record: *const u8,
}

#[repr(C)]
struct EXCEPTION_RECORD {
    exception_code: u32,
    exception_flags: u32,
    exception_record: *const EXCEPTION_RECORD,
    exception_address: *const u8,
    number_parameters: u32,
    exception_information: [usize; 15],
}

// Exception codes
const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC0000005;
const EXCEPTION_IN_PAGE_ERROR: u32 = 0xC0000006;
const EXCEPTION_STACK_OVERFLOW: u32 = 0xC00000FD;
const STATUS_HEAP_CORRUPTION: u32 = 0xC0000374;
const STATUS_STACK_BUFFER_OVERRUN: u32 = 0xC0000409;

type PVECTORED_EXCEPTION_HANDLER = extern "system" fn(*const EXCEPTION_POINTERS) -> i32;

#[link(name = "kernel32")]
extern "system" {
    fn AddVectoredExceptionHandler(first: u32, handler: PVECTORED_EXCEPTION_HANDLER) -> *mut u8;
}

const PROTOCOL_VERSION: u8 = 1;
const CMD_PING: u8 = 0x01;
const CMD_IOCTL: u8 = 0x02;
const CMD_BATCH_SCAN: u8 = 0x03;  // Batch IOCTL scanning for speed
const CMD_SHUTDOWN: u8 = 0xFF;

const RESP_OK: u8 = 0x00;
const RESP_ERROR: u8 = 0x01;
const RESP_PONG: u8 = 0x02;
const RESP_WRITE_DETECTED: u8 = 0x03;  // Arbitrary write detection response
const RESP_TYPE_CONFUSION: u8 = 0x04;  // Type confusion detection response

// Canary pattern for arbitrary write detection
const CANARY_PATTERN: u64 = 0xDEADBEEFCAFEBABE;
const CANARY_PAGE_SIZE: usize = 4096;
const NUM_CANARY_PAGES: usize = 8;

// Type confusion test patterns
const TYPE_CONFUSION_MARKERS: [u32; 16] = [
    0x00000000, 0x00000001, 0x00000002, 0x00000003,  // Common type IDs
    0xFFFFFFFF, 0xFFFFFFFE, 0x80000000, 0x7FFFFFFF,  // Edge cases
    0x00010000, 0x00020000, 0x00030000, 0x00040000,  // High-byte types
    0x41414141, 0x42424242, 0xDEADBEEF, 0xCAFEBABE,  // Magic values
];

// FALSE POSITIVE values - common constants that look like kernel pointers but aren't
const FALSE_POSITIVE_KERNEL_VALUES: &[u64] = &[
    0xFFFFFFFFFFFFFFFF,    // -1
    0xFFFFFFFFFFFFFFFE,    // -2
    0xFFFFFFFF00000000,    // High bits only
    0xFFFF800000000000,    // Start of kernel range (unlikely to be actual ptr)
    0xFFFFFFFF80000000,    // Common constant
];

// Range for valid kernel pointers
const KERNEL_PTR_LOW: u64 = 0xFFFF800000000000;
const KERNEL_PTR_HIGH: u64 = 0xFFFFFFFFFFFFFFFE;

// Range for high user-mode pointers (might indicate ASLR'd addresses)  
const USER_HIGH_PTR_LOW: u64 = 0x00007FF000000000;
const USER_HIGH_PTR_HIGH: u64 = 0x00007FFFFFFFFFFF;

/// Type confusion tester
struct TypeConfusionTester {
    /// Track which (ioctl, type_field) combinations caused interesting behavior
    interesting_types: std::collections::HashMap<(u32, u32), Vec<u32>>,
    /// Track delayed effects - IOCTLs that succeeded but might corrupt state
    pending_checks: Vec<(u32, u32, Vec<u8>)>,  // (ioctl, type_val, input)
    /// Count of potential type confusions found
    confusions_found: u64,
}

impl TypeConfusionTester {
    fn new() -> Self {
        TypeConfusionTester {
            interesting_types: std::collections::HashMap::new(),
            pending_checks: Vec::new(),
            confusions_found: 0,
        }
    }
    
    /// Generate type-confused variants of an input buffer
    fn generate_confused_inputs(&self, original: &[u8], ioctl: u32) -> Vec<(Vec<u8>, u32, String)> {
        let mut variants = Vec::new();
        
        if original.is_empty() {
            return variants;
        }
        
        // Strategy 1: Mutate first 4 bytes (common type discriminator location)
        if original.len() >= 4 {
            for &type_val in &TYPE_CONFUSION_MARKERS {
                let mut confused = original.to_vec();
                confused[0..4].copy_from_slice(&type_val.to_le_bytes());
                variants.push((confused, type_val, "type_field_0".to_string()));
            }
        }
        
        // Strategy 2: Mutate bytes 4-8 (secondary type or size field)
        if original.len() >= 8 {
            for &type_val in &TYPE_CONFUSION_MARKERS {
                let mut confused = original.to_vec();
                confused[4..8].copy_from_slice(&type_val.to_le_bytes());
                variants.push((confused, type_val, "type_field_4".to_string()));
            }
        }
        
        // Strategy 3: Inject function pointers at common callback offsets
        let callback_offsets = [8, 16, 24, 32, 0x10, 0x18, 0x20];
        for &offset in &callback_offsets {
            if original.len() >= offset + 8 {
                let mut confused = original.to_vec();
                // Inject a recognizable "function pointer" pattern
                let fake_ptr: u64 = 0x4141414141414141;
                confused[offset..offset+8].copy_from_slice(&fake_ptr.to_le_bytes());
                variants.push((confused, offset as u32, format!("callback_offset_{}", offset)));
            }
        }
        
        // Strategy 4: Size/type mismatch - claim large size with small type
        if original.len() >= 8 {
            let mut confused = original.to_vec();
            // Type = 0 (simple), but size = huge
            confused[0..4].copy_from_slice(&0u32.to_le_bytes());
            confused[4..8].copy_from_slice(&0xFFFFu32.to_le_bytes());
            variants.push((confused, 0xFFFF0000, "size_type_mismatch".to_string()));
        }
        
        // Strategy 5: Object type confusion - wrong object type in handle field
        if original.len() >= 8 {
            let object_types: [(u32, &str); 4] = [
                (0x00000001, "File"),
                (0x00000003, "Process"),
                (0x00000005, "Thread"),
                (0x00000007, "Event"),
            ];
            for (obj_type, name) in object_types {
                let mut confused = original.to_vec();
                confused[0..4].copy_from_slice(&obj_type.to_le_bytes());
                variants.push((confused, obj_type, format!("object_type_{}", name)));
            }
        }
        
        variants
    }
    
    /// Check if a result indicates type confusion
    fn analyze_result(&mut self, ioctl: u32, type_val: u32, mutation: &str, 
                     ntstatus: u32, original_status: u32, 
                     output: &[u8], original_output: &[u8]) -> Option<String> {
        // CRITICAL: Filter out false positives from type field mutations
        // If mutation is type_field_X or object_type_X, the original likely failed
        // because the fuzzer's random data had invalid type values.
        // This is NOT a vulnerability - it's just fixing bad input.
        let is_type_field_mutation = mutation.starts_with("type_field_") || 
                                      mutation.starts_with("object_type_");
        
        // Error codes that indicate "your input format was wrong"
        // These are expected to fail with random fuzzer input
        let input_format_errors: &[u32] = &[
            0x80070057,  // ERROR_INVALID_PARAMETER (Win32)
            0x8007003B,  // ERROR_SHARING_PAUSED / similar
            0xC000000D,  // STATUS_INVALID_PARAMETER (NT)
            0xC0000004,  // STATUS_INFO_LENGTH_MISMATCH
            0xC0000008,  // STATUS_INVALID_HANDLE
            0xC0000023,  // STATUS_BUFFER_TOO_SMALL
            0xC0000010,  // STATUS_INVALID_DEVICE_REQUEST
        ];
        
        // If original failed with "bad input" error and we're doing type mutation,
        // then success is NOT interesting - we just fixed the fuzzer's bad input
        let original_was_bad_input = input_format_errors.contains(&original_status);
        
        // High severity findings
        let high_severity = match ntstatus {
            0x00000000 if original_status != 0 => {
                // SUCCESS when original failed
                // BUT: Filter if this is just a type field mutation fixing bad fuzzer input
                if is_type_field_mutation && original_was_bad_input {
                    // Not interesting - type mutation just provided valid type
                    None
                } else if !original_was_bad_input {
                    // Original failed for a DIFFERENT reason, and mutation made it work
                    // This could be interesting!
                    Some(format!("TYPE_BYPASS: {} made IOCTL 0x{:08X} succeed! (was 0x{:08X})", 
                                mutation, ioctl, original_status))
                } else {
                    None
                }
            }
            0xC0000005 => {
                // Access violation - likely dereferenced bad pointer from confusion
                // THIS IS ALWAYS INTERESTING
                Some(format!("TYPE_CRASH: {} caused ACCESS_VIOLATION on IOCTL 0x{:08X}", 
                            mutation, ioctl))
            }
            _ => None
        };
        
        if high_severity.is_some() {
            self.confusions_found += 1;
            self.interesting_types
                .entry((ioctl, type_val))
                .or_insert_with(Vec::new)
                .push(ntstatus);
            return high_severity;
        }
        
        // Medium severity - only report if accompanied by other indicators
        let medium_severity = match ntstatus {
            0xC0000024 => {
                // Object type mismatch - explicit type confusion detection by driver
                // Only interesting if it didn't happen with original input
                if original_status != 0xC0000024 {
                    Some(format!("TYPE_MISMATCH: Driver detected {} confusion on IOCTL 0x{:08X}", 
                               mutation, ioctl))
                } else {
                    None
                }
            }
            _ => None
        };
        
        if medium_severity.is_some() {
            self.confusions_found += 1;
            self.interesting_types
                .entry((ioctl, type_val))
                .or_insert_with(Vec::new)
                .push(ntstatus);
            return medium_severity;
        }
        
        // Low severity - status difference
        // Filter out common expected status changes (these are NOT type confusion)
        let expected_status_changes: &[(u32, u32)] = &[
            (0xC0000010, 0xC000000D), // STATUS_NO_SUCH_DEVICE <-> STATUS_INVALID_PARAMETER
            (0xC000000D, 0xC0000010), // Same, reversed
            (0xC0000008, 0xC000000D), // STATUS_INVALID_HANDLE <-> STATUS_INVALID_PARAMETER
            (0xC000000D, 0xC0000008), // Same, reversed
            (0xC0000023, 0xC000000D), // STATUS_BUFFER_TOO_SMALL <-> STATUS_INVALID_PARAMETER
            (0xC000000D, 0xC0000023), // Same, reversed
            (0xC0000004, 0xC000000D), // STATUS_INFO_LENGTH_MISMATCH <-> STATUS_INVALID_PARAMETER
            (0xC000000D, 0xC0000004), // Same, reversed
        ];
        
        if ntstatus != original_status {
            // Check if this is an expected status change
            let is_expected = expected_status_changes.iter()
                .any(|(from, to)| *from == original_status && *to == ntstatus);
            
            if is_expected {
                return None; // Not a real type confusion
            }
            
            // CRITICAL: Also filter TYPE_DIFF for type field mutations with input format errors
            // This is the same false positive - fuzzer sends bad type, mutation fixes it
            if is_type_field_mutation && original_was_bad_input && ntstatus == 0 {
                // Type mutation "fixed" bad input → driver now succeeds
                // This is NOT interesting, just expected multi-handler behavior
                return None;
            }
            
            // Only report TYPE_DIFF if output contains KERNEL data (real leak)
            // Size changes alone are not interesting for type mutations
            if Self::has_new_kernel_data(output, original_output) {
                let finding = format!("TYPE_DIFF: {} changed status 0x{:08X} -> 0x{:08X} WITH kernel data leak!", 
                               mutation, original_status, ntstatus);
                self.confusions_found += 1;
                self.interesting_types
                    .entry((ioctl, type_val))
                    .or_insert_with(Vec::new)
                    .push(ntstatus);
                return Some(finding);
            }
            
            // Just a status change with no other indicators - not interesting
        }
        
        None
    }
    
    /// Check if output has new kernel-looking data compared to original
    fn has_new_kernel_data(output: &[u8], original: &[u8]) -> bool {
        if output.len() < 8 {
            return false;
        }
        
        for (i, chunk) in output.chunks_exact(8).enumerate() {
            let val = u64::from_le_bytes(chunk.try_into().unwrap());
            
            // Check if this looks like a kernel pointer
            if val >= KERNEL_PTR_LOW && val <= KERNEL_PTR_HIGH {
                // Check if original had something different at this offset
                let offset = i * 8;
                if offset + 8 <= original.len() {
                    let orig_val = u64::from_le_bytes(
                        original[offset..offset+8].try_into().unwrap()
                    );
                    if orig_val != val {
                        // New kernel-like value!
                        return true;
                    }
                } else {
                    // This offset wasn't in original - new data
                    return true;
                }
            }
        }
        
        false
    }
}

/// Canary pool for arbitrary write detection
struct CanaryPool {
    pages: Vec<*mut u8>,
    addresses: Vec<usize>,
}

impl CanaryPool {
    fn new() -> Self {
        let mut pages = Vec::with_capacity(NUM_CANARY_PAGES);
        let mut addresses = Vec::with_capacity(NUM_CANARY_PAGES);
        
        for _ in 0..NUM_CANARY_PAGES {
            unsafe {
                let page = VirtualAlloc(
                    None,
                    CANARY_PAGE_SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );
                
                if !page.is_null() {
                    // Fill with known pattern
                    let page_ptr = page as *mut u64;
                    for i in 0..(CANARY_PAGE_SIZE / 8) {
                        *page_ptr.add(i) = CANARY_PATTERN;
                    }
                    pages.push(page as *mut u8);
                    addresses.push(page as usize);
                }
            }
        }
        
        CanaryPool { pages, addresses }
    }
    
    /// Reset all canaries to known pattern
    fn reset(&self) {
        for page in &self.pages {
            unsafe {
                let page_ptr = *page as *mut u64;
                for i in 0..(CANARY_PAGE_SIZE / 8) {
                    *page_ptr.add(i) = CANARY_PATTERN;
                }
            }
        }
    }
    
    /// Check if any canary was modified, returns (page_idx, offset, old_val, new_val)
    /// Filters out uninteresting writes (zeros, common patterns)
    fn check_writes(&self) -> Option<(usize, usize, u64, u64)> {
        for (page_idx, page) in self.pages.iter().enumerate() {
            unsafe {
                let page_ptr = *page as *mut u64;
                for i in 0..(CANARY_PAGE_SIZE / 8) {
                    let val = *page_ptr.add(i);
                    if val != CANARY_PATTERN {
                        // Filter out uninteresting writes
                        // Zero writes might just be memset or initialization
                        if val == 0 {
                            // Check if entire page was zeroed (memset)
                            let mut all_zero = true;
                            for j in 0..(CANARY_PAGE_SIZE / 8) {
                                if *page_ptr.add(j) != 0 && *page_ptr.add(j) != CANARY_PATTERN {
                                    all_zero = false;
                                    break;
                                }
                            }
                            if all_zero {
                                // Likely a memset, still report but note it
                                return Some((page_idx, i * 8, CANARY_PATTERN, val));
                            }
                        }
                        
                        // Check if it's a controlled write (interesting)
                        // Writes of small values (0-0xFFFF) or our patterns are interesting
                        let is_small = val < 0x10000;
                        let is_address_like = (val >= 0x10000 && val <= 0x7FFFFFFFFFFF) || 
                                              (val >= KERNEL_PTR_LOW && val <= KERNEL_PTR_HIGH);
                        let is_pattern = (val & 0xFFFFFFFF) == (val >> 32);  // Repeated pattern like 0x41414141_41414141
                        
                        if is_small || is_address_like || is_pattern || val != 0 {
                            return Some((page_idx, i * 8, CANARY_PATTERN, val));
                        }
                    }
                }
            }
        }
        None
    }
    
    /// Get a canary address for embedding in fuzz inputs
    fn get_address(&self, idx: usize) -> usize {
        self.addresses.get(idx % self.addresses.len()).copied().unwrap_or(0)
    }
    
    /// Inject canary addresses into a buffer at pointer-aligned positions
    fn inject_addresses(&self, buffer: &mut [u8]) {
        // Inject canary addresses at likely pointer positions (8-byte aligned)
        let ptr_size = std::mem::size_of::<usize>();
        
        for (i, chunk) in buffer.chunks_exact_mut(ptr_size).enumerate() {
            // Every 4th pointer position, inject a canary address
            if i % 4 == 0 && i < self.addresses.len() * 4 {
                let addr = self.addresses[i / 4 % self.addresses.len()];
                chunk.copy_from_slice(&addr.to_le_bytes());
            }
        }
    }
}

impl Drop for CanaryPool {
    fn drop(&mut self) {
        for page in &self.pages {
            unsafe {
                VirtualFree(*page as *mut _, 0, MEM_RELEASE);
            }
        }
    }
}

/// Kernel pointer leak detector with false positive filtering
struct KernelLeakDetector {
    /// Baseline output for comparison (from initial run)
    baseline: Option<Vec<u8>>,
    /// Previous outputs to confirm leaks across multiple runs
    previous_outputs: Vec<Vec<u8>>,
    /// Known false positive constants
    false_positives: std::collections::HashSet<u64>,
    /// Confirmed leaks (ioctl, offset, sample_values)
    confirmed_leaks: Vec<(u32, usize, Vec<u64>)>,
}

impl KernelLeakDetector {
    fn new() -> Self {
        let mut false_positives = std::collections::HashSet::new();
        // Add known false positive values
        for &val in FALSE_POSITIVE_KERNEL_VALUES {
            false_positives.insert(val);
        }
        // Also add common flag values that look like kernel pointers
        false_positives.insert(0xFFE30000_00000000);  // Flags
        false_positives.insert(0xFFFFFFFF_FFFFFFFF);  // -1LL
        false_positives.insert(0x00000001_00000000);  // High bit flag
        
        KernelLeakDetector {
            baseline: None,
            previous_outputs: Vec::new(),
            false_positives,
            confirmed_leaks: Vec::new(),
        }
    }
    
    /// Set baseline output for comparison
    fn set_baseline(&mut self, output: Vec<u8>) {
        self.baseline = Some(output.clone());
        self.previous_outputs.clear();
        self.previous_outputs.push(output);
    }
    
    /// Check for kernel pointer leaks in output buffer
    fn check_leak(&mut self, ioctl: u32, output: &[u8], ntstatus: u32) -> Option<String> {
        // Only check successful calls or calls that returned data
        if output.is_empty() {
            return None;
        }
        
        let mut potential_leaks = Vec::new();
        
        // Scan for 8-byte aligned values that look like kernel pointers
        for (i, chunk) in output.chunks_exact(8).enumerate() {
            let val = u64::from_le_bytes(chunk.try_into().unwrap());
            let offset = i * 8;
            
            // Check if it looks like a kernel pointer
            if self.is_potential_kernel_pointer(val) {
                // Verify it's not a false positive
                if !self.false_positives.contains(&val) {
                    potential_leaks.push((offset, val));
                }
            }
            
            // Also check for high user-mode pointers (might indicate leaked user addresses)
            if val >= USER_HIGH_PTR_LOW && val <= USER_HIGH_PTR_HIGH {
                // This could be a leaked user-mode address
                potential_leaks.push((offset, val));
            }
        }
        
        if potential_leaks.is_empty() {
            return None;
        }
        
        // Cross-validate with baseline to detect dynamic leaks
        let mut confirmed = Vec::new();
        
        if let Some(ref baseline) = self.baseline {
            for (offset, val) in potential_leaks {
                // Check if value differs from baseline at same offset
                if offset + 8 <= baseline.len() {
                    let baseline_val = u64::from_le_bytes(
                        baseline[offset..offset+8].try_into().unwrap()
                    );
                    
                    // If same high bits but different low bits = likely real leak (ASLR'd)
                    let same_high = (val & 0xFFFF_F000_0000_0000) == (baseline_val & 0xFFFF_F000_0000_0000);
                    let different_low = (val & 0x0000_0FFF_FFFF_FFFF) != (baseline_val & 0x0000_0FFF_FFFF_FFFF);
                    
                    if same_high && different_low && self.is_potential_kernel_pointer(baseline_val) {
                        // High confidence - both runs showed kernel-like pointer at same offset
                        confirmed.push((offset, val, baseline_val));
                    } else if val != baseline_val && self.is_potential_kernel_pointer(val) {
                        // Value changed between runs - might be interesting
                        confirmed.push((offset, val, baseline_val));
                    }
                } else {
                    // Offset not in baseline - new data, treat as potential leak
                    confirmed.push((offset, val, 0));
                }
            }
        } else {
            // No baseline - record all potential leaks for first pass
            for (offset, val) in potential_leaks {
                confirmed.push((offset, val, 0));
            }
        }
        
        // Record for next comparison
        self.previous_outputs.push(output.to_vec());
        if self.previous_outputs.len() > 5 {
            self.previous_outputs.remove(0);
        }
        
        if confirmed.is_empty() {
            return None;
        }
        
        // Build leak report
        let mut report = format!("KERNEL_LEAK: IOCTL 0x{:08X} - {} potential leak(s):\n", 
                                 ioctl, confirmed.len());
        for (offset, val, baseline_val) in &confirmed {
            report.push_str(&format!("  Offset 0x{:04X}: 0x{:016X}", offset, val));
            if *baseline_val != 0 {
                report.push_str(&format!(" (baseline: 0x{:016X})", baseline_val));
            }
            report.push_str("\n");
        }
        
        // Record confirmed leak
        let sample_values: Vec<u64> = confirmed.iter().map(|(_, v, _)| *v).collect();
        self.confirmed_leaks.push((ioctl, confirmed[0].0, sample_values));
        
        Some(report)
    }
    
    /// Check if value looks like a kernel pointer
    fn is_potential_kernel_pointer(&self, val: u64) -> bool {
        // Must be in kernel address range
        if val < KERNEL_PTR_LOW || val > KERNEL_PTR_HIGH {
            return false;
        }
        
        // Check for known false positive patterns
        if self.false_positives.contains(&val) {
            return false;
        }
        
        // Additional heuristics:
        // - Real kernel pointers usually have non-zero low 12 bits (page offset)
        // - Real kernel pointers usually aren't all 0xF or 0x0 in any nibble group
        
        // Check for suspicious patterns (all Fs or all 0s in groups)
        let nibbles = [
            (val >> 48) & 0xFFFF,
            (val >> 32) & 0xFFFF,
            (val >> 16) & 0xFFFF,
            val & 0xFFFF,
        ];
        
        // If more than 2 nibble groups are all Fs or all 0s, likely a constant
        let suspicious_count = nibbles.iter()
            .filter(|&&n| n == 0xFFFF || n == 0x0000)
            .count();
        
        if suspicious_count >= 3 {
            return false;
        }
        
        true
    }
    
    /// Get summary of confirmed leaks
    fn get_summary(&self) -> String {
        if self.confirmed_leaks.is_empty() {
            return "No kernel pointer leaks detected".to_string();
        }
        
        let mut summary = format!("Found {} potential kernel pointer leaks:\n", 
                                  self.confirmed_leaks.len());
        for (ioctl, offset, samples) in &self.confirmed_leaks {
            summary.push_str(&format!("  IOCTL 0x{:08X} @ offset 0x{:04X}: {:?}\n", 
                                      ioctl, offset, samples));
        }
        summary
    }
}

/// Known 3rd party driver device paths to probe
const DEVICE_PATHS_TO_PROBE: &[(&str, &str, &str)] = &[
    // (device_path, driver_name, vendor)
    ("\\\\.\\RTCore64", "RTCore64.sys", "MSI (Afterburner)"),
    ("\\\\.\\RTCore32", "RTCore32.sys", "MSI (Afterburner)"),
    ("\\\\.\\MsIo", "MsIo64.sys", "MSI"),
    ("\\\\.\\Asusgio2", "AsIO64.sys", "ASUS"),
    ("\\\\.\\Asusgio3", "AsIO3.sys", "ASUS"),
    ("\\\\.\\GIO", "gdrv.sys", "GIGABYTE"),
    ("\\\\.\\DBUtil_2_3", "dbutil_2_3.sys", "Dell"),
    ("\\\\.\\AsrDrv106", "AsrDrv106.sys", "ASRock"),
    ("\\\\.\\AMDRyzenMasterDriverV17", "AMDRyzenMasterDriver.sys", "AMD"),
    ("\\\\.\\AMDRyzenMasterDriverV19", "AMDRyzenMasterDriver.sys", "AMD"),
    ("\\\\.\\HWiNFO64", "HWiNFO64.sys", "HWiNFO"),
    ("\\\\.\\HWiNFO32", "HWiNFO32.sys", "HWiNFO"),
    ("\\\\.\\cpuz141", "cpuz141_x64.sys", "CPUID (CPU-Z)"),
    ("\\\\.\\cpuz153", "cpuz153_x64.sys", "CPUID (CPU-Z)"),
    ("\\\\.\\WinRing0_1_2_0", "WinRing0x64.sys", "WinRing0"),
    ("\\\\.\\WinRing0", "WinRing0.sys", "WinRing0"),
    ("\\\\.\\WinRing0_1_0_1", "WinRing0.sys", "LibreHardwareMonitor"),
    ("\\\\.\\CorsairLLAccess64", "CorsairLLAccess64.sys", "Corsair"),
    ("\\\\.\\RzDev", "rzdev.sys", "Razer"),
    ("\\\\.\\ENE_Link", "ene.sys", "ENE Technology"),
    ("\\\\.\\PhyMem64", "phymemx64.sys", "Physical Memory"),
    ("\\\\.\\inpoutx64", "inpoutx64.sys", "Port I/O"),
    ("\\\\.\\speedfan", "speedfan.sys", "SpeedFan"),
    ("\\\\.\\AIDA64Driver", "AIDA64Driver.sys", "AIDA64"),
    ("\\\\.\\ATSZIO", "ATSZIO64.sys", "ASMedia"),
    // Common Windows drivers for testing
    ("\\\\.\\ahcache", "ahcache.sys", "Windows"),
    ("\\\\.\\Afd", "afd.sys", "Windows (Networking)"),
    ("\\\\.\\Nsi", "nsiproxy.sys", "Windows (NSI)"),
    ("\\\\.\\MountPointManager", "mountmgr.sys", "Windows"),
    ("\\\\.\\RawDisk", "disk.sys", "Windows"),
    ("\\\\.\\Tcp", "tcpip.sys", "Windows (TCP/IP)"),
    ("\\\\.\\Udp", "tcpip.sys", "Windows (UDP)"),
];

/// Probe device paths and report which are accessible
fn discover_drivers() {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║        🐞 LADYBUG EXECUTOR - Driver Discovery Mode 🐞      ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    
    println!("[*] 🔎 Probing {} known device paths...\n", DEVICE_PATHS_TO_PROBE.len());
    
    let mut found_3rd_party = Vec::new();
    let mut found_windows = Vec::new();
    
    for (device_path, driver_name, vendor) in DEVICE_PATHS_TO_PROBE {
        let wide: Vec<u16> = device_path.encode_utf16().chain(std::iter::once(0)).collect();
        
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            )
        };
        
        match handle {
            Ok(h) => {
                unsafe { let _ = CloseHandle(h); }
                
                if vendor.starts_with("Windows") {
                    found_windows.push((*device_path, *driver_name, *vendor));
                } else {
                    println!("    [+] 🎯 ACCESSIBLE: {} -> {} [{}]", device_path, driver_name, vendor);
                    found_3rd_party.push((*device_path, *driver_name, *vendor));
                }
            }
            Err(e) => {
                let code = e.code().0 as u32;
                if code == 0x80070005 { // ERROR_ACCESS_DENIED - driver exists but needs admin
                    if vendor.starts_with("Windows") {
                        found_windows.push((*device_path, *driver_name, *vendor));
                    } else {
                        println!("    [~] EXISTS (needs admin): {} -> {} [{}]", device_path, driver_name, vendor);
                        found_3rd_party.push((*device_path, *driver_name, *vendor));
                    }
                }
            }
        }
    }
    
    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("[+] Results:");
    println!("    - 3rd party drivers found: {}", found_3rd_party.len());
    println!("    - Windows drivers found: {}", found_windows.len());
    println!();
    
    if !found_3rd_party.is_empty() {
        println!("[!] 🎯 THIRD-PARTY DRIVERS AVAILABLE FOR FUZZING:");
        for (path, name, vendor) in &found_3rd_party {
            println!("    {} ({}) - {}", path, name, vendor);
        }
        println!();
        println!("[*] To fuzz, run:");
        if let Some((first_path, _, _)) = found_3rd_party.first() {
            println!("    executor.exe -d \"{}\" -p 9999", first_path);
        }
    } else {
        println!("[!] No 3rd party drivers found. Install one of:");
        println!("    - MSI Afterburner     (RTCore64.sys)");
        println!("    - HWiNFO64            (HWiNFO64.sys)");
        println!("    - CPU-Z               (cpuz_x64.sys)");
        println!("    - AIDA64              (AIDA64Driver.sys)");
        println!("    - Open Hardware Mon.  (WinRing0x64.sys)");
        println!("    - SpeedFan            (speedfan.sys)");
    }
    
    if !found_windows.is_empty() {
        println!();
        println!("[*] Windows drivers available (for research/testing):");
        for (path, name, _vendor) in &found_windows {
            println!("    {} ({})", path, name);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    let mut port: u16 = 9999;
    let mut device = String::from("\\\\.\\ahcache");
    let mut discover_mode = false;
    let mut detect_writes = false;
    let mut type_confusion = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or(9999);
                    i += 1;
                }
            }
            "--device" | "-d" => {
                if i + 1 < args.len() {
                    device = args[i + 1].clone();
                    i += 1;
                }
            }
            "--discover" | "--scan" => {
                discover_mode = true;
            }
            "--detect-writes" | "--arb-write" => {
                detect_writes = true;
            }
            "--type-confusion" | "--type-confuse" => {
                type_confusion = true;
            }
            "--help" | "-h" => {
                println!("Executor - IOCTL Fuzzer Agent");
                println!("Runs in VM, receives commands from controller\n");
                println!("Usage: executor.exe [OPTIONS]");
                println!("  --port, -p <PORT>      TCP port to listen on (default: 9999)");
                println!("  --device, -d <PATH>    Device path (default: \\\\.\\ahcache)");
                println!("  --discover, --scan     Discover available drivers (no fuzzing)");
                println!("  --detect-writes        Enable arbitrary write detection (canaries)");
                println!("  --type-confusion       Enable type confusion testing");
                println!("  --help, -h             Show this help");
                println!();
                println!("Detection capabilities:");
                println!("  - Arbitrary write detection via canary pages");
                println!("  - Type confusion testing with smart false-positive filtering");
                println!("  - Kernel pointer leak detection (always enabled)");
                println!("  - Multiple AFD socket states (TCP/UDP, fresh/bound/listening)");
                return;
            }
            _ => {}
        }
        i += 1;
    }
    
    // Handle discover mode
    if discover_mode {
        discover_drivers();
        return;
    }
    
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║        🐞 LADYBUG EXECUTOR - Kernel Fuzzing Agent 🐞       ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    
    // Install exception handler to log crashes
    unsafe {
        AddVectoredExceptionHandler(1, exception_handler);
    }
    println!("[+] Exception handler installed");
    
    // Initialize canary pool if write detection enabled
    let canary_pool = if detect_writes {
        println!("[+] 🎯 Arbitrary write detection ENABLED");
        let pool = CanaryPool::new();
        println!("    Allocated {} canary pages ({} bytes each)", pool.pages.len(), CANARY_PAGE_SIZE);
        for (i, addr) in pool.addresses.iter().enumerate() {
            println!("    Canary {}: 0x{:016X}", i, addr);
        }
        Some(pool)
    } else {
        None
    };
    
    // Initialize type confusion tester
    let type_confusion_tester = if type_confusion {
        println!("[+] 🔀 Type confusion testing ENABLED");
        println!("    Will test {} type markers per IOCTL", TYPE_CONFUSION_MARKERS.len());
        println!("    Mutations: type_field, callback_offset, size_mismatch, object_type");
        Some(std::sync::Mutex::new(TypeConfusionTester::new()))
    } else {
        None
    };
    
    // Kernel leak detection is always enabled
    println!("[+] 💧 Kernel pointer leak detection ENABLED");
    println!("    False positive filtering: {:?} known values", FALSE_POSITIVE_KERNEL_VALUES.len());
    println!("    Kernel range: 0x{:016X} - 0x{:016X}", KERNEL_PTR_LOW, KERNEL_PTR_HIGH);
    
    println!("[*] Device: {}", device);
    println!("[*] Port: {}", port);
    println!();
    
    // Test device access
    let handle = open_device(&device);
    if handle.is_invalid() {
        eprintln!("[!] ERROR: Cannot open device: {}", device);
        eprintln!("[!] Make sure you're running as Administrator");
        std::process::exit(1);
    }
    unsafe { CloseHandle(handle).ok() };
    println!("[+] Device accessible");
    
    // Start TCP server
    let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[!] Failed to bind port {}: {}", port, e);
            std::process::exit(1);
        }
    };
    
    // Set listener to non-blocking for fast reconnects
    listener.set_nonblocking(false).ok();
    
    println!("[+] Listening on 0.0.0.0:{}", port);
    println!("[*] Waiting for controller connection...");
    println!();
    
    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                println!("[+] Controller connected from {}", addr);
                handle_connection(stream, &device, canary_pool.as_ref(), type_confusion_tester.as_ref());
                println!("[*] ⚡ Ready for reconnection (instant)...");
            }
            Err(e) => {
                eprintln!("[!] Accept error: {}", e);
                // Brief sleep on error, then retry
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

/// Socket states for AFD testing
#[derive(Clone, Copy, Debug)]
enum AfdSocketState {
    TcpFresh,       // Just created
    TcpBound,       // Bound to address
    TcpListening,   // Listening for connections
    UdpFresh,       // UDP socket
    UdpBound,       // UDP bound
}

/// Track current socket state
static mut CURRENT_AFD_STATE: u8 = 0; // 0-4 for cycling

/// Open AFD via socket - AFD can't be opened with CreateFile, must use socket API
fn open_afd_socket() -> HANDLE {
    unsafe {
        // Initialize Winsock
        let mut wsa_data: WSADATA = std::mem::zeroed();
        let result = WSAStartup(0x0202, &mut wsa_data);
        if result != 0 {
            println!("    [-] WSAStartup failed: {}", result);
            return HANDLE::default();
        }
        println!("[+] Winsock initialized");
        
        // Cycle through different socket states for better coverage
        let state = match CURRENT_AFD_STATE % 5 {
            0 => AfdSocketState::TcpFresh,
            1 => AfdSocketState::TcpBound,
            2 => AfdSocketState::TcpListening,
            3 => AfdSocketState::UdpFresh,
            _ => AfdSocketState::UdpBound,
        };
        CURRENT_AFD_STATE = CURRENT_AFD_STATE.wrapping_add(1);
        
        let (family, sock_type, protocol) = match state {
            AfdSocketState::TcpFresh | AfdSocketState::TcpBound | AfdSocketState::TcpListening => {
                (AF_INET.0 as i32, SOCK_STREAM.0 as i32, IPPROTO_TCP.0 as i32)
            }
            AfdSocketState::UdpFresh | AfdSocketState::UdpBound => {
                (AF_INET.0 as i32, SOCK_DGRAM.0 as i32, IPPROTO_UDP.0 as i32)
            }
        };
        
        // Create socket - this gives us an AFD handle!
        let sock = WSASocketW(
            family, sock_type, protocol,
            None, 0, 0,
        );
        
        if sock == INVALID_SOCKET {
            println!("    [-] WSASocket failed");
            return HANDLE::default();
        }
        
        // Apply state-specific operations
        match state {
            AfdSocketState::TcpBound | AfdSocketState::TcpListening | AfdSocketState::UdpBound => {
                // Bind to ephemeral port
                let mut addr: SOCKADDR_IN = std::mem::zeroed();
                addr.sin_family = AF_INET;
                addr.sin_port = 0; // Let OS pick port
                addr.sin_addr.S_un.S_addr = 0; // 0.0.0.0
                
                let bind_result = bind(
                    sock,
                    &addr as *const _ as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                );
                
                if bind_result != 0 {
                    println!("    [-] bind failed: {:?}", WSAGetLastError());
                }
            }
            _ => {}
        }
        
        if let AfdSocketState::TcpListening = state {
            let listen_result = listen(sock, 5);
            if listen_result != 0 {
                println!("    [-] listen failed: {:?}", WSAGetLastError());
            }
        }
        
        println!("[+] SUCCESS: Got AFD socket handle (state: {:?})", state);
        
        // Socket is actually an AFD device handle - convert to HANDLE
        HANDLE(sock.0 as isize)
    }
}

fn open_device(device_path: &str) -> HANDLE {
    // Special handling for AFD - requires socket API
    if device_path.to_lowercase().contains("afd") {
        println!("[*] AFD detected - using socket-based access");
        return open_afd_socket();
    }
    
    let wide: Vec<u16> = device_path.encode_utf16().chain(std::iter::once(0)).collect();
    
    // Try different access modes - some drivers are picky
    let access_modes: &[(u32, &str)] = &[
        ((GENERIC_READ | GENERIC_WRITE).0, "GENERIC_READ|WRITE"),
        (GENERIC_READ.0, "GENERIC_READ"),
        (GENERIC_WRITE.0, "GENERIC_WRITE"),  
        (0, "NO_ACCESS"),
    ];
    
    println!("[*] Trying to open device: {}", device_path);
    
    for (access, name) in access_modes {
        let result = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                *access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            )
        };
        
        match result {
            Ok(h) if !h.is_invalid() => {
                println!("[+] SUCCESS: Opened with {} (0x{:08X})", name, access);
                return h;
            }
            Ok(_) => {
                println!("    [-] {} - invalid handle", name);
            }
            Err(e) => {
                let code = e.code().0 as u32;
                let msg = match code {
                    0x80070005 => "ACCESS_DENIED",
                    0x80070002 => "FILE_NOT_FOUND", 
                    0x80070003 => "PATH_NOT_FOUND",
                    0x80070020 => "SHARING_VIOLATION",
                    0x8007001F => "GEN_FAILURE",
                    0x80070057 => "INVALID_PARAMETER",
                    _ => "UNKNOWN",
                };
                println!("    [-] {} - Error 0x{:08X} ({})", name, code, msg);
            }
        }
    }
    
    HANDLE::default()
}

fn handle_connection(mut stream: TcpStream, device: &str, canary_pool: Option<&CanaryPool>, 
                     type_confusion_tester: Option<&std::sync::Mutex<TypeConfusionTester>>) {
    // Set timeouts - shorter for faster disconnect detection
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5))).ok();
    stream.set_nodelay(true).ok();
    
    // Open device handle for this session
    let handle = open_device(device);
    if handle.is_invalid() {
        eprintln!("[!] Failed to open device for session");
        return;
    }
    
    // Create leak detector for this session
    let mut leak_detector = KernelLeakDetector::new();
    
    let mut total_ioctls: u64 = 0;
    let mut writes_detected: u64 = 0;
    let mut type_confusions_found: u64 = 0;
    let mut leaks_found: u64 = 0;
    let start = Instant::now();
    
    loop {
        // Read command header: [version:1][cmd:1][len:4]
        let mut header = [0u8; 6];
        if stream.read_exact(&mut header).is_err() {
            break;
        }
        
        let version = header[0];
        let cmd = header[1];
        let payload_len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        
        if version != PROTOCOL_VERSION {
            eprintln!("[!] Protocol version mismatch: {} vs {}", version, PROTOCOL_VERSION);
            break;
        }
        
        // Read payload
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 && stream.read_exact(&mut payload).is_err() {
            break;
        }
        
        match cmd {
            CMD_PING => {
                // Respond with pong
                let response = [PROTOCOL_VERSION, RESP_PONG, 0, 0, 0, 0];
                if stream.write_all(&response).is_err() {
                    break;
                }
            }
            
            CMD_IOCTL => {
                // Payload: [ioctl_code:4][input_size:4][input_data:N]
                if payload.len() < 8 {
                    send_error(&mut stream, "Invalid IOCTL payload");
                    continue;
                }
                
                let ioctl_code = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let input_size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
                
                let mut input_data: Vec<u8> = if input_size > 0 && payload.len() >= 8 + input_size {
                    payload[8..8 + input_size].to_vec()
                } else {
                    Vec::new()
                };
                
                // If write detection enabled, inject canary addresses and reset canaries
                if let Some(pool) = canary_pool {
                    pool.reset();
                    if !input_data.is_empty() {
                        pool.inject_addresses(&mut input_data);
                    }
                }
                
                // Execute IOCTL
                let result = execute_ioctl(handle, ioctl_code, &input_data);
                total_ioctls += 1;
                
                // Check for arbitrary writes after IOCTL
                if let Some(pool) = canary_pool {
                    if let Some((page_idx, offset, old_val, new_val)) = pool.check_writes() {
                        writes_detected += 1;
                        let canary_addr = pool.get_address(page_idx) + offset;
                        
                        eprintln!("\n[🔥] ARBITRARY WRITE DETECTED!");
                        eprintln!("    IOCTL: 0x{:08X}", ioctl_code);
                        eprintln!("    Input size: {} bytes", input_data.len());
                        eprintln!("    Write location: 0x{:016X} (canary page {})", canary_addr, page_idx);
                        eprintln!("    Old value: 0x{:016X}", old_val);
                        eprintln!("    New value: 0x{:016X}", new_val);
                        
                        // Save crash input for analysis
                        let crash_dir = std::path::Path::new("arb_writes");
                        std::fs::create_dir_all(crash_dir).ok();
                        let crash_file = crash_dir.join(format!("write_0x{:08X}_{}.bin", ioctl_code, writes_detected));
                        std::fs::write(&crash_file, &input_data).ok();
                        eprintln!("    Saved to: {:?}", crash_file);
                        
                        // Send special response indicating write detection
                        let mut response = Vec::with_capacity(30);
                        response.push(PROTOCOL_VERSION);
                        response.push(RESP_WRITE_DETECTED);
                        let resp_len = 24u32; // 4 + 8 + 8 + 4
                        response.extend_from_slice(&resp_len.to_le_bytes());
                        response.extend_from_slice(&ioctl_code.to_le_bytes());
                        response.extend_from_slice(&(canary_addr as u64).to_le_bytes());
                        response.extend_from_slice(&new_val.to_le_bytes());
                        response.extend_from_slice(&(input_data.len() as u32).to_le_bytes());
                        
                        if stream.write_all(&response).is_err() {
                            break;
                        }
                        continue;
                    }
                }
                
                // Check for kernel pointer leaks in output buffer
                if result.ntstatus == 0 || !result.output.is_empty() {
                    if let Some(leak_report) = leak_detector.check_leak(ioctl_code, &result.output, result.ntstatus) {
                        leaks_found += 1;
                        eprintln!("\n[💧] POTENTIAL KERNEL LEAK DETECTED!");
                        eprintln!("{}", leak_report);
                        
                        // Save leak information
                        let leak_dir = std::path::Path::new("kernel_leaks");
                        std::fs::create_dir_all(leak_dir).ok();
                        let leak_file = leak_dir.join(format!("leak_0x{:08X}_{}.bin", ioctl_code, leaks_found));
                        std::fs::write(&leak_file, &result.output).ok();
                        
                        // Also save the input that triggered the leak
                        let input_file = leak_dir.join(format!("leak_0x{:08X}_{}_input.bin", ioctl_code, leaks_found));
                        std::fs::write(&input_file, &input_data).ok();
                        eprintln!("    Saved output to: {:?}", leak_file);
                    }
                    
                    // Set baseline if this is first successful call with this IOCTL
                    if leak_detector.baseline.is_none() && !result.output.is_empty() {
                        leak_detector.set_baseline(result.output.clone());
                    }
                }
                
                // Type confusion testing - test variants of the input
                if let Some(tester_mutex) = type_confusion_tester {
                    let original_status = result.ntstatus;
                    let original_output = result.output.clone(); // Save for comparison
                    
                    if let Ok(mut tester) = tester_mutex.lock() {
                        let variants = tester.generate_confused_inputs(&input_data, ioctl_code);
                        
                        for (confused_input, type_val, mutation) in variants {
                            // Execute with confused input
                            let confused_result = execute_ioctl(handle, ioctl_code, &confused_input);
                            total_ioctls += 1;
                            
                            // Analyze the result with output comparison
                            if let Some(finding) = tester.analyze_result(
                                ioctl_code, type_val, &mutation, 
                                confused_result.ntstatus, original_status,
                                &confused_result.output, &original_output
                            ) {
                                type_confusions_found += 1;
                                eprintln!("\n[🔀] TYPE CONFUSION DETECTED!");
                                eprintln!("    {}", finding);
                                eprintln!("    IOCTL: 0x{:08X}", ioctl_code);
                                eprintln!("    Mutation: {}", mutation);
                                eprintln!("    Type value: 0x{:08X}", type_val);
                                
                                // Save the confused input
                                let crash_dir = std::path::Path::new("type_confusions");
                                std::fs::create_dir_all(crash_dir).ok();
                                let crash_file = crash_dir.join(format!(
                                    "confusion_0x{:08X}_{}_{}.bin", 
                                    ioctl_code, mutation, type_confusions_found
                                ));
                                std::fs::write(&crash_file, &confused_input).ok();
                                eprintln!("    Saved to: {:?}", crash_file);
                                
                                // Also check canaries after type-confused IOCTL
                                if let Some(pool) = canary_pool {
                                    if let Some((page_idx, offset, _old_val, new_val)) = pool.check_writes() {
                                        let canary_addr = pool.get_address(page_idx) + offset;
                                        eprintln!("    [🔥🔀] TYPE CONFUSION LED TO ARBITRARY WRITE!");
                                        eprintln!("    Write at: 0x{:016X}, value: 0x{:016X}", canary_addr, new_val);
                                    }
                                    pool.reset(); // Reset for next test
                                }
                            }
                        }
                    }
                }
                
                // Send response: [version:1][status:1][len:4][ntstatus:4][bytes_returned:4][output:N]
                let mut response = Vec::with_capacity(14 + result.output.len());
                response.push(PROTOCOL_VERSION);
                response.push(RESP_OK);
                
                let resp_len = (8 + result.output.len()) as u32;
                response.extend_from_slice(&resp_len.to_le_bytes());
                response.extend_from_slice(&result.ntstatus.to_le_bytes());
                response.extend_from_slice(&result.bytes_returned.to_le_bytes());
                response.extend_from_slice(&result.output);
                
                if stream.write_all(&response).is_err() {
                    break;
                }
                
                // Status update every 1000 IOCTLs
                if total_ioctls % 1000 == 0 {
                    let elapsed = start.elapsed().as_secs_f64();
                    let eps = total_ioctls as f64 / elapsed.max(0.001);
                    print!("\r[*] IOCTLs: {} | Speed: {:.0}/s    ", total_ioctls, eps);
                    std::io::stdout().flush().ok();
                }
            }
            
            CMD_BATCH_SCAN => {
                // Batch scan: test many IOCTLs at once, return only successes
                // Payload: [count:4][ioctl1:4][ioctl2:4]...[input_size:4][input_data:N]
                if payload.len() < 8 {
                    send_error(&mut stream, "Invalid batch scan payload");
                    continue;
                }
                
                let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
                
                if payload.len() < 4 + count * 4 + 4 {
                    send_error(&mut stream, "Batch payload too short");
                    continue;
                }
                
                // Extract IOCTL list
                let mut ioctls = Vec::with_capacity(count);
                for i in 0..count {
                    let offset = 4 + i * 4;
                    let ioctl = u32::from_le_bytes([
                        payload[offset], payload[offset+1], payload[offset+2], payload[offset+3]
                    ]);
                    ioctls.push(ioctl);
                }
                
                // Extract input data
                let input_offset = 4 + count * 4;
                let input_size = u32::from_le_bytes([
                    payload[input_offset], payload[input_offset+1], 
                    payload[input_offset+2], payload[input_offset+3]
                ]) as usize;
                
                let input_data = if input_size > 0 && payload.len() >= input_offset + 4 + input_size {
                    &payload[input_offset + 4..input_offset + 4 + input_size]
                } else {
                    &[]
                };
                
                // Test all IOCTLs and collect successes
                let mut successes: Vec<u32> = Vec::new();
                for ioctl in ioctls {
                    let result = execute_ioctl(handle, ioctl, input_data);
                    total_ioctls += 1;
                    if result.ntstatus == 0 {
                        successes.push(ioctl);
                    }
                }
                
                // Send response: [version:1][status:1][len:4][count:4][ioctl1:4][ioctl2:4]...
                let resp_len = (4 + successes.len() * 4) as u32;
                let mut response = Vec::with_capacity(6 + resp_len as usize);
                response.push(PROTOCOL_VERSION);
                response.push(RESP_OK);
                response.extend_from_slice(&resp_len.to_le_bytes());
                response.extend_from_slice(&(successes.len() as u32).to_le_bytes());
                for ioctl in &successes {
                    response.extend_from_slice(&ioctl.to_le_bytes());
                }
                
                if stream.write_all(&response).is_err() {
                    break;
                }
            }
            
            CMD_SHUTDOWN => {
                println!("\n[*] Shutdown requested by controller");
                break;
            }
            
            _ => {
                send_error(&mut stream, &format!("Unknown command: {}", cmd));
            }
        }
    }
    
    unsafe { CloseHandle(handle).ok() };
    
    let elapsed = start.elapsed().as_secs_f64();
    println!("\n[*] Session stats: {} IOCTLs in {:.1}s ({:.0}/s)", 
             total_ioctls, elapsed, total_ioctls as f64 / elapsed.max(0.001));
    if writes_detected > 0 {
        println!("[🔥] ARBITRARY WRITES DETECTED: {}", writes_detected);
    }
    if type_confusions_found > 0 {
        println!("[🔀] TYPE CONFUSIONS DETECTED: {}", type_confusions_found);
    }
    if leaks_found > 0 {
        println!("[💧] POTENTIAL KERNEL LEAKS: {}", leaks_found);
        println!("     {}", leak_detector.get_summary());
    }
}

struct IoctlResult {
    ntstatus: u32,
    bytes_returned: u32,
    output: Vec<u8>,
    exception_code: u32,  // Non-zero if exception occurred
}

// Global to track last IOCTL for crash reporting
static mut LAST_IOCTL: u32 = 0;
static mut LAST_SIZE: u32 = 0;
static mut LAST_EXCEPTION_CODE: u32 = 0;

// Use jmp_buf for longjmp-style recovery
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
static IN_IOCTL_CALL: AtomicBool = AtomicBool::new(false);
static EXCEPTION_OCCURRED: AtomicBool = AtomicBool::new(false);
static EXCEPTION_CODE_ATOMIC: AtomicU32 = AtomicU32::new(0);

extern "system" fn exception_handler(info: *const EXCEPTION_POINTERS) -> i32 {
    // Only handle if we're in an IOCTL call
    if !IN_IOCTL_CALL.load(Ordering::SeqCst) {
        return 0; // Not our exception, continue search
    }
    
    unsafe {
        if !info.is_null() && !(*info).exception_record.is_null() {
            let record = &*(*info).exception_record;
            let code = record.exception_code;
            
            LAST_EXCEPTION_CODE = code;
            EXCEPTION_CODE_ATOMIC.store(code, Ordering::SeqCst);
            EXCEPTION_OCCURRED.store(true, Ordering::SeqCst);
            
            // Log but DON'T terminate - we'll handle it
            eprintln!("[!] Caught exception 0x{:08X} for IOCTL 0x{:08X} (size {})", 
                     code, LAST_IOCTL, LAST_SIZE);
        }
    }
    0 // EXCEPTION_CONTINUE_SEARCH - process will handle via thread
}

fn execute_ioctl(handle: HANDLE, ioctl_code: u32, input: &[u8]) -> IoctlResult {
    // Track for crash reporting
    unsafe {
        LAST_IOCTL = ioctl_code;
        LAST_SIZE = input.len() as u32;
    }
    
    // Reset exception flags
    EXCEPTION_OCCURRED.store(false, Ordering::SeqCst);
    EXCEPTION_CODE_ATOMIC.store(0, Ordering::SeqCst);
    IN_IOCTL_CALL.store(true, Ordering::SeqCst);
    
    let mut output = vec![0u8; 4096];
    let mut bytes_returned: u32 = 0;
    
    let input_ptr = if input.is_empty() { ptr::null() } else { input.as_ptr() as *const std::ffi::c_void };
    let input_len = input.len() as u32;
    let output_ptr = output.as_mut_ptr() as *mut std::ffi::c_void;
    let output_len = output.len() as u32;
    
    // Use panic::catch_unwind to catch any panics
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe {
            DeviceIoControl(
                handle,
                ioctl_code,
                Some(input_ptr),
                input_len,
                Some(output_ptr),
                output_len,
                Some(&mut bytes_returned),
                None,
            ).is_ok()
        }
    }));
    
    IN_IOCTL_CALL.store(false, Ordering::SeqCst);
    
    // Check if exception occurred
    let exc_code = EXCEPTION_CODE_ATOMIC.load(Ordering::SeqCst);
    if exc_code != 0 || EXCEPTION_OCCURRED.load(Ordering::SeqCst) {
        return IoctlResult {
            ntstatus: 0xC0000005, // Report as access violation
            bytes_returned: 0,
            output: Vec::new(),
            exception_code: exc_code,
        };
    }
    
    // Check if panic occurred
    let success = match result {
        Ok(s) => s,
        Err(_) => {
            return IoctlResult {
                ntstatus: 0xC0000005,
                bytes_returned: 0,
                output: Vec::new(),
                exception_code: EXCEPTION_ACCESS_VIOLATION,
            };
        }
    };
    
    let ntstatus = if success {
        0u32
    } else {
        unsafe { 
            let err = windows::Win32::Foundation::GetLastError();
            match err {
                Ok(_) => 0,
                Err(e) => e.code().0 as u32,
            }
        }
    };
    
    // Trim output to actual returned bytes
    output.truncate(bytes_returned as usize);
    
    IoctlResult {
        ntstatus,
        bytes_returned,
        output,
        exception_code: 0,
    }
}

fn send_error(stream: &mut TcpStream, msg: &str) {
    let msg_bytes = msg.as_bytes();
    let mut response = Vec::with_capacity(6 + msg_bytes.len());
    response.push(PROTOCOL_VERSION);
    response.push(RESP_ERROR);
    response.extend_from_slice(&(msg_bytes.len() as u32).to_le_bytes());
    response.extend_from_slice(msg_bytes);
    stream.write_all(&response).ok();
}
