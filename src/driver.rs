//! Windows Driver I/O Module
//! 
//! Handles communication with Windows kernel drivers via DeviceIoControl.
//! Also provides driver discovery and IOCTL probing.

#![allow(dead_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use colored::*;

use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::Storage::FileSystem::*,
    Win32::System::IO::*,
    Win32::System::Registry::*,
};

/// Driver I/O handler
pub struct DriverIO {
    handle: HANDLE,
    device_path: String,
}

impl DriverIO {
    /// Open a handle to a driver device
    pub fn new(device_path: &str) -> windows::core::Result<Self> {
        let wide_path: Vec<u16> = OsStr::new(device_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?
        };
        
        Ok(Self {
            handle,
            device_path: device_path.to_string(),
        })
    }
    
    /// Get raw handle value
    pub fn handle(&self) -> isize {
        self.handle.0 as isize
    }
    
    /// Send IOCTL to driver
    /// Returns bytes written to output buffer on success, or error code on failure
    pub fn send_ioctl(&mut self, ioctl_code: u32, input: &[u8], output: &mut [u8]) -> std::result::Result<u32, i32> {
        let mut bytes_returned: u32 = 0;
        
        let input_ptr = if input.is_empty() {
            None
        } else {
            Some(input.as_ptr() as *const std::ffi::c_void)
        };
        
        let output_ptr = if output.is_empty() {
            None
        } else {
            Some(output.as_mut_ptr() as *mut std::ffi::c_void)
        };
        
        let result = unsafe {
            DeviceIoControl(
                self.handle,
                ioctl_code,
                input_ptr,
                input.len() as u32,
                output_ptr,
                output.len() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };
        
        match result {
            Ok(_) => Ok(bytes_returned),
            Err(e) => Err(e.code().0),
        }
    }
    
    /// Send IOCTL with raw pointers (for METHOD_NEITHER testing)
    /// WARNING: This can crash the kernel if driver doesn't validate!
    pub fn send_ioctl_raw(
        &mut self, 
        ioctl_code: u32, 
        input_ptr: usize,
        input_len: u32,
        output_ptr: usize,
        output_len: u32,
    ) -> std::result::Result<u32, i32> {
        let mut bytes_returned: u32 = 0;
        
        let result = unsafe {
            DeviceIoControl(
                self.handle,
                ioctl_code,
                if input_ptr == 0 { None } else { Some(input_ptr as *const std::ffi::c_void) },
                input_len,
                if output_ptr == 0 { None } else { Some(output_ptr as *mut std::ffi::c_void) },
                output_len,
                Some(&mut bytes_returned),
                None,
            )
        };
        
        match result {
            Ok(_) => Ok(bytes_returned),
            Err(e) => Err(e.code().0),
        }
    }
    
    /// Send IOCTL (simplified, returns owned buffer)
    pub fn send_ioctl_owned(&mut self, ioctl_code: u32, input: &[u8]) -> windows::core::Result<Vec<u8>> {
        let mut output = vec![0u8; 4096];
        let mut bytes_returned: u32 = 0;
        
        let input_ptr = if input.is_empty() {
            None
        } else {
            Some(input.as_ptr() as *const std::ffi::c_void)
        };
        
        let result = unsafe {
            DeviceIoControl(
                self.handle,
                ioctl_code,
                input_ptr,
                input.len() as u32,
                Some(output.as_mut_ptr() as *mut std::ffi::c_void),
                output.len() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };
        
        match result {
            Ok(_) => {
                output.truncate(bytes_returned as usize);
                Ok(output)
            }
            Err(e) => Err(e),
        }
    }
    
    /// Probe an IOCTL to check if it's implemented
    pub fn probe_ioctl(&mut self, ioctl_code: u32) -> IoctlProbeResult {
        let test_inputs: Vec<&[u8]> = vec![
            &[],
            &[0u8; 4],
            &[0u8; 16],
            &[0u8; 64],
            &[0xFFu8; 16],
        ];
        
        let mut output = vec![0u8; 4096];
        
        for input in test_inputs {
            match self.send_ioctl(ioctl_code, input, &mut output) {
                Ok(bytes) => {
                    return IoctlProbeResult::Implemented {
                        output_size: bytes as usize,
                        input_size: input.len(),
                    };
                }
                Err(code) => {
                    let code_u = code as u32;
                    
                    // These errors suggest IOCTL IS implemented but needs different input
                    if matches!(code_u,
                        0x80070057 |  // ERROR_INVALID_PARAMETER
                        0x8007007A |  // ERROR_INSUFFICIENT_BUFFER
                        0x80070018 |  // ERROR_BAD_LENGTH
                        0x8007000D    // ERROR_INVALID_DATA
                    ) {
                        return IoctlProbeResult::Implemented {
                            output_size: 0,
                            input_size: input.len(),
                        };
                    }
                }
            }
        }
        
        IoctlProbeResult::NotImplemented
    }
}

impl Drop for DriverIO {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle).ok();
        }
    }
}

/// Result of probing an IOCTL
#[derive(Debug)]
pub enum IoctlProbeResult {
    Implemented { output_size: usize, input_size: usize },
    NotImplemented,
}

/// Discover available drivers on the system
pub fn discover_drivers() {
    println!("{}", "[*] Scanning for accessible drivers...".yellow());
    
    // ============================================================
    // COMPREHENSIVE LIST OF WINDOWS ATTACK SURFACES
    // Based on real CVEs and historical vulnerabilities
    // ============================================================
    
    let security_critical_drivers = vec![
        // === CLFS - CVE-2025-29824 (Ransomware UAF!) ===
        (r"\\.\Clfs", "CLFS - Common Log File System (CVE-2025-29824 UAF!)"),
        
        // === Kernel Streaming - Many CVEs ===
        (r"\\.\Ks", "Kernel Streaming (multiple CVEs)"),
        (r"\\.\KsThunk", "Kernel Streaming Thunk"),
        
        // === Network Drivers - AFD/TDI/NSI ===
        (r"\\.\Afd", "AFD - Ancillary Function Driver (Winsock)"),
        (r"\\.\Nsi", "NSI - Network Store Interface"),
        (r"\\.\Tcp", "TCP/IP Driver"),
        (r"\\.\Udp", "UDP Driver"),
        (r"\\.\Ip", "IP Driver"),
        (r"\\.\RawIp", "Raw IP Driver"),
        (r"\\.\GLOBALROOT\Device\Afd", "AFD (alt path)"),
        (r"\\.\GLOBALROOT\Device\Nsi", "NSI (alt path)"),
        (r"\\.\GLOBALROOT\Device\Tcp", "TCP (alt path)"),
        
        // === File System Drivers ===
        (r"\\.\Ntfs", "NTFS File System"),
        (r"\\.\FastFat", "FAT File System"),
        (r"\\.\Refs", "ReFS File System"),
        (r"\\.\MRxSmb", "SMB Redirector"),
        (r"\\.\Rdbss", "RDBSS (Redirected Drive Buffering)"),
        
        // === Storage Drivers ===
        (r"\\.\PhysicalDrive0", "Physical Disk 0"),
        (r"\\.\PhysicalDrive1", "Physical Disk 1"),
        (r"\\.\Volume{", "Volume GUID"),
        (r"\\.\spaceport", "Storage Spaces"),
        (r"\\.\vdrvroot", "Virtual Disk"),
        (r"\\.\PartMgr", "Partition Manager"),
        (r"\\.\MountPointManager", "Mount Point Manager"),
        
        // === Security/Crypto Drivers - HIGH VALUE ===
        (r"\\.\TPM", "TPM - Trusted Platform Module"),
        (r"\\.\PEAUTH", "Protected Environment Auth (DRM)"),
        (r"\\.\WindowsTrustedRT", "Windows Trusted Runtime"),
        (r"\\.\WindowsTrustedRTProxy", "Windows Trusted RT Proxy"),
        (r"\\.\CNG", "CNG - Crypto Next Gen"),
        (r"\\.\KSecDD", "Kernel Security Device"),
        
        // === Print Spooler - PrintNightmare etc ===
        (r"\\.\Spooler", "Print Spooler"),
        (r"\\.\Print", "Print Driver"),
        
        // === Graphics/Display - Win32k adjacent ===
        (r"\\.\DxgKrnl", "DirectX Graphics Kernel"),
        (r"\\.\Dxg", "DirectX Graphics"),
        (r"\\.\NvidiaDxgKrnl", "NVIDIA DxgKrnl"),
        (r"\\.\AMD", "AMD GPU Driver"),
        (r"\\.\Intel", "Intel GPU Driver"),
        
        // === Win32k related (limited usermode access) ===
        (r"\\.\Win32k", "Win32k (unlikely accessible)"),
        
        // === HTTP.sys - Remote attack surface ===
        (r"\\.\HTTP", "HTTP.sys"),
        (r"\\.\Http\AppPool", "HTTP AppPool"),
        
        // === Multimedia/Streaming ===
        (r"\\.\Video0", "Video Device 0"),
        (r"\\.\WMVideo", "WM Video"),
        (r"\\.\Audio0", "Audio Device 0"),
        
        // === Hyper-V (if present) ===
        (r"\\.\VmGenerationCounter", "Hyper-V Gen Counter"),
        (r"\\.\VmGid", "Hyper-V GID"),
        (r"\\.\VMBusVideoAdapterGuid", "VMBus Video"),
        
        // === WMI/Management ===
        (r"\\.\WMIDataDevice", "WMI Data Device"),
        (r"\\.\ACPI", "ACPI"),
        (r"\\.\ACPI_HAL", "ACPI HAL"),
        
        // === Misc high-value ===
        (r"\\.\ahcache", "App Compat Cache"),
        (r"\\.\DeviceApi", "Device API"),
        (r"\\.\BattC", "Battery"),
        (r"\\.\ConDrv", "Console Driver"),
        (r"\\.\NtfsLog", "NTFS Log"),
        (r"\\.\Ndis", "NDIS Network Driver"),
        (r"\\.\NdisWan", "NDIS WAN"),
        
        // === Filter Managers ===
        (r"\\.\FltMgr", "Filter Manager"),
        (r"\\.\FltMgrMsg", "Filter Manager Message"),
        
        // === NULL/Test ===
        (r"\\.\GLOBALROOT\Device\Null", "Null Device"),
    ];
    
    let mut accessible: Vec<(&str, &str)> = Vec::new();
    let mut needs_special: Vec<(&str, &str)> = Vec::new();
    let mut denied: Vec<&str> = Vec::new();
    
    for (device, description) in &security_critical_drivers {
        match DriverIO::new(device) {
            Ok(driver) => {
                println!("  {} {} - {} (handle: 0x{:X})", 
                    "[OPEN]".green().bold(), device, description, driver.handle());
                accessible.push((device, description));
            }
            Err(e) => {
                let code = e.code().0 as u32;
                if code == 0x80070005 { // ACCESS_DENIED
                    denied.push(device);
                } else if code == 0x80070002 || code == 0x80070003 { // NOT_FOUND
                    // Skip silently
                } else {
                    // Might need special access method
                    println!("  {} {} - {} (error: 0x{:08X})", 
                        "[SPECIAL]".yellow(), device, description, code);
                    needs_special.push((device, description));
                }
            }
        }
    }
    
    // Also enumerate from registry
    println!("\n{}", "[*] Enumerating driver services from registry...".yellow());
    enumerate_driver_services();
    
    // Summary
    println!("\n{}", "═".repeat(70).cyan());
    println!("{}", "                    SCAN RESULTS SUMMARY".cyan().bold());
    println!("{}", "═".repeat(70).cyan());
    
    println!("\n{} {} drivers accessible from usermode!", 
        "[+]".green().bold(), accessible.len());
    
    if !accessible.is_empty() {
        println!("\n{}", "┌─ ACCESSIBLE (Can fuzz directly) ─────────────────────────────────┐".green());
        for (dev, desc) in &accessible {
            println!("│  {} - {}", dev, desc);
        }
        println!("{}", "└──────────────────────────────────────────────────────────────────┘".green());
    }
    
    if !needs_special.is_empty() {
        println!("\n{}", "┌─ NEEDS SPECIAL ACCESS ───────────────────────────────────────────┐".yellow());
        for (dev, desc) in &needs_special {
            println!("│  {} - {}", dev, desc);
        }
        println!("{}", "└──────────────────────────────────────────────────────────────────┘".yellow());
    }
    
    println!("\n{}", "═".repeat(70).cyan());
    println!("{}", "                    RECOMMENDED ACTIONS".cyan().bold());
    println!("{}", "═".repeat(70).cyan());
    
    println!("
  For each accessible driver, run:
  
    {} --device \"DEVICE\" --probe
    {} --device \"DEVICE\" --auto
  
  High-value targets for bounties:
    1. {} - CVE-2025-29824 style (use --clfs mode!)
    2. {} - Crypto bugs = $$$  
    3. {} - DRM bypass = $$$
    4. {} - Network stack bugs
    5. {} - Storage bugs
",
        "windriver_fuzzer.exe".cyan(),
        "windriver_fuzzer.exe".cyan(),
        "CLFS".red().bold(),
        "TPM".yellow().bold(),
        "PEAUTH".yellow().bold(),
        "AFD/NSI".yellow(),
        "spaceport".yellow(),
    );
    
    // Special note about CLFS
    println!("{}", "═".repeat(70).red());
    println!("{}", "  🔥 CLFS NOTE: Use --clfs mode (file-based, no device handle needed!)".red().bold());
    println!("{}", "═".repeat(70).red());
}

/// Enumerate driver services from registry
fn enumerate_driver_services() {
    let hklm = HKEY_LOCAL_MACHINE;
    let subkey = "SYSTEM\\CurrentControlSet\\Services";
    
    let wide_subkey: Vec<u16> = OsStr::new(subkey)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    
    let mut hkey = HKEY::default();
    
    let result = unsafe {
        RegOpenKeyExW(
            hklm,
            PCWSTR(wide_subkey.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
    };
    
    if result.is_err() {
        println!("  {} Could not open registry", "[-]".red());
        return;
    }
    
    // Enumerate subkeys (driver names)
    let mut index = 0u32;
    let mut driver_count = 0;
    
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        
        let result = unsafe {
            RegEnumKeyExW(
                hkey,
                index,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                PWSTR::null(),
                None,
                None,
            )
        };
        
        if result.is_err() {
            break;
        }
        
        // name_buf contains the service name, but we're just counting
        let _name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        
        // Check if it's a kernel driver (Type = 1 or 2)
        // For simplicity, just count them
        driver_count += 1;
        index += 1;
    }
    
    unsafe { RegCloseKey(hkey).ok(); }
    
    println!("  {} Found {} registered driver services", 
        "[*]".cyan(), driver_count);
}

/// Generate IOCTL code using Windows CTL_CODE macro
pub fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// Decode IOCTL code into components and return as string
pub fn ioctl_decode(code: u32) -> String {
    let device_type = (code >> 16) & 0xFFFF;
    let access = (code >> 14) & 0x3;
    let function = (code >> 2) & 0xFFF;
    let method = code & 0x3;
    
    let method_str = match method {
        0 => "BUFFERED",
        1 => "IN_DIRECT",
        2 => "OUT_DIRECT",
        3 => "NEITHER",
        _ => "UNKNOWN",
    };
    
    let access_str = match access {
        0 => "ANY",
        1 => "READ",
        2 => "WRITE",
        3 => "READ|WRITE",
        _ => "UNKNOWN",
    };
    
    format!("Type={} Func={} Method={} Access={}", 
        device_type, function, method_str, access_str)
}

/// Decode IOCTL code into raw components
pub fn ioctl_decode_raw(code: u32) -> (u32, u32, u32, u32) {
    let device_type = (code >> 16) & 0xFFFF;
    let access = (code >> 14) & 0x3;
    let function = (code >> 2) & 0xFFF;
    let method = code & 0x3;
    (device_type, function, method, access)
}
