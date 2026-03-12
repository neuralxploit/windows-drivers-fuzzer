// Driver Hunter Module
// Finds and targets 3rd party drivers for IOCTL fuzzing
// Based on techniques from Connor McGarr's talk on kernel exploitation

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows::Win32::Foundation::*;
use windows::Win32::System::ProcessStatus::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Security::*;

// ═══════════════════════════════════════════════════════════════════════════
// KUSER_SHARED_DATA - Fixed address shared between kernel and userland
// Connor McGarr technique: Use this for data-only attacks / known address pivot
// ═══════════════════════════════════════════════════════════════════════════

/// KUSER_SHARED_DATA usermode address (same on all Windows x64)
pub const KUSER_SHARED_DATA_USER: usize = 0x7FFE0000;

/// KUSER_SHARED_DATA kernel address (same on all Windows x64)
pub const KUSER_SHARED_DATA_KERNEL: usize = 0xFFFFF78000000000;

/// Useful offsets within KUSER_SHARED_DATA for exploitation
pub mod kuser_offsets {
    pub const SYSTEM_TIME: usize = 0x014;           // KSYSTEM_TIME
    pub const TICK_COUNT: usize = 0x320;            // KSYSTEM_TIME  
    pub const COOKIE: usize = 0x330;                // Stack cookie seed
    pub const SYSTEM_CALL: usize = 0x308;           // SystemCall (int 2e vs syscall)
    pub const TESTRET_INSTRUCTION: usize = 0x9F0;  // Test/ret gadget location
    pub const INTERRUPT_TIME: usize = 0x008;        // Interrupt time
    pub const IMAGE_NUMBER_LOW: usize = 0x02C;      // Image subsystem numbers
    pub const IMAGE_NUMBER_HIGH: usize = 0x02E;
}

/// Read data from KUSER_SHARED_DATA (always accessible, no admin needed!)
pub fn read_kuser_shared_data() -> KUserSharedData {
    unsafe {
        let ptr = KUSER_SHARED_DATA_USER as *const u8;
        
        KUserSharedData {
            user_address: KUSER_SHARED_DATA_USER,
            kernel_address: KUSER_SHARED_DATA_KERNEL,
            stack_cookie: *(ptr.add(kuser_offsets::COOKIE) as *const u32),
            system_call_type: *ptr.add(kuser_offsets::SYSTEM_CALL),
            // TestRet gadget at KUSER_SHARED_DATA+0x9F0 - useful for SMEP bypass
            testret_user: KUSER_SHARED_DATA_USER + kuser_offsets::TESTRET_INSTRUCTION,
            testret_kernel: KUSER_SHARED_DATA_KERNEL + kuser_offsets::TESTRET_INSTRUCTION,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KUserSharedData {
    pub user_address: usize,
    pub kernel_address: usize,
    pub stack_cookie: u32,
    pub system_call_type: u8,  // 0 = int 2e, 1 = syscall
    pub testret_user: usize,   // test al, al; ret gadget
    pub testret_kernel: usize,
}

/// Dump KUSER_SHARED_DATA info (NO ADMIN REQUIRED!)
pub fn dump_kuser_shared_data() {
    println!("[*] 📍 KUSER_SHARED_DATA (Fixed address - NO ADMIN NEEDED!)\n");
    
    let kuser = read_kuser_shared_data();
    
    println!("    ┌─────────────────────────────────────────────────────────────┐");
    println!("    │ User Address:   0x{:016X}                   │", kuser.user_address);
    println!("    │ Kernel Address: 0x{:016X}                   │", kuser.kernel_address);
    println!("    └─────────────────────────────────────────────────────────────┘");
    println!();
    println!("    Stack Cookie Seed:  0x{:08X}", kuser.stack_cookie);
    println!("    SystemCall Type:    {} ({})", kuser.system_call_type, 
             if kuser.system_call_type == 1 { "syscall" } else { "int 2e" });
    println!();
    println!("    [!] TestRet Gadget (SMEP bypass):");
    println!("        User:   0x{:016X}", kuser.testret_user);
    println!("        Kernel: 0x{:016X}", kuser.testret_kernel);
    println!();
    println!("    [*] Connor McGarr technique:");
    println!("        - KUSER_SHARED_DATA is at KNOWN ADDRESS in kernel");
    println!("        - Can use for data-only attacks without info leak");
    println!("        - Kernel address 0x{:X} is ALWAYS valid", KUSER_SHARED_DATA_KERNEL);
}

// ═══════════════════════════════════════════════════════════════════════════
// Admin/Privilege Checking
// ═══════════════════════════════════════════════════════════════════════════

/// Check if running as Administrator
pub fn is_admin() -> bool {
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token,
        ).is_err() {
            return false;
        }
        
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size: u32 = 0;
        
        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        
        let _ = CloseHandle(token);
        
        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// NtQuerySystemInformation - Kernel Base Address Leak (Connor McGarr technique)
// ═══════════════════════════════════════════════════════════════════════════

/// SystemModuleInformation class for NtQuerySystemInformation
const SYSTEM_MODULE_INFORMATION: u32 = 11;

/// RTL_PROCESS_MODULE_INFORMATION structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RtlProcessModuleInformation {
    pub section: usize,
    pub mapped_base: usize,
    pub image_base: usize,        // <-- This is the kernel VA we want!
    pub image_size: u32,
    pub flags: u32,
    pub load_order_index: u16,
    pub init_order_index: u16,
    pub load_count: u16,
    pub offset_to_file_name: u16,
    pub full_path_name: [u8; 256],
}

/// RTL_PROCESS_MODULES header + modules array
#[repr(C)]
pub struct RtlProcessModules {
    pub number_of_modules: u32,
    pub modules: [RtlProcessModuleInformation; 1], // Variable length array
}

/// Kernel module info with base address (leaked from userland!)
#[derive(Debug, Clone)]
pub struct KernelModuleInfo {
    pub name: String,
    pub full_path: String,
    pub base_address: usize,  // Kernel virtual address - the golden ticket
    pub size: u32,
    pub load_order: u16,
}

// Link to ntdll.dll for NtQuerySystemInformation
#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut std::ffi::c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32; // NTSTATUS
}

/// Get kernel base address (ntoskrnl.exe) - THE key primitive for exploitation
/// This is what Connor McGarr uses for IAT overwrites and gadget finding
pub fn get_kernel_base() -> Option<usize> {
    let modules = enumerate_kernel_modules().ok()?;
    
    // First module is always ntoskrnl.exe (or ntkrnlpa.exe, etc.)
    modules.first().map(|m| m.base_address)
}

/// Get base address of a specific kernel module by name
pub fn get_module_base(module_name: &str) -> Option<usize> {
    let modules = enumerate_kernel_modules().ok()?;
    let name_lower = module_name.to_lowercase();
    
    modules.iter()
        .find(|m| m.name.to_lowercase().contains(&name_lower))
        .map(|m| m.base_address)
}

/// Enumerate ALL kernel modules using NtQuerySystemInformation
/// Returns base addresses that can be used for:
/// - Gadget finding (ROP chains)
/// - IAT overwrite calculations
/// - Driver targeting
pub fn enumerate_kernel_modules() -> Result<Vec<KernelModuleInfo>, String> {
    unsafe {
        // First call to get required buffer size
        let mut return_length: u32 = 0;
        let status = NtQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut return_length,
        );
        
        // STATUS_INFO_LENGTH_MISMATCH = 0xC0000004 is expected
        if status != 0xC0000004u32 as i32 && status != 0 {
            return Err(format!("NtQuerySystemInformation failed with status: 0x{:X}", status as u32));
        }
        
        // Allocate buffer with some extra space
        let buffer_size = return_length + 0x1000;
        let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
        
        // Second call to get actual data
        let status = NtQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION,
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            buffer_size,
            &mut return_length,
        );
        
        if status != 0 {
            return Err(format!("NtQuerySystemInformation failed: 0x{:X}", status as u32));
        }
        
        // Parse the RTL_PROCESS_MODULES structure
        // On 64-bit, the structure is:
        //   NumberOfModules: u32 (4 bytes)
        //   Padding: 4 bytes (for alignment)
        //   Modules[]: array of RTL_PROCESS_MODULE_INFORMATION
        
        let num_modules = *(buffer.as_ptr() as *const u32);
        
        let mut result = Vec::new();
        
        // Get pointer to first module - after u32 count + padding on x64
        // sizeof(usize) accounts for pointer alignment
        let modules_ptr = (buffer.as_ptr() as usize + std::mem::size_of::<usize>()) 
                          as *const RtlProcessModuleInformation;
        
        for i in 0..num_modules {
            let module = &*modules_ptr.add(i as usize);
            
            // Extract module name from full path
            let full_path = std::str::from_utf8(&module.full_path_name)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();
            
            let name = full_path
                .rsplit('\\')
                .next()
                .unwrap_or(&full_path)
                .to_string();
            
            result.push(KernelModuleInfo {
                name,
                full_path,
                base_address: module.image_base,  // THE LEAKED KERNEL ADDRESS
                size: module.image_size,
                load_order: module.load_order_index,
            });
        }
        
        Ok(result)
    }
}

/// Print all kernel modules with their base addresses
/// This is what exploit devs use to find targets
pub fn dump_kernel_modules() {
    // Check admin first!
    if !is_admin() {
        println!("[!] ⚠️  NOT RUNNING AS ADMINISTRATOR!");
        println!("[!] NtQuerySystemInformation(SystemModuleInformation) requires elevation.");
        println!("[!] Kernel base addresses will show as 0x0000000000000000\n");
        println!("[*] Run as Admin to leak kernel addresses, or use KUSER_SHARED_DATA:\n");
        dump_kuser_shared_data();
        println!();
        return;
    }
    
    println!("[+] ✅ Running as Administrator - can leak kernel addresses!\n");
    println!("[*] 🔓 Leaking kernel module addresses via NtQuerySystemInformation...\n");
    
    match enumerate_kernel_modules() {
        Ok(modules) => {
            println!("[+] Found {} kernel modules:\n", modules.len());
            
            // ntoskrnl is always first - most important
            if let Some(nt) = modules.first() {
                println!("    ┌─────────────────────────────────────────────────────────────┐");
                println!("    │ 🎯 NTOSKRNL BASE: 0x{:016X}  ({})  │", nt.base_address, nt.name);
                println!("    └─────────────────────────────────────────────────────────────┘\n");
            }
            
            // Find win32k if loaded
            if let Some(win32k) = modules.iter().find(|m| m.name.to_lowercase().contains("win32k")) {
                println!("    [*] win32k.sys  @ 0x{:016X} (GUI subsystem)", win32k.base_address);
            }
            
            // Show all modules
            println!("\n    {:^18} {:^12} {}", "Base Address", "Size", "Module");
            println!("    {} {} {}", "─".repeat(18), "─".repeat(12), "─".repeat(40));
            
            for m in &modules {
                let marker = if m.name.to_lowercase().contains("ntoskrnl") {
                    "★"
                } else if KNOWN_VULNERABLE_DRIVERS.iter().any(|(n, _, _)| m.name.to_lowercase().contains(&n.to_lowercase().replace(".sys", ""))) {
                    "🎯"
                } else if !is_microsoft_driver(&m.name, &PathBuf::from(&m.full_path)) {
                    "•"
                } else {
                    " "
                };
                
                println!("    0x{:016X}  {:>10}  {} {}", 
                         m.base_address, 
                         format_size(m.size),
                         marker,
                         m.name);
            }
            
            println!("\n    Legend: ★ = Kernel  🎯 = Known Vulnerable  • = Third-party");
        }
        Err(e) => {
            println!("[-] Failed to enumerate kernel modules: {}", e);
            println!("    (May require elevation or be blocked by security software)");
        }
    }
}

fn format_size(bytes: u32) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Known Vulnerable Drivers Database
// ═══════════════════════════════════════════════════════════════════════════

/// Known vulnerable 3rd party drivers (from public research)
pub const KNOWN_VULNERABLE_DRIVERS: &[(&str, &str, u32)] = &[
    // (driver_name, device_path, known_ioctl)
    ("dbutil_2_3.sys", "\\\\.\\DBUtil_2_3", 0x9B0C1EC0),      // Dell - R/W primitive
    ("RTCore64.sys", "\\\\.\\RTCore64", 0x80002048),          // MSI Afterburner - R/W
    ("AsIO64.sys", "\\\\.\\Asusgio2", 0xA040240C),            // ASUS - Physical memory R/W
    ("WinRing0x64.sys", "\\\\.\\WinRing0_1_2_0", 0x9C402084), // Various - MSR R/W
    ("ATSZIO64.sys", "\\\\.\\ATSZIO", 0x8807200C),            // ASMedia - Port I/O
    ("phymemx64.sys", "\\\\.\\PhyMem64", 0x80002000),         // Physical memory access
    ("gdrv.sys", "\\\\.\\GIO", 0xC3502808),                    // GIGABYTE - R/W primitive
    ("AsrDrv106.sys", "\\\\.\\AsrDrv106", 0x22E01C),          // ASRock - Physical R/W
    ("MsIo64.sys", "\\\\.\\MsIo", 0x80102040),                // MSI - R/W primitive
    ("HwRwDrv.sys", "\\\\.\\HwRwDrv", 0x8000204C),            // Huawei - R/W primitive
    ("inpoutx64.sys", "\\\\.\\inpoutx64", 0x9C402410),        // Port I/O
    ("AMDRyzenMasterDriver.sys", "\\\\.\\AMDRyzenMasterDriverV17", 0x81112F04), // AMD
    ("ene.sys", "\\\\.\\ENE_Link", 0x80102040),               // ENE Technology
];

/// Extended list of device paths to probe (NO ADMIN NEEDED!)
/// These are common 3rd party driver device names
pub const DEVICE_PATHS_TO_PROBE: &[(&str, &str, &str)] = &[
    // (device_path, driver_name, vendor)
    // MSI / Microstar
    ("\\\\.\\RTCore64", "RTCore64.sys", "MSI (Afterburner)"),
    ("\\\\.\\RTCore32", "RTCore32.sys", "MSI (Afterburner)"),
    ("\\\\.\\MsIo", "MsIo64.sys", "MSI"),
    
    // ASUS
    ("\\\\.\\Asusgio2", "AsIO64.sys", "ASUS"),
    ("\\\\.\\Asusgio3", "AsIO3.sys", "ASUS"),
    ("\\\\.\\ASUS_XONE", "asus_xone.sys", "ASUS"),
    ("\\\\.\\AsUpIO", "AsUpIO.sys", "ASUS"),
    
    // GIGABYTE  
    ("\\\\.\\GIO", "gdrv.sys", "GIGABYTE"),
    ("\\\\.\\GPCIDrv", "GPCIDrv64.sys", "GIGABYTE"),
    
    // Dell
    ("\\\\.\\DBUtil_2_3", "dbutil_2_3.sys", "Dell"),
    ("\\\\.\\DBUtilDrv2", "DBUtilDrv2.sys", "Dell"),
    
    // ASRock
    ("\\\\.\\AsrDrv106", "AsrDrv106.sys", "ASRock"),
    ("\\\\.\\AsrAutoChkUpdDrv", "AsrAutoChkUpdDrv.sys", "ASRock"),
    
    // AMD
    ("\\\\.\\AMDRyzenMasterDriverV17", "AMDRyzenMasterDriver.sys", "AMD"),
    ("\\\\.\\AMDRyzenMasterDriverV19", "AMDRyzenMasterDriver.sys", "AMD"),
    
    // Intel
    ("\\\\.\\Nal", "iqvw64e.sys", "Intel (Network Adapter)"),
    ("\\\\.\\IQVWDrv", "IQVWDrv.sys", "Intel"),
    
    // HWiNFO
    ("\\\\.\\HWiNFO64", "HWiNFO64.sys", "HWiNFO"),
    ("\\\\.\\HWiNFO32", "HWiNFO32.sys", "HWiNFO"),
    
    // CPU-Z
    ("\\\\.\\cpuz141", "cpuz141_x64.sys", "CPUID (CPU-Z)"),
    ("\\\\.\\cpuz153", "cpuz153_x64.sys", "CPUID (CPU-Z)"),
    
    // WinRing0 (used by many tools)
    ("\\\\.\\WinRing0_1_2_0", "WinRing0x64.sys", "WinRing0"),
    ("\\\\.\\WinRing0", "WinRing0.sys", "WinRing0"),
    
    // EVGA
    ("\\\\.\\EVGA_USB", "evga_usb.sys", "EVGA"),
    
    // Corsair
    ("\\\\.\\CorsairLLAccess64", "CorsairLLAccess64.sys", "Corsair"),
    
    // NZXT
    ("\\\\.\\NzxtCOM", "NzxtCOM.sys", "NZXT"),
    
    // Razer
    ("\\\\.\\RzDev", "rzdev.sys", "Razer"),
    
    // ENE Technology
    ("\\\\.\\ENE_Link", "ene.sys", "ENE Technology"),
    ("\\\\.\\ENE_Feature", "ene.sys", "ENE Technology"),
    
    // Generic physical memory / port I/O
    ("\\\\.\\PhyMem64", "phymemx64.sys", "Physical Memory"),
    ("\\\\.\\inpoutx64", "inpoutx64.sys", "Port I/O"),
    
    // NVIDIA
    ("\\\\.\\NvDrv", "nvoclock.sys", "NVIDIA"),
    
    // Huawei
    ("\\\\.\\HwRwDrv", "HwRwDrv.sys", "Huawei"),
    
    // ASMedia
    ("\\\\.\\ATSZIO", "ATSZIO64.sys", "ASMedia"),
    
    // EVGA Precision / various
    ("\\\\.\\EVGA_ELEET", "eleetx1.sys", "EVGA"),
    
    // Speedfan
    ("\\\\.\\speedfan", "speedfan.sys", "SpeedFan"),
    
    // Open Hardware Monitor / LibreHardwareMonitor
    ("\\\\.\\WinRing0_1_0_1", "WinRing0.sys", "LibreHardwareMonitor"),
    ("\\\\.\\WinRing0_1_2_0", "WinRing0x64.sys", "OpenHardwareMonitor"),
    
    // AIDA64
    ("\\\\.\\AIDA64Driver", "AIDA64Driver.sys", "AIDA64"),
];

/// Driver information gathered from system
#[derive(Debug, Clone)]
pub struct DriverInfo {
    pub name: String,
    pub path: PathBuf,
    pub base_address: usize,
    pub device_path: Option<String>,
    pub vendor: Option<String>,
    pub is_microsoft: bool,
    pub is_known_vulnerable: bool,
}

/// Result of driver enumeration
pub struct DriverScanResult {
    pub all_drivers: Vec<DriverInfo>,
    pub third_party: Vec<DriverInfo>,
    pub vulnerable: Vec<DriverInfo>,
    pub microsoft: Vec<DriverInfo>,
}

/// Enumerate all loaded kernel drivers
pub fn enumerate_drivers() -> Result<DriverScanResult, String> {
    let mut drivers = Vec::new();
    
    unsafe {
        // Get list of all driver base addresses
        let mut needed: u32 = 0;
        let mut driver_bases: Vec<*mut std::ffi::c_void> = vec![std::ptr::null_mut(); 1024];
        
        let result = EnumDeviceDrivers(
            driver_bases.as_mut_ptr(),
            (driver_bases.len() * std::mem::size_of::<*mut std::ffi::c_void>()) as u32,
            &mut needed,
        );
        
        if result.is_err() {
            return Err("Failed to enumerate device drivers".to_string());
        }
        
        let count = needed as usize / std::mem::size_of::<*mut std::ffi::c_void>();
        
        for i in 0..count {
            let base = driver_bases[i];
            if base.is_null() {
                continue;
            }
            
            // Get driver name
            let mut name_buf: [u16; 260] = [0; 260];
            let name_len = GetDeviceDriverBaseNameW(base, &mut name_buf);
            
            if name_len == 0 {
                continue;
            }
            
            let name = OsString::from_wide(&name_buf[..name_len as usize])
                .to_string_lossy()
                .to_string();
            
            // Get full path
            let mut path_buf: [u16; 260] = [0; 260];
            let path_len = GetDeviceDriverFileNameW(base, &mut path_buf);
            
            let path = if path_len > 0 {
                let path_str = OsString::from_wide(&path_buf[..path_len as usize])
                    .to_string_lossy()
                    .to_string();
                // Convert \SystemRoot\ to actual path
                PathBuf::from(path_str.replace("\\SystemRoot\\", "C:\\Windows\\"))
            } else {
                PathBuf::new()
            };
            
            // Check if Microsoft driver
            let is_microsoft = is_microsoft_driver(&name, &path);
            
            // Check if known vulnerable
            let known_vuln = KNOWN_VULNERABLE_DRIVERS.iter()
                .find(|(drv_name, _, _)| name.to_lowercase() == drv_name.to_lowercase());
            
            let device_path = known_vuln.map(|(_, dev, _)| dev.to_string());
            
            let info = DriverInfo {
                name: name.clone(),
                path,
                base_address: base as usize,
                device_path,
                vendor: extract_vendor(&name),
                is_microsoft,
                is_known_vulnerable: known_vuln.is_some(),
            };
            
            drivers.push(info);
        }
    }
    
    // Categorize drivers
    let third_party: Vec<_> = drivers.iter()
        .filter(|d| !d.is_microsoft)
        .cloned()
        .collect();
    
    let vulnerable: Vec<_> = drivers.iter()
        .filter(|d| d.is_known_vulnerable)
        .cloned()
        .collect();
    
    let microsoft: Vec<_> = drivers.iter()
        .filter(|d| d.is_microsoft)
        .cloned()
        .collect();
    
    Ok(DriverScanResult {
        all_drivers: drivers,
        third_party,
        vulnerable,
        microsoft,
    })
}

/// Check if a driver is from Microsoft
fn is_microsoft_driver(name: &str, path: &PathBuf) -> bool {
    let name_lower = name.to_lowercase();
    
    // Known Microsoft driver patterns
    let ms_patterns = [
        "nt", "hal", "ci.dll", "win32k", "dxgkrnl", "ndis", "tcpip",
        "afd", "http", "fltmgr", "ksecdd", "cng", "clfs", "volsnap",
        "disk", "partmgr", "storport", "nvme", "usbhub", "usbport",
        "hid", "kbdclass", "mouclass", "acpi", "pci", "intelppm",
        "msrpc", "srv", "nfs", "mrxsmb", "rdbss", "npfs", "msfs",
    ];
    
    for pattern in ms_patterns {
        if name_lower.contains(pattern) {
            return true;
        }
    }
    
    // Check path for Windows directory
    if let Some(path_str) = path.to_str() {
        let path_lower = path_str.to_lowercase();
        if path_lower.contains("\\windows\\system32\\drivers\\") {
            // Most System32\drivers are Microsoft
            // But some 3rd party install there too
            // Check for known 3rd party names
            for (vuln_name, _, _) in KNOWN_VULNERABLE_DRIVERS {
                if name_lower == vuln_name.to_lowercase() {
                    return false;
                }
            }
        }
    }
    
    false
}

/// Extract vendor from driver name
fn extract_vendor(name: &str) -> Option<String> {
    let name_lower = name.to_lowercase();
    
    let vendors = [
        ("dbutil", "Dell"),
        ("rtcore", "MSI"),
        ("asio", "ASUS"),
        ("asus", "ASUS"),
        ("gdrv", "GIGABYTE"),
        ("gigabyte", "GIGABYTE"),
        ("asr", "ASRock"),
        ("amd", "AMD"),
        ("intel", "Intel"),
        ("nvidia", "NVIDIA"),
        ("realtek", "Realtek"),
        ("razer", "Razer"),
        ("corsair", "Corsair"),
        ("logitech", "Logitech"),
        ("steelseries", "SteelSeries"),
        ("hwinfo", "HWiNFO"),
        ("cpuz", "CPUID"),
        ("aida", "FinalWire"),
    ];
    
    for (pattern, vendor) in vendors {
        if name_lower.contains(pattern) {
            return Some(vendor.to_string());
        }
    }
    
    None
}

/// Scan system for potentially vulnerable drivers
pub fn scan_for_targets() -> Vec<DriverInfo> {
    println!("[*] 🔍 Scanning for kernel drivers...\n");
    
    // First, dump kernel module addresses (the Connor McGarr technique)
    dump_kernel_modules();
    
    println!("\n[*] ═══════════════════════════════════════════════════════════════");
    println!("[*] Enumerating loaded drivers via EnumDeviceDrivers...\n");
    
    let mut all_targets = Vec::new();
    
    match enumerate_drivers() {
        Ok(result) => {
            println!("[+] Found {} total drivers", result.all_drivers.len());
            println!("[+] Microsoft drivers: {}", result.microsoft.len());
            println!("[+] Third-party drivers: {}", result.third_party.len());
            println!("[+] Known vulnerable: {}", result.vulnerable.len());
            
            if !result.vulnerable.is_empty() {
                println!("\n[!] 🎯 KNOWN VULNERABLE DRIVERS FOUND:");
                for drv in &result.vulnerable {
                    println!("    {} @ 0x{:X}", drv.name, drv.base_address);
                    if let Some(dev) = &drv.device_path {
                        println!("       Device: {}", dev);
                    }
                }
            }
            
            if !result.third_party.is_empty() {
                println!("\n[*] Third-party drivers (potential targets):");
                for drv in &result.third_party {
                    let vendor = drv.vendor.as_deref().unwrap_or("Unknown");
                    println!("    {} [{}] @ 0x{:X}", drv.name, vendor, drv.base_address);
                }
            }
            
            // Add to targets
            all_targets.extend(result.vulnerable);
            all_targets.extend(result.third_party.into_iter().filter(|d| !d.is_known_vulnerable));
        }
        Err(e) => {
            println!("[-] Failed to enumerate drivers: {}", e);
        }
    }
    
    // Always probe device paths - this works without admin!
    println!("\n[*] ═══════════════════════════════════════════════════════════════");
    println!("[*] 🔎 Probing {} known device paths (NO ADMIN NEEDED!)...\n", DEVICE_PATHS_TO_PROBE.len());
    
    let found = probe_device_paths();
    
    if found.is_empty() {
        println!("[!] No 3rd party drivers detected via device path probing.");
        println!("[*] Install one of these to get a vulnerable driver:");
        println!("    - MSI Afterburner     (RTCore64.sys)");
        println!("    - HWiNFO64            (HWiNFO64A.sys)");  
        println!("    - CPU-Z               (cpuz_x64.sys)");
        println!("    - AIDA64              (kerneld.x64)");
        println!("    - Open Hardware Mon.  (WinRing0x64.sys)");
        println!("    - SpeedFan            (speedfan.sys)");
        println!("    - Any RGB software    (various)");
    } else {
        // Add found drivers that aren't already in our list
        for found_drv in found {
            if !all_targets.iter().any(|t| t.device_path == found_drv.device_path) {
                all_targets.push(found_drv);
            }
        }
    }
    
    all_targets
}

/// Probe known device paths to find loaded 3rd party drivers
/// This works WITHOUT admin privileges!
pub fn probe_device_paths() -> Vec<DriverInfo> {
    use windows::Win32::Storage::FileSystem::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    
    let mut found = Vec::new();
    
    for (device_path, driver_name, vendor) in DEVICE_PATHS_TO_PROBE {
        // Try to open the device
        let wide: Vec<u16> = OsStr::new(*device_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        
        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR(wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        
        match handle {
            Ok(h) => {
                // Successfully opened!
                unsafe { let _ = CloseHandle(h); }
                
                println!("    [+] 🎯 FOUND: {} -> {} [{}]", device_path, driver_name, vendor);
                
                // Check if it's a known vulnerable driver
                let is_vulnerable = KNOWN_VULNERABLE_DRIVERS.iter()
                    .any(|(name, _, _)| name.to_lowercase() == driver_name.to_lowercase());
                
                found.push(DriverInfo {
                    name: driver_name.to_string(),
                    path: PathBuf::new(),
                    base_address: 0, // Can't get without admin
                    device_path: Some(device_path.to_string()),
                    vendor: Some(vendor.to_string()),
                    is_microsoft: false,
                    is_known_vulnerable: is_vulnerable,
                });
            }
            Err(e) => {
                // Check specific error - access denied means driver exists!
                let code = e.code().0 as u32;
                if code == 0x80070005 { // ERROR_ACCESS_DENIED
                    println!("    [~] EXISTS (Access Denied): {} -> {} [{}]", device_path, driver_name, vendor);
                    
                    let is_vulnerable = KNOWN_VULNERABLE_DRIVERS.iter()
                        .any(|(name, _, _)| name.to_lowercase() == driver_name.to_lowercase());
                    
                    found.push(DriverInfo {
                        name: driver_name.to_string(),
                        path: PathBuf::new(),
                        base_address: 0,
                        device_path: Some(device_path.to_string()),
                        vendor: Some(vendor.to_string()),
                        is_microsoft: false,
                        is_known_vulnerable: is_vulnerable,
                    });
                }
                // ERROR_FILE_NOT_FOUND (2) or ERROR_PATH_NOT_FOUND (3) = driver not loaded
            }
        }
    }
    
    if !found.is_empty() {
        let vuln_count = found.iter().filter(|d| d.is_known_vulnerable).count();
        println!();
        println!("    [+] Found {} accessible 3rd party drivers", found.len());
        if vuln_count > 0 {
            println!("    [!] 🔥 {} KNOWN VULNERABLE drivers detected!", vuln_count);
        }
    }
    
    found
}

/// Generate IOCTL codes based on CTL_CODE macro patterns
pub fn generate_ioctl_range(device_type: u32, function_start: u32, function_end: u32) -> Vec<u32> {
    let mut ioctls = Vec::new();
    
    // METHOD_BUFFERED = 0, METHOD_IN_DIRECT = 1, METHOD_OUT_DIRECT = 2, METHOD_NEITHER = 3
    let methods = [0u32, 1, 2, 3];
    
    // FILE_ANY_ACCESS = 0, FILE_READ_DATA = 1, FILE_WRITE_DATA = 2
    let access = [0u32, 1, 2, 3];
    
    for func in function_start..=function_end {
        for method in methods {
            for acc in access {
                let ioctl = (device_type << 16) | (acc << 14) | (func << 2) | method;
                ioctls.push(ioctl);
            }
        }
    }
    
    ioctls
}
