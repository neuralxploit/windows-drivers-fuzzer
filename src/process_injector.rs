// Process Injector Module  
// Enumerate processes and find targets for IOCTL testing
// Based on Connor McGarr's talk: Previous Mode corruption technique

use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;

/// Test if we can access a device
pub fn test_driver_access() {
    println!("[*] Testing driver accessibility...");
    
    let devices = [
        ("\\\\.\\PhysicalDrive0", "Physical Disk"),
        ("\\\\.\\Afd", "AFD (Network)"),
        ("\\\\.\\DBUtil_2_3", "Dell DBUtil"),
        ("\\\\.\\RTCore64", "MSI RTCore"),
        ("\\\\.\\GIO", "GIGABYTE GIO"),
        ("\\\\.\\Asusgio2", "ASUS ASIO"),
        ("\\\\.\\WinRing0_1_2_0", "WinRing0"),
        ("\\\\.\\PhyMem64", "Physical Memory"),
    ];
    
    for (path, name) in devices {
        let accessible = can_access_device(path);
        let status = if accessible { "✅ ACCESSIBLE" } else { "❌ Denied" };
        println!("    {} {} - {}", status, name, path);
    }
}

/// Check if device is accessible
fn can_access_device(device_path: &str) -> bool {
    unsafe {
        let device_wide: Vec<u16> = device_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        
        let handle = CreateFileW(
            windows::core::PCWSTR(device_wide.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        );
        
        match handle {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}

/// Find processes that may have loaded vulnerable drivers
pub fn find_ioctl_targets() -> Vec<ProcessInfo> {
    println!("[*] 🔍 Looking for interesting processes...");
    
    // Known processes that often load vulnerable drivers
    let interesting = [
        "hwinfo64.exe", "hwinfo32.exe",
        "cpuz.exe", "cpu-z.exe",
        "aida64.exe",
        "afterburner.exe", "msiafterburner.exe",
        "gpuz.exe",
        "icue.exe",
        "razer",
        "armoury",
        "ryzenmaster.exe",
        "openhardwaremonitor.exe",
    ];
    
    println!("[*] Looking for: {:?}", &interesting[..5]);
    println!("[*] (Run HWiNFO64, CPU-Z, or MSI Afterburner to load vulnerable drivers)");
    
    Vec::new() // Simplified - full implementation would enumerate processes
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}
