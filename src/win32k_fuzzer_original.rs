// Win32k Fuzzer - Simplified Version (Original Ladybug Style)
// This is a SAFE version that won't crash itself
//
// REALITY CHECK: User-mode win32k API fuzzing is UNLIKELY to find kernel bugs
// because all calls go through win32u.dll validation BEFORE reaching kernel.
// 
// For real kernel bug hunting, you need:
// - Direct syscalls (bypass win32u)
// - kAFL/WTF with coverage
// - Callback abuse during GDI operations
// - Or just fuzz IOCTLs on drivers like ahcache.sys, cng.sys, etc.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::fs;
use std::path::PathBuf;
use std::io::Write;
use rand::Rng;

use windows::Win32::Graphics::Gdi::*;
use windows::Win32::Foundation::*;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::core::PCWSTR;

pub struct Win32kFuzzer {
    pub crash_dir: PathBuf,
}

impl Win32kFuzzer {
    pub fn new(output_dir: &str) -> Self {
        let crash_dir = PathBuf::from(output_dir).join("win32k_crashes");
        let _ = fs::create_dir_all(&crash_dir);
        
        Win32kFuzzer { crash_dir }
    }
    
    pub fn run(&self, max_iterations: u64) {
        println!("[*] Win32k Fuzzer (Safe Mode)");
        println!("[*] Output: {:?}", self.crash_dir);
        println!("[!] Note: User-mode API fuzzing rarely finds kernel bugs.");
        println!("[!] Consider IOCTL fuzzing or kAFL for real kernel bugs.\n");
        
        let start_time = Instant::now();
        let running = Arc::new(AtomicBool::new(true));
        let iterations = Arc::new(AtomicU64::new(0));
        
        // Ctrl+C handler
        let r = running.clone();
        let _ = ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        });
        
        // Spawn fuzzing threads
        let num_threads = 4;
        let mut handles = Vec::new();
        
        for thread_id in 0..num_threads {
            let running_clone = running.clone();
            let iterations_clone = iterations.clone();
            let thread_max = if max_iterations == u64::MAX { u64::MAX } else { max_iterations / num_threads as u64 };
            
            let h = thread::spawn(move || {
                fuzz_thread_safe(thread_id, running_clone, iterations_clone, thread_max);
            });
            handles.push(h);
        }
        
        // Monitor loop
        while running.load(Ordering::SeqCst) {
            let iters = iterations.load(Ordering::Relaxed);
            let elapsed = start_time.elapsed().as_secs();
            let rate = if elapsed > 0 { iters / elapsed } else { 0 };
            
            print!("\r[{:02}:{:02}:{:02}] Iterations: {} | Rate: {}/sec   ",
                   elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60,
                   iters, rate);
            std::io::stdout().flush().ok();
            
            if max_iterations != u64::MAX && iters >= max_iterations {
                running.store(false, Ordering::SeqCst);
                break;
            }
            
            thread::sleep(Duration::from_millis(500));
        }
        
        for h in handles {
            let _ = h.join();
        }
        
        let elapsed = start_time.elapsed();
        let total_iters = iterations.load(Ordering::Relaxed);
        println!("\n\n[+] Done: {} iterations in {:?}", total_iters, elapsed);
        println!("[!] If no BSOD occurred, no kernel bugs were found.");
    }
}

fn fuzz_thread_safe(
    thread_id: usize,
    running: Arc<AtomicBool>,
    iterations: Arc<AtomicU64>,
    max_iterations: u64,
) {
    let mut rng = rand::thread_rng();
    let mut local_iters = 0u64;
    
    // Create test window
    let hwnd = match create_test_window(thread_id) {
        Some(h) => h,
        None => return,
    };
    
    let hdc = unsafe { GetDC(hwnd) };
    if hdc.0 == 0 {
        unsafe { let _ = DestroyWindow(hwnd); }
        return;
    }
    
    while running.load(Ordering::SeqCst) && local_iters < max_iterations {
        // Use ONLY safe operations that won't crash user-mode
        match rng.gen_range(0..5) {
            0 => safe_window_ops(hwnd, &mut rng),
            1 => safe_gdi_ops(hdc, &mut rng),
            2 => safe_bitmap_ops(hdc, &mut rng),
            3 => safe_region_ops(hdc, &mut rng),
            4 => safe_menu_ops(hwnd, &mut rng),
            _ => {},
        }
        
        local_iters += 1;
        iterations.fetch_add(1, Ordering::Relaxed);
        
        // Periodic cleanup
        if local_iters % 1000 == 0 {
            unsafe { let _ = GdiFlush(); }
        }
    }
    
    unsafe {
        let _ = ReleaseDC(hwnd, hdc);
        let _ = DestroyWindow(hwnd);
    }
}

fn create_test_window(thread_id: usize) -> Option<HWND> {
    unsafe {
        let class_name: Vec<u16> = format!("SafeFuzz{}\0", thread_id).encode_utf16().collect();
        
        let hinstance = GetModuleHandleW(PCWSTR::null()).ok()?;
        
        let wc = WNDCLASSW {
            lpfnWndProc: Some(def_window_proc),
            hInstance: hinstance.into(),
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..Default::default()
        };
        
        let _ = RegisterClassW(&wc);
        
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class_name.as_ptr()),
            PCWSTR::null(),
            WS_POPUP,
            0, 0, 1, 1,
            HWND::default(),
            HMENU::default(),
            hinstance,
            None,
        );
        
        if hwnd.0 != 0 { Some(hwnd) } else { None }
    }
}

unsafe extern "system" fn def_window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

fn safe_window_ops(hwnd: HWND, rng: &mut impl Rng) {
    unsafe {
        // Only use SAFE indices and values
        let index = match rng.gen_range(0..3) {
            0 => WINDOW_LONG_PTR_INDEX(-21), // GWLP_USERDATA
            1 => WINDOW_LONG_PTR_INDEX(-16), // GWL_STYLE
            _ => WINDOW_LONG_PTR_INDEX(-20), // GWL_EXSTYLE
        };
        
        // Safe values only
        let value: isize = match rng.gen_range(0..5) {
            0 => 0,
            1 => 1,
            2 => 0x1000,
            3 => rng.gen_range(0..0x10000),
            _ => rng.gen::<i32>() as isize,
        };
        
        let _ = SetWindowLongPtrW(hwnd, index, value);
        let _ = GetWindowLongPtrW(hwnd, index);
    }
}

fn safe_gdi_ops(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        match rng.gen_range(0..4) {
            0 => {
                // Solid brush
                let hbr = CreateSolidBrush(COLORREF(rng.gen::<u32>()));
                if !hbr.is_invalid() {
                    let _ = DeleteObject(hbr);
                }
            }
            1 => {
                // Pen
                let hpen = CreatePen(PS_SOLID, rng.gen_range(1..10), COLORREF(rng.gen()));
                if !hpen.is_invalid() {
                    let _ = DeleteObject(hpen);
                }
            }
            2 => {
                // Small bitmap - safe sizes
                let hbm = CreateCompatibleBitmap(hdc, rng.gen_range(10..200), rng.gen_range(10..200));
                if !hbm.is_invalid() {
                    let _ = DeleteObject(hbm);
                }
            }
            _ => {
                // DC
                let new_dc = CreateCompatibleDC(hdc);
                if !new_dc.is_invalid() {
                    let _ = DeleteDC(new_dc);
                }
            }
        }
    }
}

fn safe_bitmap_ops(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        let src_dc = CreateCompatibleDC(hdc);
        if src_dc.is_invalid() { return; }
        
        let hbm = CreateCompatibleBitmap(hdc, 50, 50);
        if hbm.is_invalid() {
            let _ = DeleteDC(src_dc);
            return;
        }
        
        let old = SelectObject(src_dc, hbm);
        
        // Safe BitBlt
        let _ = BitBlt(
            hdc,
            rng.gen_range(0..50),
            rng.gen_range(0..50),
            rng.gen_range(10..50),
            rng.gen_range(10..50),
            src_dc,
            0, 0,
            SRCCOPY,
        );
        
        let _ = SelectObject(src_dc, old);
        let _ = DeleteObject(hbm);
        let _ = DeleteDC(src_dc);
    }
}

fn safe_region_ops(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        // Safe region coordinates
        let x1 = rng.gen_range(0..100);
        let y1 = rng.gen_range(0..100);
        let x2 = x1 + rng.gen_range(10..200);
        let y2 = y1 + rng.gen_range(10..200);
        
        let hrgn = CreateRectRgn(x1, y1, x2, y2);
        if !hrgn.is_invalid() {
            let _ = SelectClipRgn(hdc, hrgn);
            let _ = SelectClipRgn(hdc, HRGN::default());
            let _ = DeleteObject(hrgn);
        }
    }
}

fn safe_menu_ops(hwnd: HWND, rng: &mut impl Rng) {
    unsafe {
        if let Ok(hmenu) = CreateMenu() {
            for i in 0..rng.gen_range(1..5) {
                let text: Vec<u16> = format!("Item{}\0", i).encode_utf16().collect();
                let _ = AppendMenuW(hmenu, MF_STRING, (100 + i) as usize, PCWSTR(text.as_ptr()));
            }
            
            let _ = SetMenu(hwnd, hmenu);
            let _ = SetMenu(hwnd, HMENU::default());
            let _ = DestroyMenu(hmenu);
        }
    }
}
