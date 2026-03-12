// Win32k Syscall Fuzzer - Full Aggressive Mode
// Target: win32k.sys kernel vulnerabilities
// Historical CVEs: CVE-2021-1732, CVE-2022-21882, CVE-2024-30088

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use rand::Rng;

use windows::Win32::Graphics::Gdi::*;
use windows::Win32::Foundation::*;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::core::{PCWSTR, w};

fn dangerous_int(rng: &mut impl Rng) -> isize {
    match rng.gen_range(0..20) {
        0 => 0, 1 => 1, 2 => -1,
        3 => 0x7FFFFFFF, 4 => -0x7FFFFFFF - 1,
        5 => 0x7FFFFFFFFFFFFFFF, 6 => -0x7FFFFFFFFFFFFFFF - 1,
        7 => 0xFFFFFFFF_u32 as isize, 8 => 0x80000000_u32 as isize,
        9 => 0xDEADBEEF_u32 as isize, 10 => 0x41414141_u32 as isize,
        11 => 0xFFFF, 12 => 0x10000, 13 => 0xFFFE, 14 => 0x7FFE,
        15 => rng.gen_range(-1000..1000), 16 => rng.gen_range(-100000..100000),
        17 => rng.gen::<i32>() as isize, 18 => rng.gen::<i16>() as isize,
        _ => rng.gen::<isize>(),
    }
}

fn dangerous_ptr(rng: &mut impl Rng) -> usize {
    match rng.gen_range(0..15) {
        0 => 0, 1 => 1, 2 => 0xFFFFFFFF, 3 => 0xFFFFFFFFFFFFFFFF,
        4 => 0xDEADBEEF, 5 => 0x41414141, 6 => 0x80000000,
        7 => 0x7FFE0000, 8 => 0xFFFF0000, 9 => 0x00010000,
        10 => rng.gen_range(1..0x10000), 11 => rng.gen_range(0x10000..0x7FFFFFFF),
        12 => 0x0000000100000000, 13 => 0x00007FF000000000,
        _ => rng.gen::<usize>(),
    }
}

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
        println!("[*] 🪟 WIN32K SYSCALL FUZZER | NtUser*/NtGdi* | {:?}", self.crash_dir);
        self.save_kernel_info();
        
        let start_time = Instant::now();
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        let _ = ctrlc::set_handler(move || { r.store(false, Ordering::SeqCst); });
        
        let num_threads = 4;
        let mut handles = Vec::new();
        let shared_iterations = Arc::new(AtomicU64::new(0));
        let shared_interesting = Arc::new(AtomicU64::new(0));
        let shared_crashes = Arc::new(AtomicU64::new(0));
        
        for thread_id in 0..num_threads {
            let running_clone = running.clone();
            let iterations_clone = shared_iterations.clone();
            let interesting_clone = shared_interesting.clone();
            let crashes_clone = shared_crashes.clone();
            let thread_max = if max_iterations == u64::MAX { u64::MAX } else { max_iterations / num_threads as u64 };
            
            let h = thread::spawn(move || {
                fuzz_thread(thread_id, running_clone, iterations_clone, interesting_clone, crashes_clone, thread_max);
            });
            handles.push(h);
        }
        
        while running.load(Ordering::SeqCst) {
            let iters = shared_iterations.load(Ordering::Relaxed);
            let crashes = shared_crashes.load(Ordering::Relaxed);
            let interesting = shared_interesting.load(Ordering::Relaxed);
            let elapsed = start_time.elapsed().as_secs();
            let rate = if elapsed > 0 { iters / elapsed } else { 0 };
            
            print!("\r[{:02}:{:02}:{:02}] Iterations: {:>12} | Crashes: {} | Interesting: {:>8} | Rate: {:>5}/sec   ",
                   elapsed / 3600, (elapsed % 3600) / 60, elapsed % 60, iters, crashes, interesting, rate);
            std::io::stdout().flush().ok();
            
            if max_iterations != u64::MAX && iters >= max_iterations {
                running.store(false, Ordering::SeqCst);
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
        
        for h in handles { let _ = h.join(); }
        
        let elapsed = start_time.elapsed();
        let total = shared_iterations.load(Ordering::Relaxed);
        let eps = total as f64 / elapsed.as_secs_f64();
        println!("\n\n[+] DONE | {:?} | {} iter | 💀{} | {}interesting | {:.0}/s",
                 elapsed, total, shared_crashes.load(Ordering::Relaxed),
                 shared_interesting.load(Ordering::Relaxed), eps);
    }
    
    fn save_kernel_info(&self) {
        let info_path = self.crash_dir.join("kernel_info.txt");
        if let Ok(mut file) = File::create(&info_path) {
            let _ = writeln!(file, "WIN32K FUZZER - KERNEL INFO\nTarget: win32k.sys, win32kfull.sys, win32kbase.sys");
        }
    }
}

fn fuzz_thread(thread_id: usize, running: Arc<AtomicBool>, iterations: Arc<AtomicU64>,
               interesting: Arc<AtomicU64>, _crashes: Arc<AtomicU64>, max_iterations: u64) {
    let mut rng = rand::thread_rng();
    let mut local_iters = 0u64;
    
    let hwnd = create_test_window(thread_id);
    if hwnd.0 == 0 { return; }
    
    let hdc = unsafe { GetDC(hwnd) };
    if hdc.0 == 0 { unsafe { let _ = DestroyWindow(hwnd); } return; }
    
    while running.load(Ordering::SeqCst) && (max_iterations == 0 || local_iters < max_iterations) {
        let strategy = rng.gen_range(0..15);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match strategy {
                0..=1 => fuzz_window_aggressive(hwnd, &mut rng, &interesting),
                2..=3 => fuzz_gdi_aggressive(hdc, &mut rng),
                4 => fuzz_messages(hwnd, &mut rng),
                5 => fuzz_menu(hwnd, &mut rng),
                6 => fuzz_bitmap(hdc, &mut rng),
                7 => fuzz_region(hdc, &mut rng),
                8 => fuzz_brush_pen(hdc, &mut rng),
                9 => fuzz_font(hdc, &mut rng),
                10 => fuzz_dc(hdc, &mut rng),
                11 => fuzz_clip(hdc, &mut rng),
                12 => fuzz_uaf_pattern(hdc, &mut rng),
                13 => fuzz_race_pattern(hdc, &mut rng),
                _ => fuzz_misc(hwnd, hdc, &mut rng),
            }
        }));
        
        local_iters += 1;
        iterations.fetch_add(1, Ordering::Relaxed);
        if local_iters % 1000 == 0 { unsafe { let _ = GdiFlush(); } }
    }
    
    unsafe { let _ = ReleaseDC(hwnd, hdc); let _ = DestroyWindow(hwnd); }
}

fn create_test_window(thread_id: usize) -> HWND {
    unsafe {
        let class_name: Vec<u16> = format!("Win32kFuzz{}\0", thread_id).encode_utf16().collect();
        let hinstance = match GetModuleHandleW(PCWSTR::null()) { Ok(h) => h, Err(_) => return HWND::default() };
        let wc = WNDCLASSW {
            lpfnWndProc: Some(fuzz_wndproc), hInstance: hinstance.into(),
            lpszClassName: PCWSTR(class_name.as_ptr()), style: CS_OWNDC, ..Default::default()
        };
        let _ = RegisterClassW(&wc);
        CreateWindowExW(WINDOW_EX_STYLE(0), PCWSTR(class_name.as_ptr()), PCWSTR::null(),
            WS_POPUP, 0, 0, 1, 1, HWND::default(), HMENU::default(), hinstance, None)
    }
}

unsafe extern "system" fn fuzz_wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

// ===== AGGRESSIVE FUZZING FUNCTIONS =====

fn fuzz_window_aggressive(hwnd: HWND, rng: &mut impl Rng, interesting: &Arc<AtomicU64>) {
    unsafe {
        // SetWindowLongPtrW - CVE-2021-1732 target
        let indices = [
            WINDOW_LONG_PTR_INDEX(-4),   // GWLP_WNDPROC
            WINDOW_LONG_PTR_INDEX(-21),  // GWLP_USERDATA
            WINDOW_LONG_PTR_INDEX(-16),  // GWL_STYLE
            WINDOW_LONG_PTR_INDEX(-20),  // GWL_EXSTYLE
            WINDOW_LONG_PTR_INDEX(-6),   // GWL_ID
            WINDOW_LONG_PTR_INDEX(0),    // Extra window memory
        ];
        let idx = indices[rng.gen_range(0..indices.len())];
        let value = dangerous_int(rng);
        let result = SetWindowLongPtrW(hwnd, idx, value);
        if result == 0 { let err = GetLastError(); if err.is_err() { interesting.fetch_add(1, Ordering::Relaxed); } }
        
        // SetWindowPos with extreme values
        let _ = SetWindowPos(hwnd, HWND::default(),
            dangerous_int(rng) as i32, dangerous_int(rng) as i32,
            dangerous_int(rng) as i32, dangerous_int(rng) as i32,
            SWP_NOACTIVATE | SWP_NOZORDER);
        
        // MoveWindow
        let _ = MoveWindow(hwnd, dangerous_int(rng) as i32, dangerous_int(rng) as i32,
            dangerous_int(rng) as i32, dangerous_int(rng) as i32, rng.gen_bool(0.5));
    }
}

fn fuzz_gdi_aggressive(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        match rng.gen_range(0..8) {
            0 => {
                let hbm = CreateBitmap(dangerous_int(rng) as i32, dangerous_int(rng) as i32, 1, 32, None);
                if !hbm.is_invalid() { let _ = DeleteObject(hbm); }
            }
            1 => {
                let rgn = CreateRectRgn(dangerous_int(rng) as i32, dangerous_int(rng) as i32,
                    dangerous_int(rng) as i32, dangerous_int(rng) as i32);
                if !rgn.is_invalid() { let _ = DeleteObject(rgn); }
            }
            2 => {
                let _ = BitBlt(hdc, dangerous_int(rng) as i32, dangerous_int(rng) as i32,
                    dangerous_int(rng) as i32, dangerous_int(rng) as i32,
                    hdc, dangerous_int(rng) as i32, dangerous_int(rng) as i32, SRCCOPY);
            }
            3 => {
                let hbm = CreateCompatibleBitmap(hdc, 0x7FFFFFFF, 1);
                if !hbm.is_invalid() { let _ = DeleteObject(hbm); }
            }
            4 => {
                let _ = StretchBlt(hdc, 0, 0, dangerous_int(rng) as i32, dangerous_int(rng) as i32,
                    hdc, 0, 0, 1, 1, SRCCOPY);
            }
            5 => {
                let _ = PatBlt(hdc, dangerous_int(rng) as i32, dangerous_int(rng) as i32,
                    dangerous_int(rng) as i32, dangerous_int(rng) as i32, BLACKNESS);
            }
            6 => {
                let hbm = CreateCompatibleBitmap(hdc, 100, 100);
                if !hbm.is_invalid() {
                    let mut buf = [0u8; 4096];
                    let _ = GetObjectW(hbm, dangerous_int(rng) as i32, Some(buf.as_mut_ptr() as *mut _));
                    let _ = DeleteObject(hbm);
                }
            }
            _ => {
                let rgn1 = CreateRectRgn(0, 0, 0x7FFFFFFF, 0x7FFFFFFF);
                let rgn2 = CreateRectRgn(-0x7FFFFFFF, -0x7FFFFFFF, 0, 0);
                let rgn3 = CreateRectRgn(0, 0, 100, 100);
                if !rgn1.is_invalid() && !rgn2.is_invalid() && !rgn3.is_invalid() {
                    let _ = CombineRgn(rgn3, rgn1, rgn2, RGN_COPY);
                    let _ = DeleteObject(rgn1); let _ = DeleteObject(rgn2); let _ = DeleteObject(rgn3);
                }
            }
        }
    }
}

fn fuzz_messages(hwnd: HWND, rng: &mut impl Rng) {
    unsafe {
        let msgs: [u32; 15] = [0x000F, 0x0014, 0x0083, 0x0085, 0x0086, 0x0401, 0x0402,
            0x8000, WM_USER, WM_APP, WM_TIMER, WM_PAINT, WM_ERASEBKGND, WM_SIZE, WM_MOVE];
        let msg = msgs[rng.gen_range(0..msgs.len())];
        let _ = SendMessageW(hwnd, msg, WPARAM(dangerous_ptr(rng)), LPARAM(dangerous_int(rng)));
        let _ = PostMessageW(hwnd, msg, WPARAM(rng.gen()), LPARAM(rng.gen()));
    }
}

fn fuzz_menu(hwnd: HWND, rng: &mut impl Rng) {
    unsafe {
        if let Ok(menu) = CreateMenu() {
            for i in 0..rng.gen_range(1..50) {
                let _ = AppendMenuW(menu, MF_STRING, i, w!("Item"));
            }
            let _ = SetMenu(hwnd, menu);
            let _ = DrawMenuBar(hwnd);
            let _ = SetMenu(hwnd, HMENU::default());
            let _ = DestroyMenu(menu);
        }
    }
}

fn fuzz_bitmap(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        let src_dc = CreateCompatibleDC(hdc);
        if src_dc.is_invalid() { return; }
        let hbm = CreateCompatibleBitmap(hdc, rng.gen_range(10..500), rng.gen_range(10..500));
        if !hbm.is_invalid() {
            let old = SelectObject(src_dc, hbm);
            let _ = BitBlt(hdc, rng.gen_range(-100..100), rng.gen_range(-100..100),
                rng.gen_range(10..500), rng.gen_range(10..500), src_dc, 0, 0, SRCCOPY);
            let _ = SelectObject(src_dc, old);
            let _ = DeleteObject(hbm);
        }
        let _ = DeleteDC(src_dc);
    }
}

fn fuzz_region(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        let coords: [(i32,i32,i32,i32); 4] = [
            (0, 0, 0x7FFFFFFF, 0x7FFFFFFF), (-0x7FFFFFFF, -0x7FFFFFFF, 0, 0),
            (0x7FFFFFF0, 0x7FFFFFF0, 0x7FFFFFFF, 0x7FFFFFFF), (0x3FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFE, 0x7FFFFFFE),
        ];
        let mut regions: Vec<HRGN> = Vec::new();
        for &(x1, y1, x2, y2) in &coords {
            let rgn = CreateRectRgn(x1, y1, x2, y2);
            if !rgn.is_invalid() { regions.push(rgn); }
        }
        if regions.len() >= 2 {
            let dest = CreateRectRgn(0, 0, 1, 1);
            if !dest.is_invalid() {
                for _ in 0..rng.gen_range(5..20) {
                    let i = rng.gen_range(0..regions.len());
                    let j = rng.gen_range(0..regions.len());
                    let mode = match rng.gen_range(0..5) { 0 => RGN_AND, 1 => RGN_OR, 2 => RGN_XOR, 3 => RGN_DIFF, _ => RGN_COPY };
                    let _ = CombineRgn(dest, regions[i], regions[j], mode);
                    let _ = SelectClipRgn(hdc, dest);
                }
                let _ = DeleteObject(dest);
            }
        }
        for rgn in regions { let _ = DeleteObject(rgn); }
    }
}

fn fuzz_brush_pen(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        let hbr = CreateSolidBrush(COLORREF(rng.gen::<u32>()));
        if !hbr.is_invalid() {
            let old = SelectObject(hdc, hbr);
            let _ = Rectangle(hdc, rng.gen_range(-100..100), rng.gen_range(-100..100),
                rng.gen_range(100..500), rng.gen_range(100..500));
            let _ = SelectObject(hdc, old);
            let _ = DeleteObject(hbr);
        }
        let hpen = CreatePen(PS_SOLID, rng.gen_range(0..100), COLORREF(rng.gen()));
        if !hpen.is_invalid() {
            let old = SelectObject(hdc, hpen);
            let _ = MoveToEx(hdc, rng.gen_range(-100..100), rng.gen_range(-100..100), None);
            let _ = LineTo(hdc, rng.gen_range(-100..500), rng.gen_range(-100..500));
            let _ = SelectObject(hdc, old);
            let _ = DeleteObject(hpen);
        }
    }
}

fn fuzz_font(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        let hfont = CreateFontW(
            rng.gen_range(-100..100), rng.gen_range(-100..100), 0, 0,
            rng.gen_range(0..1000), 0, 0, 0, 0, 0, 0, 0, 0, w!("Arial"));
        if !hfont.is_invalid() {
            let old = SelectObject(hdc, hfont);
            let text: Vec<u16> = "FuzzTest\0".encode_utf16().collect();
            let _ = TextOutW(hdc, rng.gen_range(-100..100), rng.gen_range(-100..100),
                &text[..text.len()-1]);
            let _ = SelectObject(hdc, old);
            let _ = DeleteObject(hfont);
        }
    }
}

fn fuzz_dc(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        let _ = SetMapMode(hdc, HDC_MAP_MODE(rng.gen_range(1..8) as i32));
        let _ = SetBkMode(hdc, BACKGROUND_MODE(rng.gen_range(1u32..3u32)));
        let _ = SetROP2(hdc, R2_MODE(rng.gen_range(1..16) as i32));
        let _ = SetTextColor(hdc, COLORREF(rng.gen()));
        let _ = SetBkColor(hdc, COLORREF(rng.gen()));
        let _ = SetViewportOrgEx(hdc, dangerous_int(rng) as i32, dangerous_int(rng) as i32, None);
        let _ = SetWindowOrgEx(hdc, dangerous_int(rng) as i32, dangerous_int(rng) as i32, None);
    }
}

fn fuzz_clip(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        let rgn = CreateRectRgn(rng.gen_range(-100..100), rng.gen_range(-100..100),
            rng.gen_range(100..500), rng.gen_range(100..500));
        if !rgn.is_invalid() {
            let _ = SelectClipRgn(hdc, rgn);
            let _ = ExcludeClipRect(hdc, rng.gen_range(0..50), rng.gen_range(0..50),
                rng.gen_range(50..100), rng.gen_range(50..100));
            let _ = IntersectClipRect(hdc, rng.gen_range(0..200), rng.gen_range(0..200),
                rng.gen_range(200..400), rng.gen_range(200..400));
            let _ = SelectClipRgn(hdc, HRGN::default());
            let _ = DeleteObject(rgn);
        }
    }
}

fn fuzz_uaf_pattern(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        // Create multiple objects for UAF racing
        let mut bitmaps: Vec<HBITMAP> = Vec::new();
        for _ in 0..rng.gen_range(5..20) {
            let hbm = CreateCompatibleBitmap(hdc, rng.gen_range(100..500), rng.gen_range(100..500));
            if !hbm.is_invalid() { bitmaps.push(hbm); }
        }
        // Rapidly select/deselect
        for _ in 0..rng.gen_range(10..50) {
            if !bitmaps.is_empty() {
                let idx = rng.gen_range(0..bitmaps.len());
                let old = SelectObject(hdc, bitmaps[idx]);
                let _ = SelectObject(hdc, old);
            }
        }
        // Delete in random order while doing GDI operations
        while !bitmaps.is_empty() {
            let idx = rng.gen_range(0..bitmaps.len());
            let hbm = bitmaps.remove(idx);
            let _ = BitBlt(hdc, 0, 0, 50, 50, hdc, 0, 0, SRCCOPY);
            let _ = DeleteObject(hbm);
        }
    }
}

fn fuzz_race_pattern(hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        // Pattern brush from bitmap - complex object lifetime
        let hbm = CreateCompatibleBitmap(hdc, 8, 8);
        if hbm.is_invalid() { return; }
        let brush = CreatePatternBrush(hbm);
        if brush.is_invalid() { let _ = DeleteObject(hbm); return; }
        let old = SelectObject(hdc, brush);
        // Delete source bitmap while brush selected
        let _ = DeleteObject(hbm);
        // Use the brush
        for _ in 0..rng.gen_range(5..20) {
            let _ = Rectangle(hdc, rng.gen_range(-100..500), rng.gen_range(-100..500),
                rng.gen_range(-100..500), rng.gen_range(-100..500));
            let _ = PatBlt(hdc, rng.gen_range(-100..100), rng.gen_range(-100..100),
                rng.gen_range(10..200), rng.gen_range(10..200), PATCOPY);
        }
        let _ = SelectObject(hdc, old);
        let _ = DeleteObject(brush);
    }
}

fn fuzz_misc(hwnd: HWND, hdc: HDC, rng: &mut impl Rng) {
    unsafe {
        match rng.gen_range(0..6) {
            0 => {
                // Long window text
                let long_text: Vec<u16> = (0..rng.gen_range(1000..10000)).map(|_| b'A' as u16).chain(std::iter::once(0)).collect();
                let _ = SetWindowTextW(hwnd, PCWSTR::from_raw(long_text.as_ptr()));
            }
            1 => {
                // Scroll operations
                let mut si = SCROLLINFO { cbSize: std::mem::size_of::<SCROLLINFO>() as u32,
                    fMask: SIF_ALL, nMin: 0, nMax: 0, nPage: 0, nPos: 0, nTrackPos: 0 };
                let _ = GetScrollInfo(hwnd, SB_HORZ, &mut si);
                let _ = ScrollWindowEx(hwnd, dangerous_int(rng) as i32, dangerous_int(rng) as i32,
                    None, None, None, None, SW_INVALIDATE);
            }
            2 => {
                // Class operations
                let indices = [GCL_STYLE, GCL_HBRBACKGROUND, GCL_HCURSOR, GCL_HICON];
                let idx = indices[rng.gen_range(0..indices.len())];
                let _ = SetClassLongPtrW(hwnd, idx, rng.gen::<u32>() as isize);
            }
            3 => {
                // Ellipse operations
                let _ = Ellipse(hdc, rng.gen_range(-100..100), rng.gen_range(-100..100),
                    rng.gen_range(100..500), rng.gen_range(100..500));
            }
            4 => {
                // Arc operations
                let _ = Arc(hdc, rng.gen_range(-100..100), rng.gen_range(-100..100),
                    rng.gen_range(100..500), rng.gen_range(100..500),
                    rng.gen_range(-100..500), rng.gen_range(-100..500),
                    rng.gen_range(-100..500), rng.gen_range(-100..500));
            }
            _ => {
                // Polygon
                let points: Vec<POINT> = (0..rng.gen_range(3..10)).map(|_| POINT {
                    x: rng.gen_range(-100..500), y: rng.gen_range(-100..500)
                }).collect();
                let _ = Polygon(hdc, &points);
            }
        }
    }
}
