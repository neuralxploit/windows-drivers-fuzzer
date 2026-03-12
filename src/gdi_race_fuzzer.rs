// GDI Object Race Condition Fuzzer
// Target: win32k.sys UAF bugs via multi-threaded GDI object racing
// CVE potential: CVE-2018-8120, CVE-2021-1732, CVE-2019-0803 style UAF bugs

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use rand::Rng;

use windows::Win32::Graphics::Gdi::*;
use windows::Win32::Foundation::*;
use windows::Win32::UI::WindowsAndMessaging::*;

// Shared state between threads
pub struct SharedState {
    // GDI Object handles
    pub bitmaps: Vec<AtomicUsize>,
    pub brushes: Vec<AtomicUsize>,
    pub pens: Vec<AtomicUsize>,
    pub regions: Vec<AtomicUsize>,
    pub dcs: Vec<AtomicUsize>,
    pub fonts: Vec<AtomicUsize>,
    
    // USER Object handles (CVE-2019-0803 style)
    pub menus: Vec<AtomicUsize>,
    pub cursors: Vec<AtomicUsize>,
    pub icons: Vec<AtomicUsize>,
    pub windows: Vec<AtomicUsize>,
    
    // Control flags
    pub running: AtomicBool,
    pub iteration: AtomicU64,
    
    // Stats
    pub creates: AtomicU64,
    pub deletes: AtomicU64,
    pub uses: AtomicU64,
    pub races_detected: AtomicU64,
}

impl SharedState {
    pub fn new(pool_size: usize) -> Self {
        let mut bitmaps = Vec::with_capacity(pool_size);
        let mut brushes = Vec::with_capacity(pool_size);
        let mut pens = Vec::with_capacity(pool_size);
        let mut regions = Vec::with_capacity(pool_size);
        let mut dcs = Vec::with_capacity(pool_size);
        let mut fonts = Vec::with_capacity(pool_size);
        let mut menus = Vec::with_capacity(pool_size);
        let mut cursors = Vec::with_capacity(pool_size);
        let mut icons = Vec::with_capacity(pool_size);
        let mut windows = Vec::with_capacity(pool_size);
        
        for _ in 0..pool_size {
            bitmaps.push(AtomicUsize::new(0));
            brushes.push(AtomicUsize::new(0));
            pens.push(AtomicUsize::new(0));
            regions.push(AtomicUsize::new(0));
            dcs.push(AtomicUsize::new(0));
            fonts.push(AtomicUsize::new(0));
            menus.push(AtomicUsize::new(0));
            cursors.push(AtomicUsize::new(0));
            icons.push(AtomicUsize::new(0));
            windows.push(AtomicUsize::new(0));
        }
        
        SharedState {
            bitmaps,
            brushes,
            pens,
            regions,
            dcs,
            fonts,
            menus,
            cursors,
            icons,
            windows,
            running: AtomicBool::new(true),
            iteration: AtomicU64::new(0),
            creates: AtomicU64::new(0),
            deletes: AtomicU64::new(0),
            uses: AtomicU64::new(0),
            races_detected: AtomicU64::new(0),
        }
    }
}

pub struct GdiRaceFuzzer {
    pub crash_dir: PathBuf,
    pub pool_size: usize,
    pub num_threads: usize,
}

impl GdiRaceFuzzer {
    pub fn new(output_dir: &str) -> Self {
        let crash_dir = PathBuf::from(output_dir).join("gdi_race_crashes");
        let _ = fs::create_dir_all(&crash_dir);
        
        GdiRaceFuzzer {
            crash_dir,
            pool_size: 64,      // Number of handles per object type
            num_threads: 8,     // Total threads racing
        }
    }
    
    pub fn run(&self, iterations: u64) {
        println!("[*] 🏎️ GDI+USER RACE | {} threads | {} pool | {:?}", 
                 self.num_threads, self.pool_size, self.crash_dir);
        println!("[*] Objects: Bitmap, Brush, Pen, Region, DC, Font, Menu, Cursor, Icon, Window");
        
        let state = Arc::new(SharedState::new(self.pool_size));
        let start_time = Instant::now();
        
        // Spawn racing threads
        let mut handles = Vec::new();
        
        // Thread 1-2: GDI Creators
        for _i in 0..2 {
            let state_clone = Arc::clone(&state);
            let h = thread::spawn(move || {
                creator_thread(state_clone);
            });
            handles.push(h);
        }
        
        // Thread 3-4: GDI Deleters
        for _i in 0..2 {
            let state_clone = Arc::clone(&state);
            let h = thread::spawn(move || {
                deleter_thread(state_clone);
            });
            handles.push(h);
        }
        
        // Thread 5-6: GDI Users
        for _i in 0..2 {
            let state_clone = Arc::clone(&state);
            let h = thread::spawn(move || {
                user_thread(state_clone);
            });
            handles.push(h);
        }
        
        // Thread 7: Selector (SelectObject racing)
        {
            let state_clone = Arc::clone(&state);
            let h = thread::spawn(move || {
                selector_thread(state_clone);
            });
            handles.push(h);
        }
        
        // Thread 8: DC Creator/Destroyer
        {
            let state_clone = Arc::clone(&state);
            let h = thread::spawn(move || {
                dc_thread(state_clone);
            });
            handles.push(h);
        }
        
        // Thread 9-10: USER Object Creators (CVE-2019-0803 style)
        for _i in 0..2 {
            let state_clone = Arc::clone(&state);
            let h = thread::spawn(move || {
                user_object_creator_thread(state_clone);
            });
            handles.push(h);
        }
        
        // Thread 11-12: USER Object Deleters
        for _i in 0..2 {
            let state_clone = Arc::clone(&state);
            let h = thread::spawn(move || {
                user_object_deleter_thread(state_clone);
            });
            handles.push(h);
        }
        
        // Thread 13: Cursor/Menu User - CVE-2019-0803 race trigger
        {
            let state_clone = Arc::clone(&state);
            let h = thread::spawn(move || {
                cursor_menu_user_thread(state_clone);
            });
            handles.push(h);
        }
        
        // Main thread: monitor progress
        loop {
            let iter = state.iteration.load(Ordering::Relaxed);
            let creates = state.creates.load(Ordering::Relaxed);
            let deletes = state.deletes.load(Ordering::Relaxed);
            let uses = state.uses.load(Ordering::Relaxed);
            let races = state.races_detected.load(Ordering::Relaxed);
            
            let elapsed = start_time.elapsed();
            let total_ops = creates + deletes + uses;
            let rate = if elapsed.as_secs() > 0 { total_ops / elapsed.as_secs() } else { total_ops };
            
            print!("\r[{:02}:{:02}:{:02}] 🏎️ GDI+USER | {:>10} iter | C:{:>8} D:{:>8} U:{:>8} | 🔥{} races | {:>6}/s                    ",
                   elapsed.as_secs() / 3600,
                   (elapsed.as_secs() % 3600) / 60,
                   elapsed.as_secs() % 60,
                   iter, creates, deletes, uses, races, rate);
            std::io::stdout().flush().ok();
            
            state.iteration.fetch_add(1, Ordering::Relaxed);
            
            if iter >= iterations {
                state.running.store(false, Ordering::Relaxed);
                break;
            }
            
            thread::sleep(Duration::from_millis(100));
        }
        
        // Wait for all threads
        for h in handles {
            let _ = h.join();
        }
        
        // Cleanup remaining handles
        cleanup_handles(&state);
        
        let total_ops = state.creates.load(Ordering::Relaxed) 
                      + state.deletes.load(Ordering::Relaxed)
                      + state.uses.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed();
        
        println!("\n[+] GDI Race Complete | {} ops | {} races | {:02}:{:02}:{:02}",
                 total_ops,
                 state.races_detected.load(Ordering::Relaxed),
                 elapsed.as_secs() / 3600,
                 (elapsed.as_secs() % 3600) / 60,
                 elapsed.as_secs() % 60);
    }
}

// Thread that creates GDI objects
fn creator_thread(state: Arc<SharedState>) {
    let mut rng = rand::thread_rng();
    
    while state.running.load(Ordering::Relaxed) {
        let obj_type = rng.gen_range(0..6);
        let slot = rng.gen_range(0..state.bitmaps.len());
        
        match obj_type {
            0 => create_bitmap(&state, slot, &mut rng),
            1 => create_brush(&state, slot, &mut rng),
            2 => create_pen(&state, slot, &mut rng),
            3 => create_region(&state, slot, &mut rng),
            4 => create_dc(&state, slot),
            5 => create_font(&state, slot, &mut rng),
            _ => {}
        }
        
        state.creates.fetch_add(1, Ordering::Relaxed);
        
        // Tiny sleep to vary timing
        if rng.gen_bool(0.1) {
            thread::yield_now();
        }
    }
}

// Thread that deletes GDI objects
fn deleter_thread(state: Arc<SharedState>) {
    let mut rng = rand::thread_rng();
    
    while state.running.load(Ordering::Relaxed) {
        let obj_type = rng.gen_range(0..6);
        let slot = rng.gen_range(0..state.bitmaps.len());
        
        match obj_type {
            0 => delete_gdi_object(&state.bitmaps[slot]),
            1 => delete_gdi_object(&state.brushes[slot]),
            2 => delete_gdi_object(&state.pens[slot]),
            3 => delete_gdi_object(&state.regions[slot]),
            4 => delete_dc_handle(&state.dcs[slot]),
            5 => delete_gdi_object(&state.fonts[slot]),
            _ => {}
        }
        
        state.deletes.fetch_add(1, Ordering::Relaxed);
        
        if rng.gen_bool(0.1) {
            thread::yield_now();
        }
    }
}

// Thread that uses GDI objects
fn user_thread(state: Arc<SharedState>) {
    let mut rng = rand::thread_rng();
    
    while state.running.load(Ordering::Relaxed) {
        let slot = rng.gen_range(0..state.bitmaps.len());
        let dc_slot = rng.gen_range(0..state.dcs.len());
        
        // Get a DC handle
        let dc_handle = state.dcs[dc_slot].load(Ordering::Relaxed);
        if dc_handle != 0 {
            let hdc = HDC(dc_handle as isize);
            
            // Try to use various objects with this DC
            let op = rng.gen_range(0..10);
            match op {
                0..=2 => use_bitmap(&state, slot, hdc, &mut rng),
                3..=4 => use_brush(&state, slot, hdc, &mut rng),
                5..=6 => use_pen(&state, slot, hdc, &mut rng),
                7 => use_region(&state, slot, hdc),
                8 => use_font(&state, slot, hdc, &mut rng),
                9 => bitblt_race(&state, hdc, &mut rng),
                _ => {}
            }
        }
        
        state.uses.fetch_add(1, Ordering::Relaxed);
        
        if rng.gen_bool(0.05) {
            thread::yield_now();
        }
    }
}

// Thread that does SelectObject racing
fn selector_thread(state: Arc<SharedState>) {
    let mut rng = rand::thread_rng();
    
    while state.running.load(Ordering::Relaxed) {
        let dc_slot = rng.gen_range(0..state.dcs.len());
        let dc_handle = state.dcs[dc_slot].load(Ordering::Relaxed);
        
        if dc_handle != 0 {
            let hdc = HDC(dc_handle as isize);
            
            // Rapidly select different objects into same DC
            for _ in 0..10 {
                let obj_type = rng.gen_range(0..5);
                let slot = rng.gen_range(0..state.bitmaps.len());
                
                unsafe {
                    match obj_type {
                        0 => {
                            let h = state.bitmaps[slot].load(Ordering::Relaxed);
                            if h != 0 {
                                let _ = SelectObject(hdc, HGDIOBJ(h as isize));
                            }
                        }
                        1 => {
                            let h = state.brushes[slot].load(Ordering::Relaxed);
                            if h != 0 {
                                let _ = SelectObject(hdc, HGDIOBJ(h as isize));
                            }
                        }
                        2 => {
                            let h = state.pens[slot].load(Ordering::Relaxed);
                            if h != 0 {
                                let _ = SelectObject(hdc, HGDIOBJ(h as isize));
                            }
                        }
                        3 => {
                            let h = state.fonts[slot].load(Ordering::Relaxed);
                            if h != 0 {
                                let _ = SelectObject(hdc, HGDIOBJ(h as isize));
                            }
                        }
                        4 => {
                            let h = state.regions[slot].load(Ordering::Relaxed);
                            if h != 0 {
                                let _ = SelectClipRgn(hdc, HRGN(h as isize));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        
        state.uses.fetch_add(10, Ordering::Relaxed);
    }
}

// Thread that creates/destroys DCs rapidly
fn dc_thread(state: Arc<SharedState>) {
    let mut rng = rand::thread_rng();
    
    while state.running.load(Ordering::Relaxed) {
        let slot = rng.gen_range(0..state.dcs.len());
        
        // 50% create, 50% delete
        if rng.gen_bool(0.5) {
            create_dc(&state, slot);
            state.creates.fetch_add(1, Ordering::Relaxed);
        } else {
            delete_dc_handle(&state.dcs[slot]);
            state.deletes.fetch_add(1, Ordering::Relaxed);
        }
        
        // Also do some memory DCs
        if rng.gen_bool(0.3) {
            unsafe {
                let screen_dc = GetDC(HWND(0));
                if screen_dc.0 != 0 {
                    let mem_dc = CreateCompatibleDC(screen_dc);
                    if mem_dc.0 != 0 {
                        // Quick use then delete
                        let _ = DeleteDC(mem_dc);
                    }
                    let _ = ReleaseDC(HWND(0), screen_dc);
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Object creation functions
// ═══════════════════════════════════════════════════════════════

fn create_bitmap(state: &SharedState, slot: usize, rng: &mut impl Rng) {
    unsafe {
        // Various bitmap creation methods
        let method = rng.gen_range(0..3);
        
        let hbitmap = match method {
            0 => {
                // CreateBitmap
                let width = rng.gen_range(1..1000);
                let height = rng.gen_range(1..1000);
                CreateBitmap(width, height, 1, 32, None)
            }
            1 => {
                // CreateCompatibleBitmap
                let screen_dc = GetDC(HWND(0));
                let bmp = CreateCompatibleBitmap(screen_dc, rng.gen_range(1..500), rng.gen_range(1..500));
                let _ = ReleaseDC(HWND(0), screen_dc);
                bmp
            }
            _ => {
                // Monochrome bitmap
                CreateBitmap(rng.gen_range(1..200), rng.gen_range(1..200), 1, 1, None)
            }
        };
        
        if hbitmap.0 != 0 {
            state.bitmaps[slot].store(hbitmap.0 as usize, Ordering::Relaxed);
        }
    }
}

fn create_brush(state: &SharedState, slot: usize, rng: &mut impl Rng) {
    unsafe {
        let method = rng.gen_range(0..2);
        
        let hbrush = match method {
            0 => {
                // Solid brush
                let color = COLORREF(rng.gen::<u32>() & 0x00FFFFFF);
                CreateSolidBrush(color)
            }
            _ => {
                // Hatch brush  
                CreateHatchBrush(HS_BDIAGONAL, COLORREF(rng.gen::<u32>() & 0x00FFFFFF))
            }
        };
        
        if hbrush.0 != 0 {
            state.brushes[slot].store(hbrush.0 as usize, Ordering::Relaxed);
        }
    }
}

fn create_pen(state: &SharedState, slot: usize, rng: &mut impl Rng) {
    unsafe {
        let style = match rng.gen_range(0..5) {
            0 => PS_SOLID,
            1 => PS_DASH,
            2 => PS_DOT,
            3 => PS_DASHDOT,
            _ => PS_NULL,
        };
        
        let hpen = CreatePen(style, rng.gen_range(1..20), COLORREF(rng.gen::<u32>() & 0x00FFFFFF));
        
        if hpen.0 != 0 {
            state.pens[slot].store(hpen.0 as usize, Ordering::Relaxed);
        }
    }
}

fn create_region(state: &SharedState, slot: usize, rng: &mut impl Rng) {
    unsafe {
        let method = rng.gen_range(0..3);
        
        let hrgn = match method {
            0 => {
                // Rectangle region
                CreateRectRgn(
                    rng.gen_range(0..100),
                    rng.gen_range(0..100),
                    rng.gen_range(100..500),
                    rng.gen_range(100..500),
                )
            }
            1 => {
                // Elliptic region
                CreateEllipticRgn(
                    rng.gen_range(0..100),
                    rng.gen_range(0..100),
                    rng.gen_range(100..500),
                    rng.gen_range(100..500),
                )
            }
            _ => {
                // Round rect region
                CreateRoundRectRgn(
                    rng.gen_range(0..100),
                    rng.gen_range(0..100),
                    rng.gen_range(100..500),
                    rng.gen_range(100..500),
                    rng.gen_range(10..50),
                    rng.gen_range(10..50),
                )
            }
        };
        
        if hrgn.0 != 0 {
            state.regions[slot].store(hrgn.0 as usize, Ordering::Relaxed);
        }
    }
}

fn create_dc(state: &SharedState, slot: usize) {
    unsafe {
        let screen_dc = GetDC(HWND(0));
        if screen_dc.0 != 0 {
            let mem_dc = CreateCompatibleDC(screen_dc);
            let _ = ReleaseDC(HWND(0), screen_dc);
            
            if mem_dc.0 != 0 {
                state.dcs[slot].store(mem_dc.0 as usize, Ordering::Relaxed);
            }
        }
    }
}

fn create_font(state: &SharedState, slot: usize, rng: &mut impl Rng) {
    unsafe {
        let height = rng.gen_range(8..72);
        let weight = if rng.gen_bool(0.5) { FW_NORMAL } else { FW_BOLD };
        
        let hfont = CreateFontW(
            height,
            0,
            0,
            0,
            weight.0 as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET.0 as u32,
            OUT_DEFAULT_PRECIS.0 as u32,
            CLIP_DEFAULT_PRECIS.0 as u32,
            DEFAULT_QUALITY.0 as u32,
            (DEFAULT_PITCH.0 | FF_DONTCARE.0) as u32,
            None,
        );
        
        if hfont.0 != 0 {
            state.fonts[slot].store(hfont.0 as usize, Ordering::Relaxed);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Object deletion functions
// ═══════════════════════════════════════════════════════════════

fn delete_gdi_object(handle_slot: &AtomicUsize) {
    let handle = handle_slot.swap(0, Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let _ = DeleteObject(HGDIOBJ(handle as isize));
        }
    }
}

fn delete_dc_handle(handle_slot: &AtomicUsize) {
    let handle = handle_slot.swap(0, Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let _ = DeleteDC(HDC(handle as isize));
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Object use functions (where UAF would trigger)
// ═══════════════════════════════════════════════════════════════

fn use_bitmap(state: &SharedState, slot: usize, hdc: HDC, rng: &mut impl Rng) {
    let handle = state.bitmaps[slot].load(Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let hbitmap = HBITMAP(handle as isize);
            
            // Various bitmap operations
            match rng.gen_range(0..4) {
                0 => {
                    // SelectObject (classic race target)
                    let _ = SelectObject(hdc, HGDIOBJ(handle as isize));
                }
                1 => {
                    // GetBitmapBits
                    let mut buf = [0u8; 1024];
                    let _ = GetBitmapBits(hbitmap, buf.len() as i32, buf.as_mut_ptr() as *mut _);
                }
                2 => {
                    // SetBitmapBits
                    let buf = [0xAAu8; 1024];
                    let _ = SetBitmapBits(hbitmap, buf.len() as u32, buf.as_ptr() as *const _);
                }
                _ => {
                    // BitBlt with the bitmap selected
                    let old = SelectObject(hdc, HGDIOBJ(handle as isize));
                    let _ = BitBlt(hdc, 0, 0, 100, 100, hdc, 0, 0, SRCCOPY);
                    if old.0 != 0 {
                        let _ = SelectObject(hdc, old);
                    }
                }
            }
        }
    }
}

fn use_brush(state: &SharedState, slot: usize, hdc: HDC, rng: &mut impl Rng) {
    let handle = state.brushes[slot].load(Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            match rng.gen_range(0..2) {
                0 => {
                    let _ = SelectObject(hdc, HGDIOBJ(handle as isize));
                }
                _ => {
                    let rect = RECT { left: 0, top: 0, right: 100, bottom: 100 };
                    let _ = FillRect(hdc, &rect, HBRUSH(handle as isize));
                }
            }
        }
    }
}

fn use_pen(state: &SharedState, slot: usize, hdc: HDC, rng: &mut impl Rng) {
    let handle = state.pens[slot].load(Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let old = SelectObject(hdc, HGDIOBJ(handle as isize));
            
            // Draw something
            let _ = MoveToEx(hdc, rng.gen_range(0..100), rng.gen_range(0..100), None);
            let _ = LineTo(hdc, rng.gen_range(0..200), rng.gen_range(0..200));
            
            if old.0 != 0 {
                let _ = SelectObject(hdc, old);
            }
        }
    }
}

fn use_region(state: &SharedState, slot: usize, hdc: HDC) {
    let handle = state.regions[slot].load(Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let hrgn = HRGN(handle as isize);
            
            // Various region operations
            let _ = SelectClipRgn(hdc, hrgn);
            
            // Combine with another region
            let other_slot = slot.wrapping_add(1) % state.regions.len();
            let other = state.regions[other_slot].load(Ordering::Relaxed);
            if other != 0 {
                let _ = CombineRgn(hrgn, hrgn, HRGN(other as isize), RGN_XOR);
            }
        }
    }
}

fn use_font(state: &SharedState, slot: usize, hdc: HDC, rng: &mut impl Rng) {
    let handle = state.fonts[slot].load(Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let old = SelectObject(hdc, HGDIOBJ(handle as isize));
            
            // Text output
            let text: Vec<u16> = "RACE".encode_utf16().chain(std::iter::once(0)).collect();
            let _ = TextOutW(hdc, rng.gen_range(0..100), rng.gen_range(0..100), &text[..text.len()-1]);
            
            if old.0 != 0 {
                let _ = SelectObject(hdc, old);
            }
        }
    }
}

fn bitblt_race(state: &SharedState, hdc: HDC, rng: &mut impl Rng) {
    // BitBlt between different DCs (potential race)
    let src_slot = rng.gen_range(0..state.dcs.len());
    let src_dc = state.dcs[src_slot].load(Ordering::Relaxed);
    
    if src_dc != 0 {
        unsafe {
            let _ = BitBlt(
                hdc,
                0, 0,
                rng.gen_range(1..200),
                rng.gen_range(1..200),
                HDC(src_dc as isize),
                0, 0,
                SRCCOPY,
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// USER OBJECT THREADS (CVE-2019-0803 style racing)
// ═══════════════════════════════════════════════════════════════

fn user_object_creator_thread(state: Arc<SharedState>) {
    let mut rng = rand::thread_rng();
    
    while state.running.load(Ordering::Relaxed) {
        let obj_type = rng.gen_range(0..4);
        let slot = rng.gen_range(0..state.menus.len());
        
        match obj_type {
            0 => create_menu_obj(&state, slot),
            1 => create_cursor_obj(&state, slot, &mut rng),
            2 => create_icon_obj(&state, slot, &mut rng),
            3 => create_window_obj(&state, slot),
            _ => {}
        }
        
        state.creates.fetch_add(1, Ordering::Relaxed);
        
        if rng.gen_bool(0.1) {
            thread::yield_now();
        }
    }
}

fn user_object_deleter_thread(state: Arc<SharedState>) {
    let mut rng = rand::thread_rng();
    
    while state.running.load(Ordering::Relaxed) {
        let obj_type = rng.gen_range(0..4);
        let slot = rng.gen_range(0..state.menus.len());
        
        match obj_type {
            0 => delete_menu_obj(&state.menus[slot]),
            1 => delete_cursor_obj(&state.cursors[slot]),
            2 => delete_icon_obj(&state.icons[slot]),
            3 => delete_window_obj(&state.windows[slot]),
            _ => {}
        }
        
        state.deletes.fetch_add(1, Ordering::Relaxed);
        
        if rng.gen_bool(0.1) {
            thread::yield_now();
        }
    }
}

// CVE-2019-0803 style: cursor/menu manipulation racing
fn cursor_menu_user_thread(state: Arc<SharedState>) {
    let mut rng = rand::thread_rng();
    
    while state.running.load(Ordering::Relaxed) {
        let slot = rng.gen_range(0..state.menus.len());
        let op = rng.gen_range(0..10);
        
        match op {
            0..=2 => use_cursor_obj(&state, slot),
            3..=4 => use_menu_obj(&state, slot, &mut rng),
            5..=6 => use_icon_obj(&state, slot),
            7..=8 => use_window_obj(&state, slot, &mut rng),
            _ => cursor_menu_race(&state, &mut rng), // Special race pattern
        }
        
        state.uses.fetch_add(1, Ordering::Relaxed);
        
        if rng.gen_bool(0.05) {
            thread::yield_now();
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// USER Object creation functions
// ═══════════════════════════════════════════════════════════════

fn create_menu_obj(state: &SharedState, slot: usize) {
    unsafe {
        let hmenu = CreateMenu();
        if hmenu.is_ok() {
            let menu = hmenu.unwrap();
            if menu.0 != 0 {
                // Add some items to make the menu useful - use w!() macro for strings
                let _ = AppendMenuW(menu, MF_STRING, 1, windows::core::w!("Item"));
                state.menus[slot].store(menu.0 as usize, Ordering::Relaxed);
            }
        }
    }
}

fn create_cursor_obj(state: &SharedState, slot: usize, rng: &mut impl Rng) {
    unsafe {
        // Create cursors with different sizes (CVE-2019-0803 attack vector)
        let method = rng.gen_range(0..3);
        
        match method {
            0 => {
                // Standard cursor - just use it directly
                let hcursor = LoadCursorW(None, IDC_ARROW);
                if let Ok(cursor) = hcursor {
                    state.cursors[slot].store(cursor.0 as usize, Ordering::Relaxed);
                }
            }
            1 => {
                // Different cursor type
                let hcursor = LoadCursorW(None, IDC_CROSS);
                if let Ok(cursor) = hcursor {
                    state.cursors[slot].store(cursor.0 as usize, Ordering::Relaxed);
                }
            }
            _ => {
                // CreateCursor with specific dimensions (size manipulation)
                let cursor = CreateCursor(
                    None,
                    0, 0,
                    32, 32,
                    [0xFFu8; 128].as_ptr() as *const _,
                    [0x00u8; 128].as_ptr() as *const _,
                );
                if let Ok(c) = cursor {
                    state.cursors[slot].store(c.0 as usize, Ordering::Relaxed);
                }
            }
        }
    }
}

fn create_icon_obj(state: &SharedState, slot: usize, rng: &mut impl Rng) {
    unsafe {
        let method = rng.gen_range(0..2);
        
        match method {
            0 => {
                let hicon = LoadIconW(None, IDI_APPLICATION);
                if let Ok(icon) = hicon {
                    let copy = CopyIcon(icon);
                    if let Ok(i) = copy {
                        state.icons[slot].store(i.0 as usize, Ordering::Relaxed);
                    }
                }
            }
            _ => {
                // Create icon with specific dimensions
                let icon = CreateIcon(
                    None,
                    32, 32,
                    1, 32,
                    [0xFFu8; 128].as_ptr(),
                    [0x00u8; 4096].as_ptr(),
                );
                if let Ok(i) = icon {
                    state.icons[slot].store(i.0 as usize, Ordering::Relaxed);
                }
            }
        }
    }
}

fn create_window_obj(state: &SharedState, slot: usize) {
    unsafe {
        // Create a message-only window (lightweight, no visible UI)
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            windows::core::w!("STATIC"),
            windows::core::w!("FuzzWin"),
            WS_DISABLED,
            0, 0, 1, 1,
            HWND_MESSAGE, // Message-only window
            None,
            None,
            None,
        );
        
        // CreateWindowExW returns HWND directly (not Result)
        if hwnd.0 != 0 {
            state.windows[slot].store(hwnd.0 as usize, Ordering::Relaxed);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// USER Object deletion functions
// ═══════════════════════════════════════════════════════════════

fn delete_menu_obj(handle_slot: &AtomicUsize) {
    let handle = handle_slot.swap(0, Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let _ = DestroyMenu(HMENU(handle as isize));
        }
    }
}

fn delete_cursor_obj(handle_slot: &AtomicUsize) {
    let handle = handle_slot.swap(0, Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let _ = DestroyCursor(HCURSOR(handle as isize));
        }
    }
}

fn delete_icon_obj(handle_slot: &AtomicUsize) {
    let handle = handle_slot.swap(0, Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let _ = DestroyIcon(HICON(handle as isize));
        }
    }
}

fn delete_window_obj(handle_slot: &AtomicUsize) {
    let handle = handle_slot.swap(0, Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let _ = DestroyWindow(HWND(handle as isize));
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// USER Object use functions (UAF trigger points)
// ═══════════════════════════════════════════════════════════════

fn use_cursor_obj(state: &SharedState, slot: usize) {
    let handle = state.cursors[slot].load(Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let hcursor = HCURSOR(handle as isize);
            
            // SetCursor is the key UAF trigger in CVE-2019-0803
            let _ = SetCursor(hcursor);
            
            // Also try GetCursorInfo which accesses cursor data
            let mut ci: CURSORINFO = std::mem::zeroed();
            ci.cbSize = std::mem::size_of::<CURSORINFO>() as u32;
            let _ = GetCursorInfo(&mut ci);
        }
    }
}

fn use_menu_obj(state: &SharedState, slot: usize, rng: &mut impl Rng) {
    let handle = state.menus[slot].load(Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let hmenu = HMENU(handle as isize);
            
            match rng.gen_range(0..4) {
                0 => {
                    // GetMenuItemCount - reads from menu structure
                    let _ = GetMenuItemCount(hmenu);
                }
                1 => {
                    // InsertMenuItem - modifies menu
                    let _ = AppendMenuW(hmenu, MF_STRING, rng.gen_range(1..100), windows::core::w!("New"));
                }
                2 => {
                    // GetMenuItemInfo - reads detailed info
                    let mut mii: MENUITEMINFOW = std::mem::zeroed();
                    mii.cbSize = std::mem::size_of::<MENUITEMINFOW>() as u32;
                    mii.fMask = MIIM_TYPE;
                    let _ = GetMenuItemInfoW(hmenu, 0, true, &mut mii);
                }
                _ => {
                    // SetMenuInfo - write operation
                    let mut mi: MENUINFO = std::mem::zeroed();
                    mi.cbSize = std::mem::size_of::<MENUINFO>() as u32;
                    mi.fMask = MIM_STYLE;
                    let _ = SetMenuInfo(hmenu, &mi);
                }
            }
        }
    }
}

fn use_icon_obj(state: &SharedState, slot: usize) {
    let handle = state.icons[slot].load(Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let hicon = HICON(handle as isize);
            
            // GetIconInfo - accesses icon data structures
            let mut ii: ICONINFO = std::mem::zeroed();
            if GetIconInfo(hicon, &mut ii).is_ok() {
                // Clean up bitmaps from GetIconInfo
                if !ii.hbmMask.is_invalid() {
                    let _ = DeleteObject(HGDIOBJ(ii.hbmMask.0));
                }
                if !ii.hbmColor.is_invalid() {
                    let _ = DeleteObject(HGDIOBJ(ii.hbmColor.0));
                }
            }
        }
    }
}

fn use_window_obj(state: &SharedState, slot: usize, rng: &mut impl Rng) {
    let handle = state.windows[slot].load(Ordering::Relaxed);
    if handle != 0 {
        unsafe {
            let hwnd = HWND(handle as isize);
            
            match rng.gen_range(0..5) {
                0 => {
                    // GetWindowLong - reads window data
                    let _ = GetWindowLongW(hwnd, GWL_STYLE);
                }
                1 => {
                    // SetWindowLong - writes window data
                    let _ = SetWindowLongW(hwnd, GWL_STYLE, (WS_DISABLED.0) as i32);
                }
                2 => {
                    // GetWindowRect - reads position
                    let mut rect: RECT = std::mem::zeroed();
                    let _ = GetWindowRect(hwnd, &mut rect);
                }
                3 => {
                    // SetWindowPos - modifies window
                    let _ = SetWindowPos(hwnd, None, 0, 0, 1, 1, SWP_NOMOVE | SWP_NOSIZE);
                }
                _ => {
                    // SendMessage - trigger window procedure
                    let _ = SendMessageW(hwnd, WM_NULL, WPARAM(0), LPARAM(0));
                }
            }
        }
    }
}

// Special race pattern: rapidly switch cursor while modifying menu
// This mirrors the CVE-2019-0803 attack pattern
fn cursor_menu_race(state: &SharedState, rng: &mut impl Rng) {
    unsafe {
        // Rapidly alternate between cursor and menu operations
        for _ in 0..10 {
            let cursor_slot = rng.gen_range(0..state.cursors.len());
            let menu_slot = rng.gen_range(0..state.menus.len());
            
            let cursor_h = state.cursors[cursor_slot].load(Ordering::Relaxed);
            let menu_h = state.menus[menu_slot].load(Ordering::Relaxed);
            
            if cursor_h != 0 {
                let _ = SetCursor(HCURSOR(cursor_h as isize));
            }
            
            if menu_h != 0 {
                // Menu operations that might race with cursor
                let _ = GetMenuItemCount(HMENU(menu_h as isize));
            }
            
            // Detect potential race condition
            if cursor_h != 0 && menu_h != 0 {
                state.races_detected.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// Cleanup all remaining handles
fn cleanup_handles(state: &SharedState) {
    // GDI objects
    for slot in &state.bitmaps {
        delete_gdi_object(slot);
    }
    for slot in &state.brushes {
        delete_gdi_object(slot);
    }
    for slot in &state.pens {
        delete_gdi_object(slot);
    }
    for slot in &state.regions {
        delete_gdi_object(slot);
    }
    for slot in &state.dcs {
        delete_dc_handle(slot);
    }
    for slot in &state.fonts {
        delete_gdi_object(slot);
    }
    
    // USER objects
    for slot in &state.menus {
        delete_menu_obj(slot);
    }
    for slot in &state.cursors {
        delete_cursor_obj(slot);
    }
    for slot in &state.icons {
        delete_icon_obj(slot);
    }
    for slot in &state.windows {
        delete_window_obj(slot);
    }
}
