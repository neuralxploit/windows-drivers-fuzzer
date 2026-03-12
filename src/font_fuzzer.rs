// Font Fuzzer - Targets win32k.sys / atmfd.sys
// Attack surface: Malformed TTF/OTF font files
// Goal: RCE via font parsing vulnerabilities
//
// CVE examples:
// - CVE-2020-1020 (atmfd.sys) - RCE via PostScript font
// - CVE-2020-0938 (atmfd.sys) - RCE via Type 1 font
// - CVE-2021-1732 (win32k.sys) - EoP via font handling

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use rand::Rng;

// Windows API for font loading
#[link(name = "gdi32")]
extern "system" {
    fn AddFontResourceExW(
        name: *const u16,
        fl: u32,
        res: *mut std::ffi::c_void,
    ) -> i32;
    
    fn RemoveFontResourceExW(
        name: *const u16,
        fl: u32,
        res: *mut std::ffi::c_void,
    ) -> i32;
    
    fn AddFontMemResourceEx(
        pFileView: *const u8,
        cjSize: u32,
        pvResrved: *mut std::ffi::c_void,
        pNumFonts: *mut u32,
    ) -> isize;
    
    fn RemoveFontMemResourceEx(
        h: isize,
    ) -> i32;
    
    // Font creation and rendering - THESE trigger deep kernel parsing!
    fn CreateFontW(
        cHeight: i32,
        cWidth: i32,
        cEscapement: i32,
        cOrientation: i32,
        cWeight: i32,
        bItalic: u32,
        bUnderline: u32,
        bStrikeOut: u32,
        iCharSet: u32,
        iOutPrecision: u32,
        iClipPrecision: u32,
        iQuality: u32,
        iPitchAndFamily: u32,
        pszFaceName: *const u16,
    ) -> isize;
    
    fn DeleteObject(ho: isize) -> i32;
    fn SelectObject(hdc: isize, h: isize) -> isize;
    fn GetDC(hwnd: isize) -> isize;
    fn ReleaseDC(hwnd: isize, hdc: isize) -> i32;
    
    // Text rendering - triggers glyph parsing!
    fn TextOutW(hdc: isize, x: i32, y: i32, lpString: *const u16, c: i32) -> i32;
    fn GetTextExtentPoint32W(hdc: isize, lpString: *const u16, c: i32, psizl: *mut Size) -> i32;
    fn GetGlyphOutlineW(
        hdc: isize,
        uChar: u32,
        fuFormat: u32,
        lpgm: *mut GlyphMetrics,
        cjBuffer: u32,
        pvBuffer: *mut u8,
        lpmat2: *const Mat2,
    ) -> u32;
    
    fn CreateCompatibleDC(hdc: isize) -> isize;
    fn DeleteDC(hdc: isize) -> i32;
    
    // === ADDITIONAL HIGH-VALUE APIs FOR CRASH HUNTING ===
    
    // Character width APIs - parse horizontal metrics, CVE-prone!
    fn GetCharABCWidthsW(hdc: isize, wFirst: u32, wLast: u32, lpABC: *mut ABC) -> i32;
    fn GetCharWidth32W(hdc: isize, iFirst: u32, iLast: u32, lpBuffer: *mut i32) -> i32;
    fn GetCharWidthFloatW(hdc: isize, iFirst: u32, iLast: u32, lpBuffer: *mut f32) -> i32;
    
    // Kerning - parses kern table, complex logic!
    fn GetKerningPairsW(hdc: isize, nPairs: u32, lpKernPair: *mut KerningPair) -> u32;
    
    // Font metrics - parses multiple tables!
    fn GetOutlineTextMetricsW(hdc: isize, cjCopy: u32, potm: *mut u8) -> u32;
    fn GetTextMetricsW(hdc: isize, lptm: *mut TextMetric) -> i32;
    
    // Glyph indices - parses cmap table!
    fn GetGlyphIndicesW(hdc: isize, lpstr: *const u16, c: i32, pgi: *mut u16, fl: u32) -> u32;
    
    // Font data - raw table access!
    fn GetFontData(hdc: isize, dwTable: u32, dwOffset: u32, pvBuffer: *mut u8, cjBuffer: u32) -> u32;
    
    // Extended text rendering
    fn ExtTextOutW(hdc: isize, x: i32, y: i32, options: u32, lprect: *const Rect, lpString: *const u16, c: u32, lpDx: *const i32) -> i32;
    fn DrawTextW(hdc: isize, lpchText: *const u16, cchText: i32, lprc: *mut Rect, format: u32) -> i32;
    
    // Path APIs - complex glyph -> path conversion!
    fn BeginPath(hdc: isize) -> i32;
    fn EndPath(hdc: isize) -> i32;
    fn FlattenPath(hdc: isize) -> i32;
    fn WidenPath(hdc: isize) -> i32;
    fn StrokePath(hdc: isize) -> i32;
    fn FillPath(hdc: isize) -> i32;
    
    // CreateScalableFontResourceW - TTF to FON conversion!
    fn CreateScalableFontResourceW(fdwHidden: u32, lpszFont: *const u16, lpszFile: *const u16, lpszPath: *const u16) -> i32;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ABC {
    abcA: i32,
    abcB: u32,
    abcC: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KerningPair {
    wFirst: u16,
    wSecond: u16,
    iKernAmount: i32,
}

#[repr(C)]
struct TextMetric {
    tmHeight: i32,
    tmAscent: i32,
    tmDescent: i32,
    tmInternalLeading: i32,
    tmExternalLeading: i32,
    tmAveCharWidth: i32,
    tmMaxCharWidth: i32,
    tmWeight: i32,
    tmOverhang: i32,
    tmDigitizedAspectX: i32,
    tmDigitizedAspectY: i32,
    tmFirstChar: u16,
    tmLastChar: u16,
    tmDefaultChar: u16,
    tmBreakChar: u16,
    tmItalic: u8,
    tmUnderlined: u8,
    tmStruckOut: u8,
    tmPitchAndFamily: u8,
    tmCharSet: u8,
}

#[repr(C)]
struct Rect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[repr(C)]
struct Size {
    cx: i32,
    cy: i32,
}

#[repr(C)]
struct GlyphMetrics {
    gmBlackBoxX: u32,
    gmBlackBoxY: u32,
    gmptGlyphOrigin: Point,
    gmCellIncX: i16,
    gmCellIncY: i16,
}

#[repr(C)]
struct Point {
    x: i32,
    y: i32,
}

#[repr(C)]
struct Mat2 {
    eM11: Fixed,
    eM12: Fixed,
    eM21: Fixed,
    eM22: Fixed,
}

#[repr(C)]
struct Fixed {
    fract: u16,
    value: i16,
}

const FR_PRIVATE: u32 = 0x10;
const GGO_METRICS: u32 = 0;
const GGO_BITMAP: u32 = 1;
const GGO_NATIVE: u32 = 2;
const GGO_BEZIER: u32 = 3;
const GGO_GRAY2_BITMAP: u32 = 4;
const GGO_GRAY4_BITMAP: u32 = 5;
const GGO_GRAY8_BITMAP: u32 = 6;
const GGO_GLYPH_INDEX: u32 = 0x0080;
const GGO_UNHINTED: u32 = 0x0100;

const GGI_MARK_NONEXISTING_GLYPHS: u32 = 0x0001;

// TrueType/OpenType structures
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TTFHeader {
    sfnt_version: u32,      // 0x00010000 for TrueType, 'OTTO' for OpenType
    num_tables: u16,
    search_range: u16,
    entry_selector: u16,
    range_shift: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct TableRecord {
    tag: [u8; 4],           // Table name (e.g., "cmap", "glyf")
    checksum: u32,
    offset: u32,
    length: u32,
}

// Critical tables for fuzzing
const CRITICAL_TABLES: &[&[u8; 4]] = &[
    b"glyf",    // Glyph data - complex parsing, many bugs
    b"loca",    // Index to location - pointer bugs
    b"cmap",    // Character mapping - lookup bugs
    b"head",    // Header - size/bounds bugs
    b"hhea",    // Horizontal metrics header
    b"hmtx",    // Horizontal metrics
    b"maxp",    // Maximum profile - allocation bugs
    b"name",    // Naming table - string bugs
    b"post",    // PostScript info
    b"OS/2",    // OS/2 metrics
    b"kern",    // Kerning - complex parsing
    b"GDEF",    // Glyph definition
    b"GPOS",    // Glyph positioning
    b"GSUB",    // Glyph substitution
];

// System fonts to use as templates
const SYSTEM_FONTS: &[&str] = &[
    "C:\\Windows\\Fonts\\arial.ttf",
    "C:\\Windows\\Fonts\\times.ttf",
    "C:\\Windows\\Fonts\\cour.ttf",
    "C:\\Windows\\Fonts\\verdana.ttf",
    "C:\\Windows\\Fonts\\tahoma.ttf",
    "C:\\Windows\\Fonts\\calibri.ttf",
    "C:\\Windows\\Fonts\\segoeui.ttf",
    "C:\\Windows\\Fonts\\consola.ttf",
];

pub struct FontFuzzer {
    work_dir: PathBuf,
    crash_dir: PathBuf,
    iteration: u64,
    mutations: Vec<String>,
    templates: Vec<Vec<u8>>,  // Real font templates
}

impl FontFuzzer {
    pub fn new(output_dir: &str) -> Self {
        let work_dir = PathBuf::from(output_dir).join("font_work");
        let crash_dir = PathBuf::from(output_dir).join("font_crashes");
        
        fs::create_dir_all(&work_dir).ok();
        fs::create_dir_all(&crash_dir).ok();
        
        // Load real fonts as templates (silent)
        let mut templates = Vec::new();
        for font_path in SYSTEM_FONTS {
            if let Ok(data) = fs::read(font_path) {
                templates.push(data);
            }
        }
        
        FontFuzzer {
            work_dir,
            crash_dir,
            iteration: 0,
            mutations: vec![
                // Subtle mutations (keep font mostly valid)
                "flip_random_byte".to_string(),
                "flip_random_bits".to_string(),
                "corrupt_table_checksum".to_string(),
                "off_by_one_size".to_string(),
                "swap_table_offsets".to_string(),
                // Medium mutations
                "corrupt_glyf_points".to_string(),
                "corrupt_cmap_entry".to_string(),
                "corrupt_loca_index".to_string(),
                "corrupt_head_bounds".to_string(),
                "corrupt_maxp_counts".to_string(),
                // Aggressive mutations
                "overflow_table_size".to_string(),
                "invalid_table_offset".to_string(),
                "negative_values".to_string(),
                "truncate_table".to_string(),
                // === NEW HIGH-VALUE MUTATIONS ===
                // Hint instruction bugs (CVE-2020-0938 class)
                "corrupt_fpgm_hints".to_string(),
                "corrupt_prep_hints".to_string(),
                "corrupt_cvt_values".to_string(),
                // Composite glyph bugs (pointer chasing!)
                "corrupt_composite_glyph".to_string(),
                "circular_composite_ref".to_string(),
                "deep_composite_nesting".to_string(),
                // Integer overflow targets
                "overflow_num_glyphs".to_string(),
                "overflow_num_points".to_string(),
                "overflow_string_offset".to_string(),
                // Name table bugs (string parsing)
                "corrupt_name_records".to_string(),
                "long_name_string".to_string(),
                // CFF/PostScript bugs (atmfd.sys)
                "corrupt_cff_header".to_string(),
                "corrupt_cff_index".to_string(),
                // Kerning table bugs
                "corrupt_kern_pairs".to_string(),
                "overflow_kern_count".to_string(),
                // OpenType feature bugs
                "corrupt_gsub_lookup".to_string(),
                "corrupt_gpos_anchor".to_string(),
                // Zero/NULL bugs
                "zero_table_size".to_string(),
                "null_offset".to_string(),
            ],
            templates,
        }
    }
    
    // Get a real font template (or generate synthetic if none available)
    fn get_template(&self) -> Vec<u8> {
        if !self.templates.is_empty() {
            let mut rng = rand::thread_rng();
            let idx = rng.gen_range(0..self.templates.len());
            self.templates[idx].clone()
        } else {
            self.generate_synthetic_ttf()
        }
    }
    
    // Generate a minimal valid TTF structure (fallback)
    fn generate_synthetic_ttf(&self) -> Vec<u8> {
        let mut data = Vec::new();
        
        // TTF Header
        let header = TTFHeader {
            sfnt_version: 0x00010000u32.to_be(),  // TrueType
            num_tables: 9u16.to_be(),
            search_range: 128u16.to_be(),
            entry_selector: 3u16.to_be(),
            range_shift: 16u16.to_be(),
        };
        
        data.extend(unsafe {
            std::slice::from_raw_parts(
                &header as *const _ as *const u8,
                std::mem::size_of::<TTFHeader>()
            )
        });
        
        // Table records (minimal set)
        let tables = [
            (b"head", 0x100u32, 0x36u32),   // Font header
            (b"hhea", 0x140u32, 0x24u32),   // Horizontal header
            (b"maxp", 0x170u32, 0x20u32),   // Maximum profile
            (b"OS/2", 0x190u32, 0x60u32),   // OS/2 metrics
            (b"cmap", 0x200u32, 0x40u32),   // Character map
            (b"loca", 0x240u32, 0x20u32),   // Index to location
            (b"glyf", 0x260u32, 0x100u32),  // Glyph data
            (b"name", 0x360u32, 0x40u32),   // Naming table
            (b"post", 0x3A0u32, 0x20u32),   // PostScript
        ];
        
        for (tag, offset, length) in &tables {
            let record = TableRecord {
                tag: **tag,
                checksum: 0, // We'll corrupt this anyway
                offset: offset.to_be(),
                length: length.to_be(),
            };
            data.extend(unsafe {
                std::slice::from_raw_parts(
                    &record as *const _ as *const u8,
                    std::mem::size_of::<TableRecord>()
                )
            });
        }
        
        // Pad to first table
        while data.len() < 0x100 {
            data.push(0);
        }
        
        // head table (font header)
        data.extend(&[
            0x00, 0x01, 0x00, 0x00,  // version
            0x00, 0x01, 0x00, 0x00,  // fontRevision
            0x00, 0x00, 0x00, 0x00,  // checksumAdjustment
            0x5F, 0x0F, 0x3C, 0xF5,  // magicNumber
            0x00, 0x0B,              // flags
            0x00, 0x40,              // unitsPerEm (64)
        ]);
        // Pad rest of head
        while data.len() < 0x140 {
            data.push(0);
        }
        
        // hhea table
        data.extend(&[
            0x00, 0x01, 0x00, 0x00,  // version
            0x00, 0x40,              // ascender
            0xFF, 0xC0,              // descender  
            0x00, 0x00,              // lineGap
            0x00, 0x40,              // advanceWidthMax
        ]);
        while data.len() < 0x170 {
            data.push(0);
        }
        
        // maxp table
        data.extend(&[
            0x00, 0x01, 0x00, 0x00,  // version
            0x00, 0x02,              // numGlyphs
            0x00, 0x10,              // maxPoints
            0x00, 0x01,              // maxContours
        ]);
        while data.len() < 0x190 {
            data.push(0);
        }
        
        // OS/2 table (minimal)
        data.extend(&[0u8; 0x60]);
        while data.len() < 0x200 {
            data.push(0);
        }
        
        // cmap table (character mapping)
        data.extend(&[
            0x00, 0x00,              // version
            0x00, 0x01,              // numTables
            0x00, 0x00,              // platformID
            0x00, 0x03,              // encodingID
            0x00, 0x00, 0x00, 0x0C,  // offset
            // Format 0 subtable
            0x00, 0x00,              // format
            0x01, 0x06,              // length
            0x00, 0x00,              // language
        ]);
        while data.len() < 0x240 {
            data.push(0);
        }
        
        // loca table (index to glyph locations)
        data.extend(&[
            0x00, 0x00, 0x00, 0x00,  // glyph 0 offset
            0x00, 0x00, 0x00, 0x10,  // glyph 1 offset
            0x00, 0x00, 0x00, 0x20,  // end
        ]);
        while data.len() < 0x260 {
            data.push(0);
        }
        
        // glyf table (glyph data)
        // Simple glyph: square
        data.extend(&[
            0x00, 0x01,              // numberOfContours (1)
            0x00, 0x00,              // xMin
            0x00, 0x00,              // yMin
            0x00, 0x40,              // xMax
            0x00, 0x40,              // yMax
            0x00, 0x03,              // endPtsOfContours[0]
            0x00, 0x00,              // instructionLength
            // flags + coordinates (simplified)
            0x01, 0x01, 0x01, 0x01,
            0x00, 0x00, 0x40, 0x00,
            0x00, 0x40, 0x00, 0x00,
        ]);
        while data.len() < 0x360 {
            data.push(0);
        }
        
        // name table
        data.extend(&[
            0x00, 0x00,              // format
            0x00, 0x00,              // count
            0x00, 0x06,              // stringOffset
        ]);
        while data.len() < 0x3A0 {
            data.push(0);
        }
        
        // post table
        data.extend(&[
            0x00, 0x02, 0x00, 0x00,  // version 2.0
            0x00, 0x00, 0x00, 0x00,  // italicAngle
            0x00, 0x00,              // underlinePosition
            0x00, 0x00,              // underlineThickness
            0x00, 0x00, 0x00, 0x00,  // isFixedPitch
        ]);
        while data.len() < 0x400 {
            data.push(0);
        }
        
        data
    }
    
    // Apply mutations to TTF data
    fn apply_mutation(&self, data: &mut Vec<u8>, mutation: &str) {
        let mut rng = rand::thread_rng();
        
        if data.is_empty() {
            return;
        }
        
        match mutation {
            // ═══════════════════════════════════════════════════════════
            // SUBTLE MUTATIONS (keep font mostly valid - more likely to load)
            // ═══════════════════════════════════════════════════════════
            "flip_random_byte" => {
                // Flip 1-3 random bytes
                for _ in 0..rng.gen_range(1..4) {
                    let idx = rng.gen_range(0..data.len());
                    data[idx] = data[idx].wrapping_add(rng.gen_range(1..255));
                }
            }
            "flip_random_bits" => {
                // Flip random bits in 1-2 bytes
                for _ in 0..rng.gen_range(1..3) {
                    let idx = rng.gen_range(0..data.len());
                    let bit = 1u8 << rng.gen_range(0..8);
                    data[idx] ^= bit;
                }
            }
            "corrupt_table_checksum" => {
                // Find table directory and corrupt one checksum
                // Table records start at offset 12, each is 16 bytes
                // Checksum is at offset 4 within each record
                if data.len() >= 28 {
                    let num_tables = if data.len() >= 6 {
                        u16::from_be_bytes([data[4], data[5]]) as usize
                    } else { 1 };
                    let table_idx = rng.gen_range(0..num_tables.min(20));
                    let checksum_offset = 12 + table_idx * 16 + 4;
                    if checksum_offset + 4 <= data.len() {
                        // Just flip one byte in checksum
                        data[checksum_offset] ^= 0xFF;
                    }
                }
            }
            "off_by_one_size" => {
                // Change a size field by +/- 1 (classic off-by-one)
                if data.len() >= 28 {
                    let num_tables = if data.len() >= 6 {
                        u16::from_be_bytes([data[4], data[5]]) as usize
                    } else { 1 };
                    let table_idx = rng.gen_range(0..num_tables.min(20));
                    let size_offset = 12 + table_idx * 16 + 12;
                    if size_offset + 4 <= data.len() {
                        let size = u32::from_be_bytes([
                            data[size_offset], data[size_offset+1], 
                            data[size_offset+2], data[size_offset+3]
                        ]);
                        let new_size = if rng.gen_bool(0.5) {
                            size.wrapping_add(1)
                        } else {
                            size.wrapping_sub(1)
                        };
                        data[size_offset..size_offset+4].copy_from_slice(&new_size.to_be_bytes());
                    }
                }
            }
            "swap_table_offsets" => {
                // Swap two table offsets (can cause wrong data to be read)
                if data.len() >= 44 {
                    let offset1 = 12 + 8;  // First table's offset field
                    let offset2 = 12 + 16 + 8;  // Second table's offset field
                    if offset2 + 4 <= data.len() {
                        let tmp: Vec<u8> = data[offset1..offset1+4].to_vec();
                        let src: Vec<u8> = data[offset2..offset2+4].to_vec();
                        data[offset1..offset1+4].copy_from_slice(&src);
                        data[offset2..offset2+4].copy_from_slice(&tmp);
                    }
                }
            }
            // ═══════════════════════════════════════════════════════════
            // MEDIUM MUTATIONS (corrupt specific table data)
            // ═══════════════════════════════════════════════════════════
            "corrupt_glyf_points" => {
                // Find glyf table and corrupt point coordinates
                // Look for "glyf" tag in table directory
                let glyf_offset = self.find_table_offset(data, b"glyf");
                if let Some(offset) = glyf_offset {
                    if offset + 20 < data.len() {
                        // Corrupt some coordinates
                        for i in 0..rng.gen_range(2..8) {
                            let idx = offset + 10 + i * 2;
                            if idx + 2 <= data.len() {
                                data[idx] = rng.gen();
                                data[idx + 1] = rng.gen();
                            }
                        }
                    }
                }
            }
            "corrupt_cmap_entry" => {
                // Find cmap table and corrupt an entry
                let cmap_offset = self.find_table_offset(data, b"cmap");
                if let Some(offset) = cmap_offset {
                    if offset + 20 < data.len() {
                        // Corrupt format or length
                        let idx = offset + rng.gen_range(4..16);
                        if idx < data.len() {
                            data[idx] ^= 0xFF;
                        }
                    }
                }
            }
            "corrupt_loca_index" => {
                // Find loca table and corrupt glyph location
                let loca_offset = self.find_table_offset(data, b"loca");
                if let Some(offset) = loca_offset {
                    if offset + 8 < data.len() {
                        // Corrupt one location entry
                        let idx = offset + rng.gen_range(0..4) * 4;
                        if idx + 4 <= data.len() {
                            data[idx..idx+4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
                        }
                    }
                }
            }
            "corrupt_head_bounds" => {
                // Find head table and corrupt bounding box
                let head_offset = self.find_table_offset(data, b"head");
                if let Some(offset) = head_offset {
                    // xMin, yMin, xMax, yMax are at offsets 36-44 in head table
                    if offset + 44 < data.len() {
                        let bounds_offset = offset + 36 + rng.gen_range(0..4) * 2;
                        if bounds_offset + 2 <= data.len() {
                            // Set to extreme value
                            data[bounds_offset..bounds_offset+2].copy_from_slice(&0x7FFFu16.to_be_bytes());
                        }
                    }
                }
            }
            "corrupt_maxp_counts" => {
                // Find maxp table and corrupt max values
                let maxp_offset = self.find_table_offset(data, b"maxp");
                if let Some(offset) = maxp_offset {
                    if offset + 20 < data.len() {
                        // numGlyphs at offset 4, maxPoints at offset 6, etc.
                        let field_offset = offset + 4 + rng.gen_range(0..6) * 2;
                        if field_offset + 2 <= data.len() {
                            data[field_offset..field_offset+2].copy_from_slice(&0xFFFFu16.to_be_bytes());
                        }
                    }
                }
            }
            // ═══════════════════════════════════════════════════════════
            // AGGRESSIVE MUTATIONS (more likely to break font but can trigger deep bugs)
            // ═══════════════════════════════════════════════════════════
            "overflow_table_size" => {
                // Set table size to huge value (integer overflow)
                if data.len() >= 28 {
                    let num_tables = if data.len() >= 6 {
                        u16::from_be_bytes([data[4], data[5]]) as usize
                    } else { 1 };
                    let table_idx = rng.gen_range(0..num_tables.min(20));
                    let size_offset = 12 + table_idx * 16 + 12;
                    if size_offset + 4 <= data.len() {
                        data[size_offset..size_offset+4].copy_from_slice(&0xFFFFFFFFu32.to_be_bytes());
                    }
                }
            }
            "invalid_table_offset" => {
                // Point table offset outside file
                if data.len() >= 24 {
                    let num_tables = if data.len() >= 6 {
                        u16::from_be_bytes([data[4], data[5]]) as usize
                    } else { 1 };
                    let table_idx = rng.gen_range(0..num_tables.min(20));
                    let offset_field = 12 + table_idx * 16 + 8;
                    if offset_field + 4 <= data.len() {
                        data[offset_field..offset_field+4].copy_from_slice(&0x7FFFFFFFu32.to_be_bytes());
                    }
                }
            }
            "negative_values" => {
                // Set values to negative (signed interpretation issues)
                for _ in 0..rng.gen_range(1..5) {
                    let idx = rng.gen_range(0..(data.len() / 2)) * 2;
                    if idx + 2 <= data.len() {
                        data[idx..idx+2].copy_from_slice(&0x8000u16.to_be_bytes());
                    }
                }
            }
            "truncate_table" => {
                // Truncate file mid-table (but keep header valid)
                let min_size = 200.min(data.len());
                let truncate_at = rng.gen_range(min_size..data.len());
                data.truncate(truncate_at);
            }
            
            // ═══════════════════════════════════════════════════════════
            // NEW HIGH-VALUE MUTATIONS - Known CVE bug classes!
            // ═══════════════════════════════════════════════════════════
            
            "corrupt_fpgm_hints" | "corrupt_prep_hints" => {
                // TrueType hint instructions - CVE-2020-0938 bug class!
                // fpgm = font program, prep = CVT program
                let table = if mutation == "corrupt_fpgm_hints" { b"fpgm" } else { b"prep" };
                let offset = self.find_table_offset(data, table);
                if let Some(off) = offset {
                    if off + 32 < data.len() {
                        // Corrupt hint opcodes
                        for i in 0..rng.gen_range(4..16) {
                            let idx = off + i;
                            if idx < data.len() {
                                // Use dangerous opcodes: CALL, LOOPCALL, FDEF, IDEF
                                let dangerous = [0x2A, 0x2B, 0x2C, 0x2D, 0x89, 0x8A, 0x58, 0x59];
                                data[idx] = dangerous[rng.gen_range(0..dangerous.len())];
                            }
                        }
                    }
                }
            }
            "corrupt_cvt_values" => {
                // CVT (Control Value Table) - used by hints
                let offset = self.find_table_offset(data, b"cvt ");
                if let Some(off) = offset {
                    if off + 20 < data.len() {
                        for i in 0..rng.gen_range(2..10) {
                            let idx = off + i * 2;
                            if idx + 2 <= data.len() {
                                // Extreme values
                                let extreme: u16 = if rng.gen_bool(0.5) { 0x7FFF } else { 0x8000 };
                                data[idx..idx+2].copy_from_slice(&extreme.to_be_bytes());
                            }
                        }
                    }
                }
            }
            "corrupt_composite_glyph" => {
                // Composite glyphs have references to other glyphs
                // Bug: reference to out-of-bounds glyph ID
                let glyf_offset = self.find_table_offset(data, b"glyf");
                if let Some(off) = glyf_offset {
                    // Look for composite glyph marker (numberOfContours == -1)
                    for i in (off..data.len().min(off + 2000)).step_by(20) {
                        if i + 12 <= data.len() {
                            // Set to -1 (composite) and corrupt component glyph ID
                            data[i..i+2].copy_from_slice(&0xFFFFu16.to_be_bytes()); // -1 = composite
                            // Component at offset +10: glyphIndex + flags
                            if i + 14 <= data.len() {
                                // flags = HAS_ARG1_2 | ARG_1_AND_2_ARE_WORDS
                                data[i+10..i+12].copy_from_slice(&0x0003u16.to_be_bytes());
                                // glyphIndex = 0xFFFF (invalid!)
                                data[i+12..i+14].copy_from_slice(&0xFFFFu16.to_be_bytes());
                            }
                            break;
                        }
                    }
                }
            }
            "circular_composite_ref" => {
                // Create circular reference: glyph A refs B, B refs A = infinite loop!
                let glyf_offset = self.find_table_offset(data, b"glyf");
                if let Some(off) = glyf_offset {
                    if off + 30 < data.len() {
                        // Make glyph 0 a composite referencing glyph 1
                        data[off..off+2].copy_from_slice(&0xFFFFu16.to_be_bytes()); // -1
                        data[off+10..off+12].copy_from_slice(&0x0003u16.to_be_bytes()); // flags
                        data[off+12..off+14].copy_from_slice(&0x0001u16.to_be_bytes()); // ref glyph 1
                        
                        // Make glyph 1 reference glyph 0 (CIRCULAR!)
                        let glyph1_off = off + 20;
                        if glyph1_off + 14 <= data.len() {
                            data[glyph1_off..glyph1_off+2].copy_from_slice(&0xFFFFu16.to_be_bytes());
                            data[glyph1_off+10..glyph1_off+12].copy_from_slice(&0x0003u16.to_be_bytes());
                            data[glyph1_off+12..glyph1_off+14].copy_from_slice(&0x0000u16.to_be_bytes()); // ref glyph 0!
                        }
                    }
                }
            }
            "deep_composite_nesting" => {
                // Deep nesting: A->B->C->D->E... stack overflow potential
                let glyf_offset = self.find_table_offset(data, b"glyf");
                if let Some(off) = glyf_offset {
                    for i in 0..20 {
                        let glyph_off = off + i * 16;
                        if glyph_off + 16 <= data.len() {
                            data[glyph_off..glyph_off+2].copy_from_slice(&0xFFFFu16.to_be_bytes()); // composite
                            data[glyph_off+10..glyph_off+12].copy_from_slice(&0x0003u16.to_be_bytes());
                            // Reference next glyph
                            let next = ((i + 1) % 20) as u16;
                            data[glyph_off+12..glyph_off+14].copy_from_slice(&next.to_be_bytes());
                        }
                    }
                }
            }
            "overflow_num_glyphs" => {
                // maxp.numGlyphs overflow - allocation bugs!
                let maxp_offset = self.find_table_offset(data, b"maxp");
                if let Some(off) = maxp_offset {
                    if off + 6 <= data.len() {
                        // numGlyphs = 0xFFFF (massive allocation!)
                        data[off+4..off+6].copy_from_slice(&0xFFFFu16.to_be_bytes());
                    }
                }
            }
            "overflow_num_points" => {
                // maxp.maxPoints overflow
                let maxp_offset = self.find_table_offset(data, b"maxp");
                if let Some(off) = maxp_offset {
                    if off + 8 <= data.len() {
                        data[off+6..off+8].copy_from_slice(&0xFFFFu16.to_be_bytes()); // maxPoints
                    }
                    if off + 10 <= data.len() {
                        data[off+8..off+10].copy_from_slice(&0xFFFFu16.to_be_bytes()); // maxContours
                    }
                }
            }
            "overflow_string_offset" => {
                // name table string offset overflow
                let name_offset = self.find_table_offset(data, b"name");
                if let Some(off) = name_offset {
                    if off + 20 <= data.len() {
                        // stringOffset at +4
                        data[off+4..off+6].copy_from_slice(&0xFFFFu16.to_be_bytes());
                    }
                }
            }
            "corrupt_name_records" => {
                // Name table: corrupt name records (string parsing bugs)
                let name_offset = self.find_table_offset(data, b"name");
                if let Some(off) = name_offset {
                    if off + 30 <= data.len() {
                        // First name record at +6
                        let rec_off = off + 6;
                        // length (offset 8 in record) = 0xFFFF
                        if rec_off + 12 <= data.len() {
                            data[rec_off+8..rec_off+10].copy_from_slice(&0xFFFFu16.to_be_bytes());
                            // offset = 0
                            data[rec_off+10..rec_off+12].copy_from_slice(&0x0000u16.to_be_bytes());
                        }
                    }
                }
            }
            "long_name_string" => {
                // Append very long string to trigger buffer issues
                let name_offset = self.find_table_offset(data, b"name");
                if name_offset.is_some() {
                    // Add lots of data at end
                    let long_string = vec![0x41u8; 65535]; // "AAAA..."
                    data.extend(long_string);
                }
            }
            "corrupt_cff_header" => {
                // CFF table (PostScript outlines) - atmfd.sys target!
                let cff_offset = self.find_table_offset(data, b"CFF ");
                if let Some(off) = cff_offset {
                    if off + 10 < data.len() {
                        // CFF header: major, minor, hdrSize, offSize
                        data[off] = rng.gen_range(2..10); // invalid major version
                        data[off+2] = 0xFF; // huge header size
                        data[off+3] = 4; // max offSize
                    }
                }
            }
            "corrupt_cff_index" => {
                // CFF Index structure corruption
                let cff_offset = self.find_table_offset(data, b"CFF ");
                if let Some(off) = cff_offset {
                    if off + 20 < data.len() {
                        // Name INDEX starts at header + hdrSize
                        let idx_off = off + 4;
                        if idx_off + 6 <= data.len() {
                            // count (2 bytes) = 0xFFFF
                            data[idx_off..idx_off+2].copy_from_slice(&0xFFFFu16.to_be_bytes());
                        }
                    }
                }
            }
            "corrupt_kern_pairs" => {
                // Kerning table - kern pair data corruption
                let kern_offset = self.find_table_offset(data, b"kern");
                if let Some(off) = kern_offset {
                    if off + 20 < data.len() {
                        // Corrupt kern pairs
                        for i in 0..rng.gen_range(3..10) {
                            let idx = off + 8 + i * 6;
                            if idx + 6 <= data.len() {
                                // left glyph = 0xFFFF, right = 0xFFFF
                                data[idx..idx+2].copy_from_slice(&0xFFFFu16.to_be_bytes());
                                data[idx+2..idx+4].copy_from_slice(&0xFFFFu16.to_be_bytes());
                                // kern value = extreme
                                data[idx+4..idx+6].copy_from_slice(&0x8000u16.to_be_bytes());
                            }
                        }
                    }
                }
            }
            "overflow_kern_count" => {
                let kern_offset = self.find_table_offset(data, b"kern");
                if let Some(off) = kern_offset {
                    if off + 10 <= data.len() {
                        // nPairs = 0xFFFF
                        data[off+6..off+8].copy_from_slice(&0xFFFFu16.to_be_bytes());
                    }
                }
            }
            "corrupt_gsub_lookup" => {
                // GSUB (glyph substitution) - complex parsing!
                let gsub_offset = self.find_table_offset(data, b"GSUB");
                if let Some(off) = gsub_offset {
                    if off + 20 < data.len() {
                        // Corrupt lookup list offset
                        data[off+8..off+10].copy_from_slice(&0xFFFFu16.to_be_bytes());
                    }
                }
            }
            "corrupt_gpos_anchor" => {
                // GPOS (glyph positioning) - anchor point bugs
                let gpos_offset = self.find_table_offset(data, b"GPOS");
                if let Some(off) = gpos_offset {
                    if off + 20 < data.len() {
                        // Corrupt feature list offset
                        data[off+6..off+8].copy_from_slice(&0xFFFFu16.to_be_bytes());
                    }
                }
            }
            "zero_table_size" => {
                // Zero-size table (division by zero, null deref)
                if data.len() >= 28 {
                    let num_tables = if data.len() >= 6 {
                        u16::from_be_bytes([data[4], data[5]]) as usize
                    } else { 1 };
                    let table_idx = rng.gen_range(0..num_tables.min(20));
                    let size_offset = 12 + table_idx * 16 + 12;
                    if size_offset + 4 <= data.len() {
                        data[size_offset..size_offset+4].copy_from_slice(&0u32.to_be_bytes());
                    }
                }
            }
            "null_offset" => {
                // Null (zero) offset for table
                if data.len() >= 24 {
                    let num_tables = if data.len() >= 6 {
                        u16::from_be_bytes([data[4], data[5]]) as usize
                    } else { 1 };
                    let table_idx = rng.gen_range(0..num_tables.min(20));
                    let offset_field = 12 + table_idx * 16 + 8;
                    if offset_field + 4 <= data.len() {
                        data[offset_field..offset_field+4].copy_from_slice(&0u32.to_be_bytes());
                    }
                }
            }
            _ => {
                // Random byte corruption (fallback)
                for _ in 0..rng.gen_range(1..5) {
                    let idx = rng.gen_range(0..data.len());
                    data[idx] = rng.gen();
                }
            }
        }
    }
    
    // Helper: Find table offset by tag name
    fn find_table_offset(&self, data: &[u8], tag: &[u8; 4]) -> Option<usize> {
        if data.len() < 12 {
            return None;
        }
        
        let num_tables = u16::from_be_bytes([data[4], data[5]]) as usize;
        
        for i in 0..num_tables.min(30) {
            let record_offset = 12 + i * 16;
            if record_offset + 16 > data.len() {
                break;
            }
            
            // Check tag
            if &data[record_offset..record_offset+4] == tag {
                // Return the offset field value
                let offset = u32::from_be_bytes([
                    data[record_offset + 8],
                    data[record_offset + 9],
                    data[record_offset + 10],
                    data[record_offset + 11],
                ]) as usize;
                return Some(offset);
            }
        }
        None
    }
    
    // Try to load font and trigger parsing
    fn trigger_font_parse(&self, font_path: &PathBuf) -> Result<(), String> {
        let wide_path: Vec<u16> = font_path.to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        
        unsafe {
            // Try AddFontResourceExW (file-based)
            let result = AddFontResourceExW(
                wide_path.as_ptr(),
                FR_PRIVATE,
                std::ptr::null_mut(),
            );
            
            if result > 0 {
                // Font was loaded - remove it
                RemoveFontResourceExW(
                    wide_path.as_ptr(),
                    FR_PRIVATE,
                    std::ptr::null_mut(),
                );
                return Ok(());
            }
        }
        
        Err("Font rejected".to_string())
    }
    
    // Try memory-based font loading (can trigger different code paths)
    fn trigger_font_parse_memory(&self, font_data: &[u8]) -> Result<(), String> {
        unsafe {
            let mut num_fonts: u32 = 0;
            let handle = AddFontMemResourceEx(
                font_data.as_ptr(),
                font_data.len() as u32,
                std::ptr::null_mut(),
                &mut num_fonts,
            );
            
            if handle != 0 {
                RemoveFontMemResourceEx(handle);
                return Ok(());
            }
        }
        
        Err("Font rejected".to_string())
    }
    
    /// CRITICAL: Actually RENDER with the font to trigger deep kernel parsing!
    /// Just loading a font doesn't parse glyphs - rendering does!
    fn trigger_deep_font_parse(&self, font_data: &[u8]) -> Result<(), String> {
        unsafe {
            // Load font into memory
            let mut num_fonts: u32 = 0;
            let font_handle = AddFontMemResourceEx(
                font_data.as_ptr(),
                font_data.len() as u32,
                std::ptr::null_mut(),
                &mut num_fonts,
            );
            
            if font_handle == 0 {
                return Err("Font load failed".to_string());
            }
            
            // Create a DC (device context)
            let hdc = CreateCompatibleDC(0);
            if hdc == 0 {
                RemoveFontMemResourceEx(font_handle);
                return Err("CreateCompatibleDC failed".to_string());
            }
            
            // Create font object with the loaded font
            // Use a unique name based on iteration to find it
            let font_name: Vec<u16> = "FuzzFont\0".encode_utf16().collect();
            let hfont = CreateFontW(
                32,     // Height
                0,      // Width (0 = auto)
                0,      // Escapement
                0,      // Orientation
                400,    // Weight (normal)
                0,      // Italic
                0,      // Underline
                0,      // StrikeOut
                1,      // Charset (DEFAULT_CHARSET)
                0,      // OutPrecision
                0,      // ClipPrecision
                0,      // Quality
                0,      // PitchAndFamily
                font_name.as_ptr(),
            );
            
            if hfont != 0 {
                // Select font into DC - THIS triggers some parsing
                let old_font = SelectObject(hdc, hfont);
                
                // === TRIGGER DEEP GLYPH PARSING ===
                
                // 1. TextOut - renders glyphs
                let test_text: Vec<u16> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%\0"
                    .encode_utf16().collect();
                TextOutW(hdc, 0, 0, test_text.as_ptr(), test_text.len() as i32 - 1);
                
                // 2. GetTextExtentPoint32 - measures text, parses metrics
                let mut size = Size { cx: 0, cy: 0 };
                GetTextExtentPoint32W(hdc, test_text.as_ptr(), test_text.len() as i32 - 1, &mut size);
                
                // 3. GetGlyphOutline - DEEP parsing of glyph data!
                // This is where many CVEs were found
                let mut gm = GlyphMetrics {
                    gmBlackBoxX: 0,
                    gmBlackBoxY: 0,
                    gmptGlyphOrigin: Point { x: 0, y: 0 },
                    gmCellIncX: 0,
                    gmCellIncY: 0,
                };
                let mat2 = Mat2 {
                    eM11: Fixed { fract: 0, value: 1 },
                    eM12: Fixed { fract: 0, value: 0 },
                    eM21: Fixed { fract: 0, value: 0 },
                    eM22: Fixed { fract: 0, value: 1 },
                };
                
                // Get glyph outline for multiple characters with ALL formats!
                let test_chars: &[u32] = &[
                    0x0041, 0x0042, 0x0043,  // ABC
                    0x0061, 0x0062, 0x0063,  // abc
                    0x0030, 0x0031, 0x0032,  // 012
                    0x0000,                   // .notdef (often buggy!)
                    0xFFFF,                   // Invalid high
                    0xFFFE,                   // Reserved
                    0x20AC,                   // Euro sign (€)
                    0x2603,                   // Snowman (complex glyph)
                    0x1F600,                  // Emoji (outside BMP!)
                ];
                
                let mut buffer = vec![0u8; 65536];  // Large buffer for complex glyphs
                
                for &ch in test_chars {
                    // All GetGlyphOutline formats - each parses differently!
                    for format in &[
                        GGO_METRICS,
                        GGO_BITMAP,
                        GGO_NATIVE,
                        GGO_BEZIER,
                        GGO_GRAY2_BITMAP,
                        GGO_GRAY4_BITMAP,
                        GGO_GRAY8_BITMAP,
                        GGO_NATIVE | GGO_UNHINTED,  // Unhinted = different code path
                        GGO_BEZIER | GGO_GLYPH_INDEX,
                    ] {
                        GetGlyphOutlineW(hdc, ch, *format, &mut gm, buffer.len() as u32, buffer.as_mut_ptr(), &mat2);
                    }
                }
                
                // 4. GetCharABCWidths - parses hmtx table!
                let mut abc_buffer = vec![ABC { abcA: 0, abcB: 0, abcC: 0 }; 256];
                GetCharABCWidthsW(hdc, 0, 255, abc_buffer.as_mut_ptr());
                GetCharABCWidthsW(hdc, 0xFFFF, 0xFFFF, abc_buffer.as_mut_ptr()); // Edge case
                
                // 5. GetCharWidth32 - character widths
                let mut width_buffer = vec![0i32; 256];
                GetCharWidth32W(hdc, 0, 255, width_buffer.as_mut_ptr());
                
                // 6. GetKerningPairs - parses kern table!
                let num_pairs = GetKerningPairsW(hdc, 0, std::ptr::null_mut());
                if num_pairs > 0 && num_pairs < 10000 {
                    let mut kern_pairs = vec![KerningPair { wFirst: 0, wSecond: 0, iKernAmount: 0 }; num_pairs as usize];
                    GetKerningPairsW(hdc, num_pairs, kern_pairs.as_mut_ptr());
                }
                
                // 7. GetGlyphIndices - cmap parsing with edge cases!
                let unicode_test: Vec<u16> = "Test\u{0000}\u{FFFF}\u{FFFE}\0".encode_utf16().collect();
                let mut glyph_indices = vec![0u16; unicode_test.len()];
                GetGlyphIndicesW(hdc, unicode_test.as_ptr(), unicode_test.len() as i32, glyph_indices.as_mut_ptr(), GGI_MARK_NONEXISTING_GLYPHS);
                
                // 8. GetOutlineTextMetrics - parses OS/2, hhea, head tables!
                let otm_size = GetOutlineTextMetricsW(hdc, 0, std::ptr::null_mut());
                if otm_size > 0 && otm_size < 65536 {
                    let mut otm_buffer = vec![0u8; otm_size as usize];
                    GetOutlineTextMetricsW(hdc, otm_size, otm_buffer.as_mut_ptr());
                }
                
                // 9. GetTextMetrics - basic metrics
                let mut tm = TextMetric {
                    tmHeight: 0, tmAscent: 0, tmDescent: 0,
                    tmInternalLeading: 0, tmExternalLeading: 0,
                    tmAveCharWidth: 0, tmMaxCharWidth: 0,
                    tmWeight: 0, tmOverhang: 0,
                    tmDigitizedAspectX: 0, tmDigitizedAspectY: 0,
                    tmFirstChar: 0, tmLastChar: 0,
                    tmDefaultChar: 0, tmBreakChar: 0,
                    tmItalic: 0, tmUnderlined: 0, tmStruckOut: 0,
                    tmPitchAndFamily: 0, tmCharSet: 0,
                };
                GetTextMetricsW(hdc, &mut tm);
                
                // 10. GetFontData - direct table access!
                let critical_tables: &[u32] = &[
                    0x676C7966,  // 'glyf'
                    0x6C6F6361,  // 'loca'
                    0x636D6170,  // 'cmap'
                    0x68656164,  // 'head'
                    0x6D617870,  // 'maxp'
                    0x6B65726E,  // 'kern'
                    0x47535542,  // 'GSUB'
                    0x47504F53,  // 'GPOS'
                    0x43464620,  // 'CFF '
                    0x66706D67,  // 'fpgm'
                    0x70726570,  // 'prep'
                ];
                let mut table_buffer = vec![0u8; 65536];
                for &tag in critical_tables {
                    GetFontData(hdc, tag, 0, table_buffer.as_mut_ptr(), table_buffer.len() as u32);
                }
                
                // 11. Path operations - glyph to path conversion!
                BeginPath(hdc);
                TextOutW(hdc, 0, 0, test_text.as_ptr(), 10);
                EndPath(hdc);
                FlattenPath(hdc);  // Convert curves to lines
                
                // 12. ExtTextOut with various options
                let rect = Rect { left: 0, top: 0, right: 1000, bottom: 1000 };
                ExtTextOutW(hdc, 0, 0, 0, &rect, test_text.as_ptr(), 20, std::ptr::null());
                
                // Restore old font and cleanup
                SelectObject(hdc, old_font);
                DeleteObject(hfont);
            }
            
            DeleteDC(hdc);
            RemoveFontMemResourceEx(font_handle);
            
            Ok(())
        }
    }
    
    // Save crash-inducing font
    pub fn save_crash(&self, data: &[u8], mutation: &str) {
        let crash_path = self.crash_dir.join(format!(
            "crash_{}_{}.ttf",
            self.iteration,
            mutation.replace(" ", "_")
        ));
        
        if let Ok(mut file) = File::create(&crash_path) {
            let _ = file.write_all(data);
            println!("\n[!] CRASH SAVED: {:?}", crash_path);
        }
    }
    
    // Main fuzzing loop
    pub fn run(&mut self, max_iterations: u64) {
        use std::io::Write as IoWrite;
        use std::time::Instant;
        
        println!("[*] 🔤 FONT FUZZER | win32k/atmfd | {} templates | {:?}", self.templates.len(), self.crash_dir);
        
        let mutation_count = self.mutations.len();
        let mut successes = 0u64;
        let mut deep_parses = 0u64;
        let mut rng = rand::thread_rng();
        let start_time = Instant::now();
        
        for i in 0..max_iterations {
            self.iteration = i;
            
            // Pick mutation - use all mutations now with weighting
            let mutation = if rng.gen_bool(0.3) {
                // 30% subtle mutations (more likely to load)
                &self.mutations[rng.gen_range(0..5)].clone()
            } else if rng.gen_bool(0.5) {
                // 35% medium mutations
                &self.mutations[rng.gen_range(5..15)].clone()
            } else {
                // 35% aggressive mutations (high bug potential)
                &self.mutations[rng.gen_range(15..mutation_count)].clone()
            };
            
            // Generate and mutate font - USE REAL FONTS AS TEMPLATE!
            let mut font_data = self.get_template();
            self.apply_mutation(&mut font_data, mutation);
            
            // Extra random mutations sometimes (stacking = more bugs)
            if rng.gen_bool(0.3) {
                let extra = &self.mutations[rng.gen_range(0..mutation_count)].clone();
                self.apply_mutation(&mut font_data, extra);
            }
            
            // Save font BEFORE loading (rotating last 10 only)
            // If BSOD happens, check crash_dir for the trigger!
            let slot = (i % 10) as u32;
            let save_path = self.crash_dir.join(format!("last_{:02}.ttf", slot));
            let _ = fs::write(&save_path, &font_data);
            
            // Also save mutation info
            let info_path = self.crash_dir.join(format!("last_{:02}.txt", slot));
            let _ = fs::write(&info_path, format!("Iteration: {}\nMutation: {}", i, mutation));
            
            // Write to work file
            let font_path = self.work_dir.join(format!("fuzz_{:08}.ttf", i));
            if let Ok(mut file) = File::create(&font_path) {
                let _ = file.write_all(&font_data);
            }
            
            // Try loading AND deep parsing (rendering)
            // Deep parsing triggers GetGlyphOutline which is where bugs are!
            let result1 = self.trigger_font_parse(&font_path);
            let result2 = self.trigger_font_parse_memory(&font_data);
            let result3 = self.trigger_deep_font_parse(&font_data);
            
            if result1.is_ok() || result2.is_ok() {
                successes += 1;
            }
            
            if result3.is_ok() {
                deep_parses += 1;
                
                // Extra aggressive mutations on successful fonts
                if rng.gen_bool(0.1) {
                    let mut aggressive_font = font_data.clone();
                    self.apply_mutation(&mut aggressive_font, "overflow_table_size");
                    let _ = self.trigger_deep_font_parse(&aggressive_font);
                }
            }
            
            // Real-time single line progress update
            let elapsed = start_time.elapsed().as_secs();
            let hours = elapsed / 3600;
            let minutes = (elapsed % 3600) / 60;
            let seconds = elapsed % 60;
            let rate = if elapsed > 0 { i / elapsed } else { 0 };
            
            print!("\r[{:02}:{:02}:{:02}] 🔤 FONT | {:>8} iter | ✓{} | deep {} | {}/s | {:20}          ",
                   hours, minutes, seconds,
                   i, successes, deep_parses, rate, 
                   &mutation[..mutation.len().min(20)]);
            std::io::stdout().flush().ok();
            
            // Cleanup old files
            if i > 100 {
                let old = self.work_dir.join(format!("fuzz_{:08}.ttf", i - 100));
                let _ = fs::remove_file(old);
            }
        }
        
        let elapsed = start_time.elapsed().as_secs();
        let rate = if elapsed > 0 { max_iterations / elapsed } else { 0 };
        println!("\n\n[+] DONE | {} iter | ✓{} loaded | {} deep | {}/s", max_iterations, successes, deep_parses, rate);
    }
}

// Advanced genetic font fuzzer
pub struct GeneticFontFuzzer {
    base_fuzzer: FontFuzzer,
    population: Vec<Vec<u8>>,
    fitness: Vec<f64>,
    generation: u32,
}

impl GeneticFontFuzzer {
    pub fn new(output_dir: &str) -> Self {
        GeneticFontFuzzer {
            base_fuzzer: FontFuzzer::new(output_dir),
            population: Vec::new(),
            fitness: Vec::new(),
            generation: 0,
        }
    }
    
    // Initialize population with mutated base fonts (USE REAL FONTS!)
    fn init_population(&mut self, size: usize) {
        for i in 0..size {
            let mut font = self.base_fuzzer.get_template();
            let mutation = &self.base_fuzzer.mutations[i % self.base_fuzzer.mutations.len()];
            self.base_fuzzer.apply_mutation(&mut font, mutation);
            self.population.push(font);
            self.fitness.push(0.0);
        }
    }
    
    // Crossover two fonts
    fn crossover(&self, a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let min_len = a.len().min(b.len());
        let mut result = Vec::with_capacity(min_len);
        
        // Two-point crossover
        let point1 = rng.gen_range(0..min_len / 2);
        let point2 = rng.gen_range(min_len / 2..min_len);
        
        result.extend(&a[..point1]);
        result.extend(&b[point1..point2]);
        result.extend(&a[point2..a.len().min(result.len() + (a.len() - point2))]);
        
        result
    }
    
    // Mutate font
    fn mutate(&self, font: &mut Vec<u8>) {
        let mut rng = rand::thread_rng();
        let mutation = &self.base_fuzzer.mutations[rng.gen_range(0..self.base_fuzzer.mutations.len())];
        
        // Create a temporary fuzzer to apply mutation
        let temp_fuzzer = FontFuzzer::new("");
        temp_fuzzer.apply_mutation(font, mutation);
    }
    
    pub fn run(&mut self, generations: u32, pop_size: usize) {
        use std::io::Write as IoWrite;
        
        println!("[*] 🧬 GENETIC FONT | pop {} | {} generations", pop_size, generations);
        
        self.init_population(pop_size);
        let mut rng = rand::thread_rng();
        
        for gen in 0..generations {
            self.generation = gen;
            
            // Evaluate fitness (fonts that load = more interesting)
            for (i, font) in self.population.iter().enumerate() {
                let result = self.base_fuzzer.trigger_font_parse_memory(font);
                self.fitness[i] = if result.is_ok() { 10.0 } else { 1.0 };
                self.fitness[i] += font.len() as f64 * 0.001; // Prefer variety
            }
            
            // Selection + reproduction
            let mut new_pop = Vec::new();
            while new_pop.len() < pop_size {
                // Tournament selection
                let a = rng.gen_range(0..pop_size);
                let b = rng.gen_range(0..pop_size);
                let parent1 = if self.fitness[a] > self.fitness[b] { a } else { b };
                
                let c = rng.gen_range(0..pop_size);
                let d = rng.gen_range(0..pop_size);
                let parent2 = if self.fitness[c] > self.fitness[d] { c } else { d };
                
                // Crossover
                let mut child = self.crossover(&self.population[parent1], &self.population[parent2]);
                
                // Mutate
                if rng.gen_bool(0.8) {
                    self.mutate(&mut child);
                }
                
                new_pop.push(child);
            }
            
            self.population = new_pop;
            
            // Progress
            let avg_fitness: f64 = self.fitness.iter().sum::<f64>() / self.fitness.len() as f64;
            print!("\r[*] Generation: {} | Avg Fitness: {:.2} | Pop Size: {}     ",
                   gen, avg_fitness, self.population.len());
            std::io::stdout().flush().ok();
        }
        
        println!("\n[+] Genetic evolution complete");
    }
}
