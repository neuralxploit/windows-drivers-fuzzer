//! Reinforcement Learning Fuzzer
//! 
//! Uses Q-learning to discover optimal fuzzing strategies.
//! The agent learns which IOCTLs, input sizes, and patterns
//! are most likely to produce interesting behavior (crashes, new errors).

use std::collections::HashMap;
use rand::prelude::*;
use std::fs::File;
use std::io::Write;

/// State representation for the RL agent
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FuzzState {
    /// Last IOCTL called
    pub last_ioctl: u32,
    /// Last result (bucketed)
    pub last_result: ResultBucket,
    /// Number of unique errors seen recently
    pub error_diversity: u8,
    /// Current "hot" IOCTL (one showing interesting behavior)
    pub hot_ioctl: Option<u32>,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum ResultBucket {
    Success,
    AccessDenied,
    InvalidParameter,
    BufferTooSmall,
    OtherError,
    Timeout,
    Crash,
}

impl ResultBucket {
    pub fn from_error_code(code: u32, success: bool) -> Self {
        if success {
            return ResultBucket::Success;
        }
        match code {
            0x80070005 => ResultBucket::AccessDenied,      // ACCESS_DENIED
            0x80070057 => ResultBucket::InvalidParameter,  // INVALID_PARAMETER
            0x8007007A => ResultBucket::BufferTooSmall,    // BUFFER_TOO_SMALL
            0x80070079 => ResultBucket::Timeout,           // TIMEOUT
            _ => ResultBucket::OtherError,
        }
    }
}

/// Actions the RL agent can take
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct FuzzAction {
    /// Which IOCTL index to call (maps to actual IOCTL code)
    pub ioctl_idx: usize,
    /// Input size bucket
    pub size_bucket: SizeBucket,
    /// Input pattern
    pub pattern: PatternType,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum SizeBucket {
    Empty,      // 0
    Tiny,       // 1-8
    Small,      // 9-64
    Medium,     // 65-256
    Large,      // 257-1024
    Huge,       // 1025-4096
    Massive,    // 4097+
}

impl SizeBucket {
    pub fn to_size(&self, rng: &mut StdRng) -> usize {
        match self {
            SizeBucket::Empty => 0,
            SizeBucket::Tiny => rng.gen_range(1..=8),
            SizeBucket::Small => rng.gen_range(9..=64),
            SizeBucket::Medium => rng.gen_range(65..=256),
            SizeBucket::Large => rng.gen_range(257..=1024),
            SizeBucket::Huge => rng.gen_range(1025..=4096),
            SizeBucket::Massive => rng.gen_range(4097..=8192),
        }
    }
    
    pub fn all() -> Vec<SizeBucket> {
        vec![
            SizeBucket::Empty, SizeBucket::Tiny, SizeBucket::Small,
            SizeBucket::Medium, SizeBucket::Large, SizeBucket::Huge,
            SizeBucket::Massive,
        ]
    }
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum PatternType {
    Zeros,
    Ones,
    Random,
    Sequential,
    SizePrefix,
    HandleLike,
    StructuredHeader,
    Overflow,        // 0x41414141...
    NullPointers,    // Embedded nulls
    MaxValues,       // 0xFFFFFFFF patterns
    // Format-aware patterns
    SdbHeader,       // Shim Database format (ahcache)
    SdbMalformed,    // SDB with corrupted fields
    SdbTagFuzz,      // Valid SDB header + fuzzed tags
    TpmCommand,      // TPM command structure
    PeAuthRequest,   // PEAUTH request structure
    // Ahcache query structures (NOT raw SDB)
    AhcacheQuery,    // Ahcache IOCTL query structure
    AhcacheLookup,   // Shim lookup request
    AhcacheNotify,   // Shim notification
    // Generic kernel structures
    UnicodeString,   // UNICODE_STRING structure
    ObjectAttrs,     // OBJECT_ATTRIBUTES structure
    IoStatusBlock,   // IO_STATUS_BLOCK
    // VirtualBox Guest Additions
    VBoxRequest,     // VBox HGCM request header
    VBoxHGCMCall,    // VBox HGCM function call
    VBoxGuestInfo,   // VBox guest info query
    VBoxMouse,       // VBox mouse integration
    VBoxVideo,       // VBox video mode change
}

impl PatternType {
    pub fn all() -> Vec<PatternType> {
        vec![
            PatternType::Zeros, PatternType::Ones, PatternType::Random,
            PatternType::Sequential, PatternType::SizePrefix, PatternType::HandleLike,
            PatternType::StructuredHeader, PatternType::Overflow, 
            PatternType::NullPointers, PatternType::MaxValues,
            PatternType::SdbHeader, PatternType::SdbMalformed, PatternType::SdbTagFuzz,
            PatternType::TpmCommand, PatternType::PeAuthRequest,
            PatternType::AhcacheQuery, PatternType::AhcacheLookup, PatternType::AhcacheNotify,
            PatternType::UnicodeString, PatternType::ObjectAttrs, PatternType::IoStatusBlock,
            PatternType::VBoxRequest, PatternType::VBoxHGCMCall, PatternType::VBoxGuestInfo,
            PatternType::VBoxMouse, PatternType::VBoxVideo,
        ]
    }
    
    pub fn generate(&self, size: usize, rng: &mut StdRng) -> Vec<u8> {
        let mut buf = vec![0u8; size];
        match self {
            PatternType::Zeros => {}, // already zeros
            PatternType::Ones => buf.fill(0xFF),
            PatternType::Random => rng.fill(&mut buf[..]),
            PatternType::Sequential => {
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = (i & 0xFF) as u8;
                }
            }
            PatternType::SizePrefix => {
                if size >= 4 {
                    buf[0..4].copy_from_slice(&(size as u32).to_le_bytes());
                }
                if size >= 8 {
                    rng.fill(&mut buf[4..]);
                }
            }
            PatternType::HandleLike => {
                // Fill with handle-like values
                for chunk in buf.chunks_mut(8) {
                    if chunk.len() >= 8 {
                        let handle: u64 = rng.gen_range(0x100..0x10000) * 4;
                        chunk.copy_from_slice(&handle.to_le_bytes());
                    }
                }
            }
            PatternType::StructuredHeader => {
                if size >= 24 {
                    // Common driver request header
                    buf[0..4].copy_from_slice(&(size as u32).to_le_bytes());     // size
                    buf[4..8].copy_from_slice(&0x00010001u32.to_le_bytes());     // version
                    buf[8..12].copy_from_slice(&rng.gen::<u32>().to_le_bytes()); // type
                    buf[12..16].copy_from_slice(&0u32.to_le_bytes());            // status
                    buf[16..24].copy_from_slice(&0u64.to_le_bytes());            // reserved
                }
            }
            PatternType::Overflow => buf.fill(0x41),
            PatternType::NullPointers => {
                // Mix of nulls and data
                for (i, chunk) in buf.chunks_mut(8).enumerate() {
                    if i % 2 == 0 {
                        chunk.fill(0);
                    } else {
                        rng.fill(chunk);
                    }
                }
            }
            PatternType::MaxValues => {
                // Fill with max int values
                for chunk in buf.chunks_mut(4) {
                    if chunk.len() >= 4 {
                        chunk.copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
                    }
                }
            }
            // ═══════════════════════════════════════════════════════════
            // FORMAT-AWARE PATTERNS (for hardened drivers)
            // ═══════════════════════════════════════════════════════════
            PatternType::SdbHeader => {
                // SDB (Shim Database) format for ahcache
                // Magic: "sdbf" (0x73, 0x64, 0x62, 0x66) little-endian = 0x66626473
                if size >= 12 {
                    // SDB file header
                    buf[0..4].copy_from_slice(&0x66626473u32.to_le_bytes()); // "sdbf" magic
                    buf[4..8].copy_from_slice(&0x00020001u32.to_le_bytes()); // Version 2.1
                    // Rest is tag-based data
                    if size >= 24 {
                        // Add a TAG_DATABASE entry
                        buf[8..10].copy_from_slice(&0x7001u16.to_le_bytes()); // TAG_DATABASE (LIST)
                        buf[10..14].copy_from_slice(&((size - 14) as u32).to_le_bytes()); // size
                        // Random payload
                        rng.fill(&mut buf[14..]);
                    }
                }
            }
            PatternType::SdbMalformed => {
                // Valid SDB header but corrupted internals
                if size >= 16 {
                    buf[0..4].copy_from_slice(&0x66626473u32.to_le_bytes()); // "sdbf" magic
                    // Corrupt version
                    buf[4..8].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
                    // Negative/huge sizes
                    buf[8..12].copy_from_slice(&0x80000000u32.to_le_bytes());
                    // Fill rest with exploit patterns
                    for chunk in buf[12..].chunks_mut(4) {
                        if chunk.len() >= 4 {
                            chunk.copy_from_slice(&0x41414141u32.to_le_bytes());
                        }
                    }
                }
            }
            PatternType::SdbTagFuzz => {
                // Valid header + fuzzed TAG entries
                if size >= 20 {
                    buf[0..4].copy_from_slice(&0x66626473u32.to_le_bytes()); // "sdbf" magic
                    buf[4..8].copy_from_slice(&0x00020001u32.to_le_bytes()); // Version
                    
                    // Generate random TAG entries
                    let mut offset = 8;
                    while offset + 6 < size {
                        // TAG format: 2 bytes type, 4 bytes size (for LIST/STRINGREF)
                        // TAG types: 0x1xxx = NULL, 0x3xxx = DWORD, 0x5xxx = QWORD, 
                        //            0x6xxx = STRINGREF, 0x7xxx = LIST, 0x8xxx = STRING, 0x9xxx = BINARY
                        let tag_type: u16 = match rng.gen_range(0..7) {
                            0 => 0x1000 | rng.gen_range(0..0x100) as u16, // NULL tags
                            1 => 0x3000 | rng.gen_range(0..0x100) as u16, // DWORD tags
                            2 => 0x5000 | rng.gen_range(0..0x100) as u16, // QWORD tags
                            3 => 0x6000 | rng.gen_range(0..0x100) as u16, // STRINGREF tags
                            4 => 0x7000 | rng.gen_range(0..0x100) as u16, // LIST tags
                            5 => 0x8000 | rng.gen_range(0..0x100) as u16, // STRING tags
                            _ => 0x9000 | rng.gen_range(0..0x100) as u16, // BINARY tags
                        };
                        buf[offset..offset+2].copy_from_slice(&tag_type.to_le_bytes());
                        
                        // Add size for variable-length tags
                        let tag_size: u32 = rng.gen_range(0..256);
                        buf[offset+2..offset+6].copy_from_slice(&tag_size.to_le_bytes());
                        
                        offset += 6 + (tag_size as usize).min(size - offset - 6);
                    }
                }
            }
            PatternType::TpmCommand => {
                // TPM 2.0 command structure
                if size >= 10 {
                    buf[0..2].copy_from_slice(&0x8001u16.to_be_bytes()); // TPM_ST_NO_SESSIONS
                    buf[2..6].copy_from_slice(&(size as u32).to_be_bytes()); // Command size
                    // Command code (various TPM commands)
                    let cmd: u32 = match rng.gen_range(0..5) {
                        0 => 0x0000014F, // TPM2_GetCapability
                        1 => 0x00000176, // TPM2_GetRandom
                        2 => 0x0000017A, // TPM2_Hash
                        3 => 0x0000015B, // TPM2_PCR_Read
                        _ => rng.gen(),  // Random command
                    };
                    buf[6..10].copy_from_slice(&cmd.to_be_bytes());
                    // Random payload
                    if size > 10 {
                        rng.fill(&mut buf[10..]);
                    }
                }
            }
            PatternType::PeAuthRequest => {
                // Protected Environment Auth request (DRM-related)
                if size >= 32 {
                    // Common PEAUTH structure
                    buf[0..4].copy_from_slice(&0x50454154u32.to_le_bytes()); // "PEAT" magic (guessed)
                    buf[4..8].copy_from_slice(&0x00000001u32.to_le_bytes()); // Version
                    buf[8..12].copy_from_slice(&(size as u32).to_le_bytes()); // Size
                    buf[12..16].copy_from_slice(&rng.gen::<u32>().to_le_bytes()); // Request type
                    // Flags
                    buf[16..20].copy_from_slice(&rng.gen::<u32>().to_le_bytes());
                    // Reserved
                    buf[20..28].copy_from_slice(&0u64.to_le_bytes());
                    // Payload offset
                    buf[28..32].copy_from_slice(&32u32.to_le_bytes());
                    // Random payload
                    if size > 32 {
                        rng.fill(&mut buf[32..]);
                    }
                }
            }
            // ═══════════════════════════════════════════════════════════
            // AHCACHE QUERY STRUCTURES (what the driver actually expects)
            // ═══════════════════════════════════════════════════════════
            PatternType::AhcacheQuery => {
                // Ahcache uses query structures, not raw SDB
                // Based on reverse engineering - typical query structure
                if size >= 48 {
                    // Query header
                    buf[0..4].copy_from_slice(&(size as u32).to_le_bytes()); // Total size
                    buf[4..8].copy_from_slice(&rng.gen_range(0u32..16).to_le_bytes()); // Query type
                    buf[8..16].copy_from_slice(&0u64.to_le_bytes()); // Reserved/handle
                    // Flags
                    buf[16..20].copy_from_slice(&rng.gen::<u32>().to_le_bytes());
                    // Path offset (points into buffer)
                    buf[20..24].copy_from_slice(&48u32.to_le_bytes());
                    // Path length  
                    let path_len = ((size - 48) / 2).min(260) as u32;
                    buf[24..28].copy_from_slice(&path_len.to_le_bytes());
                    // Database GUID (random)
                    rng.fill(&mut buf[28..44]);
                    // Checksum
                    buf[44..48].copy_from_slice(&rng.gen::<u32>().to_le_bytes());
                    // Unicode path data (fake path)
                    if size > 48 {
                        // Write a fake Unicode path like "C:\Windows\System32\test.exe"
                        let fake_paths = [
                            "C:\\Windows\\System32\\cmd.exe",
                            "C:\\Windows\\System32\\notepad.exe",
                            "C:\\Program Files\\test.exe",
                            "\\??\\C:\\test.exe",
                        ];
                        let path = fake_paths[rng.gen_range(0..fake_paths.len())];
                        for (i, c) in path.encode_utf16().enumerate() {
                            let offset = 48 + i * 2;
                            if offset + 2 <= size {
                                buf[offset..offset+2].copy_from_slice(&c.to_le_bytes());
                            }
                        }
                    }
                }
            }
            PatternType::AhcacheLookup => {
                // Shim database lookup request
                if size >= 64 {
                    // Request type
                    buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // LOOKUP
                    // Size
                    buf[4..8].copy_from_slice(&(size as u32).to_le_bytes());
                    // Process ID (current or random)
                    buf[8..12].copy_from_slice(&rng.gen_range(4u32..65536).to_le_bytes());
                    // Thread ID
                    buf[12..16].copy_from_slice(&rng.gen_range(4u32..65536).to_le_bytes());
                    // Flags
                    buf[16..20].copy_from_slice(&rng.gen::<u32>().to_le_bytes());
                    // EXE name offset
                    buf[20..24].copy_from_slice(&64u32.to_le_bytes());
                    // EXE name length (in chars)
                    buf[24..28].copy_from_slice(&32u32.to_le_bytes());
                    // SDB path offset (0 = use default)
                    buf[28..32].copy_from_slice(&0u32.to_le_bytes());
                    // More reserved/flags
                    rng.fill(&mut buf[32..64]);
                    // Unicode EXE name
                    if size > 64 {
                        let name = "notepad.exe";
                        for (i, c) in name.encode_utf16().enumerate() {
                            let offset = 64 + i * 2;
                            if offset + 2 <= size {
                                buf[offset..offset+2].copy_from_slice(&c.to_le_bytes());
                            }
                        }
                    }
                }
            }
            PatternType::AhcacheNotify => {
                // Shim cache notification (process start/stop)
                if size >= 32 {
                    // Notification type: 1=start, 2=stop, 3=update
                    buf[0..4].copy_from_slice(&rng.gen_range(1u32..4).to_le_bytes());
                    // Process ID
                    buf[4..8].copy_from_slice(&rng.gen_range(4u32..65536).to_le_bytes());
                    // Session ID
                    buf[8..12].copy_from_slice(&rng.gen_range(0u32..10).to_le_bytes());
                    // Flags
                    buf[12..16].copy_from_slice(&rng.gen::<u32>().to_le_bytes());
                    // Timestamp
                    buf[16..24].copy_from_slice(&rng.gen::<u64>().to_le_bytes());
                    // Result code
                    buf[24..28].copy_from_slice(&0u32.to_le_bytes());
                    // Reserved
                    buf[28..32].copy_from_slice(&0u32.to_le_bytes());
                }
            }
            // ═══════════════════════════════════════════════════════════
            // GENERIC KERNEL STRUCTURES (used by many drivers)
            // ═══════════════════════════════════════════════════════════
            PatternType::UnicodeString => {
                // UNICODE_STRING structure (very common in kernel)
                // struct { USHORT Length; USHORT MaxLength; PWSTR Buffer; }
                if size >= 16 {
                    let str_len = ((size - 16) / 2).min(260) as u16;
                    buf[0..2].copy_from_slice(&(str_len * 2).to_le_bytes()); // Length in bytes
                    buf[2..4].copy_from_slice(&(str_len * 2).to_le_bytes()); // MaxLength
                    // On 64-bit, pointer is at offset 8 (after padding)
                    // For embedded string, point to offset 16
                    buf[8..16].copy_from_slice(&16u64.to_le_bytes()); // Buffer pointer (relative)
                    // Write Unicode string data
                    if size > 16 {
                        let paths = [
                            "\\Device\\Afd",
                            "\\??\\C:\\",
                            "\\Registry\\Machine",
                            "\\BaseNamedObjects\\",
                        ];
                        let path = paths[rng.gen_range(0..paths.len())];
                        for (i, c) in path.encode_utf16().enumerate() {
                            let offset = 16 + i * 2;
                            if offset + 2 <= size {
                                buf[offset..offset+2].copy_from_slice(&c.to_le_bytes());
                            }
                        }
                    }
                }
            }
            PatternType::ObjectAttrs => {
                // OBJECT_ATTRIBUTES structure
                if size >= 48 {
                    buf[0..4].copy_from_slice(&48u32.to_le_bytes()); // Length (sizeof struct)
                    buf[4..8].copy_from_slice(&0u32.to_le_bytes()); // Padding
                    buf[8..16].copy_from_slice(&0u64.to_le_bytes()); // RootDirectory (NULL)
                    buf[16..24].copy_from_slice(&0u64.to_le_bytes()); // ObjectName (NULL or ptr)
                    // Attributes: OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE
                    buf[24..28].copy_from_slice(&0x240u32.to_le_bytes());
                    buf[28..32].copy_from_slice(&0u32.to_le_bytes()); // Padding
                    buf[32..40].copy_from_slice(&0u64.to_le_bytes()); // SecurityDescriptor
                    buf[40..48].copy_from_slice(&0u64.to_le_bytes()); // SecurityQualityOfService
                }
            }
            PatternType::IoStatusBlock => {
                // IO_STATUS_BLOCK (used for async I/O)
                if size >= 16 {
                    buf[0..8].copy_from_slice(&0u64.to_le_bytes()); // Status/Pointer union
                    buf[8..16].copy_from_slice(&0u64.to_le_bytes()); // Information
                }
                // Fill rest with interesting values
                if size > 16 {
                    rng.fill(&mut buf[16..]);
                }
            }
            // ═══════════════════════════════════════════════════════════
            // VIRTUALBOX GUEST ADDITIONS PATTERNS
            // ═══════════════════════════════════════════════════════════
            PatternType::VBoxRequest => {
                // VBox generic request header (VBGLREQHDR)
                // All VBox IOCTLs start with this header
                if size >= 24 {
                    buf[0..4].copy_from_slice(&(size as u32).to_le_bytes()); // cbIn (input size)
                    buf[4..8].copy_from_slice(&0x10000u32.to_le_bytes()); // uVersion (VBGL_IOCTL_HDR_VERSION)
                    buf[8..12].copy_from_slice(&rng.gen_range(1u32..100).to_le_bytes()); // uType (request type)
                    buf[12..16].copy_from_slice(&0i32.to_le_bytes()); // rc (return code, 0 = success)
                    buf[16..20].copy_from_slice(&(size as u32).to_le_bytes()); // cbOut (output size)
                    buf[20..24].copy_from_slice(&0u32.to_le_bytes()); // Reserved
                    // Payload
                    if size > 24 {
                        rng.fill(&mut buf[24..]);
                    }
                }
            }
            PatternType::VBoxHGCMCall => {
                // VBox HGCM (Host-Guest Communication Manager) call
                // This is the most complex and interesting interface
                if size >= 64 {
                    // VBGLREQHDR
                    buf[0..4].copy_from_slice(&(size as u32).to_le_bytes()); // cbIn
                    buf[4..8].copy_from_slice(&0x10000u32.to_le_bytes()); // uVersion
                    buf[8..12].copy_from_slice(&2u32.to_le_bytes()); // uType = HGCM_CALL
                    buf[12..16].copy_from_slice(&0i32.to_le_bytes()); // rc
                    buf[16..20].copy_from_slice(&(size as u32).to_le_bytes()); // cbOut
                    buf[20..24].copy_from_slice(&0u32.to_le_bytes()); // Reserved
                    
                    // HGCM Call specific fields
                    buf[24..28].copy_from_slice(&rng.gen_range(1u32..50).to_le_bytes()); // u32ClientID
                    buf[28..32].copy_from_slice(&rng.gen_range(1u32..20).to_le_bytes()); // u32Function
                    buf[32..36].copy_from_slice(&rng.gen_range(0u32..8).to_le_bytes()); // cParms (param count)
                    buf[36..40].copy_from_slice(&0u32.to_le_bytes()); // Reserved/padding
                    
                    // HGCM parameters (simplified - each param is 16 bytes)
                    let mut offset = 40;
                    while offset + 16 <= size {
                        // Parameter type
                        let parm_type: u32 = match rng.gen_range(0..5) {
                            0 => 1,  // VBOX_HGCM_SVC_PARM_32BIT
                            1 => 2,  // VBOX_HGCM_SVC_PARM_64BIT
                            2 => 3,  // VBOX_HGCM_SVC_PARM_PTR
                            3 => 4,  // VBOX_HGCM_SVC_PARM_PAGES
                            _ => 0,  // Invalid
                        };
                        buf[offset..offset+4].copy_from_slice(&parm_type.to_le_bytes());
                        // Parameter value
                        rng.fill(&mut buf[offset+4..offset+16]);
                        offset += 16;
                    }
                }
            }
            PatternType::VBoxGuestInfo => {
                // VBox guest info request (VBGL_IOCTL_DRIVER_VERSION_INFO)
                if size >= 48 {
                    // Header
                    buf[0..4].copy_from_slice(&(size as u32).to_le_bytes());
                    buf[4..8].copy_from_slice(&0x10000u32.to_le_bytes());
                    buf[8..12].copy_from_slice(&3u32.to_le_bytes()); // Info request type
                    buf[12..16].copy_from_slice(&0i32.to_le_bytes());
                    buf[16..20].copy_from_slice(&(size as u32).to_le_bytes());
                    buf[20..24].copy_from_slice(&0u32.to_le_bytes());
                    
                    // Driver version info
                    buf[24..28].copy_from_slice(&0x00060001u32.to_le_bytes()); // Version 6.1
                    buf[28..32].copy_from_slice(&rng.gen::<u32>().to_le_bytes()); // Build
                    buf[32..36].copy_from_slice(&rng.gen::<u32>().to_le_bytes()); // Revision
                    buf[36..40].copy_from_slice(&0u32.to_le_bytes()); // Reserved
                    // Session ID / flags
                    rng.fill(&mut buf[40..48]);
                }
            }
            PatternType::VBoxMouse => {
                // VBox mouse integration IOCTL
                if size >= 32 {
                    // Header
                    buf[0..4].copy_from_slice(&(size as u32).to_le_bytes());
                    buf[4..8].copy_from_slice(&0x10000u32.to_le_bytes());
                    buf[8..12].copy_from_slice(&4u32.to_le_bytes()); // Mouse request
                    buf[12..16].copy_from_slice(&0i32.to_le_bytes());
                    buf[16..20].copy_from_slice(&(size as u32).to_le_bytes());
                    buf[20..24].copy_from_slice(&0u32.to_le_bytes());
                    
                    // Mouse data
                    buf[24..28].copy_from_slice(&rng.gen::<u32>().to_le_bytes()); // Features
                    buf[28..32].copy_from_slice(&rng.gen::<u32>().to_le_bytes()); // pointerXPos
                    if size >= 40 {
                        buf[32..36].copy_from_slice(&rng.gen::<u32>().to_le_bytes()); // pointerYPos
                        buf[36..40].copy_from_slice(&rng.gen::<u32>().to_le_bytes()); // Flags
                    }
                }
            }
            PatternType::VBoxVideo => {
                // VBox video mode change request
                if size >= 48 {
                    // Header
                    buf[0..4].copy_from_slice(&(size as u32).to_le_bytes());
                    buf[4..8].copy_from_slice(&0x10000u32.to_le_bytes());
                    buf[8..12].copy_from_slice(&5u32.to_le_bytes()); // Video request
                    buf[12..16].copy_from_slice(&0i32.to_le_bytes());
                    buf[16..20].copy_from_slice(&(size as u32).to_le_bytes());
                    buf[20..24].copy_from_slice(&0u32.to_le_bytes());
                    
                    // Video mode data
                    buf[24..28].copy_from_slice(&rng.gen_range(640u32..4096).to_le_bytes()); // Width
                    buf[28..32].copy_from_slice(&rng.gen_range(480u32..2160).to_le_bytes()); // Height
                    buf[32..36].copy_from_slice(&rng.gen_range(8u32..32).to_le_bytes()); // BPP
                    buf[36..40].copy_from_slice(&rng.gen_range(0u32..4).to_le_bytes()); // Display
                    buf[40..44].copy_from_slice(&rng.gen::<u32>().to_le_bytes()); // Flags
                    buf[44..48].copy_from_slice(&rng.gen::<u32>().to_le_bytes()); // Origin X
                }
            }
        }
        buf
    }
}

/// Reward signal for RL
#[derive(Debug, Clone, Copy)]
pub struct Reward {
    pub value: f64,
    pub reason: RewardReason,
}

#[derive(Debug, Clone, Copy)]
pub enum RewardReason {
    Crash,              // +1000
    NewErrorCode,       // +50
    NewBehavior,        // +20
    Success,            // +10
    DifferentOutput,    // +5
    Explored,           // +1
    Repetitive,         // -1
    Boring,             // -5
}

impl Reward {
    pub fn crash() -> Self { Reward { value: 1000.0, reason: RewardReason::Crash } }
    pub fn new_error() -> Self { Reward { value: 50.0, reason: RewardReason::NewErrorCode } }
    pub fn new_behavior() -> Self { Reward { value: 20.0, reason: RewardReason::NewBehavior } }
    pub fn success() -> Self { Reward { value: 10.0, reason: RewardReason::Success } }
    pub fn different_output() -> Self { Reward { value: 5.0, reason: RewardReason::DifferentOutput } }
    pub fn explored() -> Self { Reward { value: 1.0, reason: RewardReason::Explored } }
    pub fn repetitive() -> Self { Reward { value: -1.0, reason: RewardReason::Repetitive } }
    pub fn boring() -> Self { Reward { value: -5.0, reason: RewardReason::Boring } }
}

/// Q-Learning based fuzzer
pub struct RLFuzzer {
    /// Q-table: State -> Action -> Value
    q_table: HashMap<(FuzzState, FuzzAction), f64>,
    /// IOCTLs to fuzz
    ioctls: Vec<u32>,
    /// Learning rate (alpha)
    alpha: f64,
    /// Discount factor (gamma)
    gamma: f64,
    /// Exploration rate (epsilon)
    epsilon: f64,
    /// Epsilon decay
    epsilon_decay: f64,
    /// Minimum epsilon
    epsilon_min: f64,
    /// Current state
    current_state: FuzzState,
    /// Seen error codes per IOCTL
    seen_errors: HashMap<u32, Vec<u32>>,
    /// Seen output hashes per IOCTL
    seen_outputs: HashMap<u32, Vec<u64>>,
    /// Total reward accumulated
    total_reward: f64,
    /// Episode count
    episode: u64,
    /// RNG
    rng: StdRng,
    /// Statistics
    stats: RLStats,
}

#[derive(Debug, Default)]
pub struct RLStats {
    pub total_actions: u64,
    pub explorations: u64,
    pub exploitations: u64,
    pub crashes: u64,
    pub new_errors: u64,
    pub successes: u64,
    pub best_reward: f64,
    pub avg_reward: f64,
}

impl RLFuzzer {
    pub fn new(ioctls: Vec<u32>) -> Self {
        Self {
            q_table: HashMap::new(),
            ioctls,
            alpha: 0.1,       // Learning rate
            gamma: 0.95,      // Discount factor (future rewards matter)
            epsilon: 1.0,     // Start with full exploration
            epsilon_decay: 0.9995,
            epsilon_min: 0.05,
            current_state: FuzzState {
                last_ioctl: 0,
                last_result: ResultBucket::OtherError,
                error_diversity: 0,
                hot_ioctl: None,
            },
            seen_errors: HashMap::new(),
            seen_outputs: HashMap::new(),
            total_reward: 0.0,
            episode: 0,
            rng: StdRng::from_entropy(),
            stats: RLStats::default(),
        }
    }
    
    /// Choose an action using epsilon-greedy policy
    pub fn choose_action(&mut self) -> FuzzAction {
        self.stats.total_actions += 1;
        
        // Epsilon-greedy: explore or exploit?
        if self.rng.gen::<f64>() < self.epsilon {
            // EXPLORE: Random action
            self.stats.explorations += 1;
            self.random_action()
        } else {
            // EXPLOIT: Best known action
            self.stats.exploitations += 1;
            self.best_action()
        }
    }
    
    /// Generate a random action
    fn random_action(&mut self) -> FuzzAction {
        let ioctl_idx = if self.ioctls.is_empty() { 0 } else { self.rng.gen_range(0..self.ioctls.len()) };
        let size_bucket = *SizeBucket::all().choose(&mut self.rng).unwrap();
        let pattern = *PatternType::all().choose(&mut self.rng).unwrap();
        
        FuzzAction { ioctl_idx, size_bucket, pattern }
    }
    
    /// Find the best action for current state based on Q-values
    fn best_action(&mut self) -> FuzzAction {
        let mut best_action = self.random_action();
        let mut best_value = f64::NEG_INFINITY;
        
        // Check all possible actions (limited search for efficiency)
        for ioctl_idx in 0..self.ioctls.len().min(20) {
            for size_bucket in SizeBucket::all() {
                for pattern in PatternType::all() {
                    let action = FuzzAction { ioctl_idx, size_bucket, pattern };
                    let value = self.get_q_value(&self.current_state, &action);
                    
                    if value > best_value {
                        best_value = value;
                        best_action = action;
                    }
                }
            }
        }
        
        // If we have a "hot" IOCTL, bias towards it
        if let Some(hot) = self.current_state.hot_ioctl {
            if let Some(idx) = self.ioctls.iter().position(|&x| x == hot) {
                if self.rng.gen_bool(0.3) {
                    best_action.ioctl_idx = idx;
                }
            }
        }
        
        best_action
    }
    
    /// Get Q-value for state-action pair
    fn get_q_value(&self, state: &FuzzState, action: &FuzzAction) -> f64 {
        *self.q_table.get(&(state.clone(), *action)).unwrap_or(&0.0)
    }
    
    /// Get the actual IOCTL code and input buffer for an action
    pub fn action_to_input(&mut self, action: &FuzzAction) -> (u32, Vec<u8>) {
        // Safety: protect against divide-by-zero if ioctls is empty
        let ioctl = if self.ioctls.is_empty() {
            0x220000 // Fallback IOCTL
        } else {
            self.ioctls[action.ioctl_idx % self.ioctls.len()]
        };
        let size = action.size_bucket.to_size(&mut self.rng);
        let input = action.pattern.generate(size, &mut self.rng);
        (ioctl, input)
    }
    
    /// Process the result and update Q-table
    pub fn process_result(
        &mut self,
        action: FuzzAction,
        ioctl: u32,
        error_code: u32,
        success: bool,
        output: &[u8],
        bytes_returned: u32,
        crashed: bool,
    ) -> Reward {
        // Calculate reward
        let reward = self.calculate_reward(ioctl, error_code, success, output, bytes_returned, crashed);
        
        // Update statistics
        self.total_reward += reward.value;
        match reward.reason {
            RewardReason::Crash => self.stats.crashes += 1,
            RewardReason::NewErrorCode => self.stats.new_errors += 1,
            RewardReason::Success => self.stats.successes += 1,
            _ => {}
        }
        
        if reward.value > self.stats.best_reward {
            self.stats.best_reward = reward.value;
        }
        
        // Create new state
        let new_state = FuzzState {
            last_ioctl: ioctl,
            last_result: ResultBucket::from_error_code(error_code, success),
            error_diversity: self.seen_errors.get(&ioctl).map(|v| v.len() as u8).unwrap_or(0),
            hot_ioctl: if reward.value > 10.0 { Some(ioctl) } else { self.current_state.hot_ioctl },
        };
        
        // Q-Learning update: Q(s,a) = Q(s,a) + α * (r + γ * max(Q(s',a')) - Q(s,a))
        let current_q = self.get_q_value(&self.current_state, &action);
        let max_next_q = self.max_q_value(&new_state);
        let new_q = current_q + self.alpha * (reward.value + self.gamma * max_next_q - current_q);
        
        self.q_table.insert((self.current_state.clone(), action), new_q);
        
        // Update state
        self.current_state = new_state;
        
        // Decay epsilon (explore less over time)
        self.epsilon = (self.epsilon * self.epsilon_decay).max(self.epsilon_min);
        
        self.episode += 1;
        
        reward
    }
    
    /// Calculate reward for an action result
    fn calculate_reward(
        &mut self,
        ioctl: u32,
        error_code: u32,
        success: bool,
        output: &[u8],
        bytes_returned: u32,
        crashed: bool,
    ) -> Reward {
        // Crash is the best outcome!
        if crashed {
            return Reward::crash();
        }
        
        // Hash output first (before borrowing seen_errors)
        let output_hash = self.hash_output(output, bytes_returned);
        
        // Check for new error code
        let is_new_error = {
            let errors = self.seen_errors.entry(ioctl).or_insert_with(Vec::new);
            let is_new = !errors.contains(&error_code);
            if is_new {
                errors.push(error_code);
            }
            is_new
        };
        
        // Check for new output
        let (is_new_output, error_count, output_count) = {
            let outputs = self.seen_outputs.entry(ioctl).or_insert_with(Vec::new);
            let is_new = !outputs.contains(&output_hash);
            if is_new && bytes_returned > 0 {
                outputs.push(output_hash);
            }
            let err_count = self.seen_errors.get(&ioctl).map(|v| v.len()).unwrap_or(0);
            (is_new, err_count, outputs.len())
        };
        
        // Determine reward
        if is_new_error {
            return Reward::new_error();
        }
        
        if success {
            if is_new_output {
                return Reward::new_behavior();
            }
            return Reward::success();
        }
        
        if is_new_output {
            return Reward::different_output();
        }
        
        // Seen this exact result before
        if error_count <= 1 && output_count <= 1 {
            return Reward::boring();
        }
        
        Reward::explored()
    }
    
    /// Hash output for comparison
    fn hash_output(&self, output: &[u8], bytes_returned: u32) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        
        let mut hasher = DefaultHasher::new();
        bytes_returned.hash(&mut hasher);
        let safe_len = std::cmp::min(bytes_returned as usize, output.len());
        output[..safe_len].hash(&mut hasher);
        hasher.finish()
    }
    
    /// Get maximum Q-value for a state (over all actions)
    fn max_q_value(&self, state: &FuzzState) -> f64 {
        let mut max_q = 0.0;
        
        for ioctl_idx in 0..self.ioctls.len().min(10) {
            for size_bucket in SizeBucket::all() {
                for pattern in PatternType::all() {
                    let action = FuzzAction { ioctl_idx, size_bucket, pattern };
                    let q = self.get_q_value(state, &action);
                    if q > max_q {
                        max_q = q;
                    }
                }
            }
        }
        
        max_q
    }
    
    /// Get current epsilon (exploration rate)
    pub fn get_epsilon(&self) -> f64 {
        self.epsilon
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> &RLStats {
        &self.stats
    }
    
    /// Get total reward
    pub fn get_total_reward(&self) -> f64 {
        self.total_reward
    }
    
    /// Get episode count
    pub fn get_episode(&self) -> u64 {
        self.episode
    }
    
    /// Get Q-table size
    pub fn get_q_table_size(&self) -> usize {
        self.q_table.len()
    }
    
    /// Get top actions by Q-value
    pub fn get_top_actions(&self, n: usize) -> Vec<(FuzzAction, f64)> {
        let mut actions: Vec<_> = self.q_table.iter()
            .map(|((_, action), &value)| (*action, value))
            .collect();
        actions.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        actions.into_iter().take(n).collect()
    }
    
    /// Save Q-table to file
    pub fn save(&self, path: &str) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        
        writeln!(file, "# RL Fuzzer Q-Table")?;
        writeln!(file, "# Episode: {}", self.episode)?;
        writeln!(file, "# Epsilon: {}", self.epsilon)?;
        writeln!(file, "# Total Reward: {}", self.total_reward)?;
        writeln!(file, "# Q-Table entries: {}", self.q_table.len())?;
        
        for ((state, action), value) in &self.q_table {
            writeln!(file, "Q|{:?}|{:?}|{}", state.last_ioctl, action.ioctl_idx, value)?;
        }
        
        Ok(())
    }
    
    /// Print learned knowledge
    pub fn print_knowledge(&self) {
        println!("\n╔══════════════════════════════════════════════════════════════╗");
        println!("║              RL FUZZER LEARNED KNOWLEDGE                     ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        
        println!("\n[*] Training Statistics:");
        println!("    Episodes:        {}", self.episode);
        println!("    Q-Table Size:    {} entries", self.q_table.len());
        println!("    Epsilon:         {:.4} (exploration rate)", self.epsilon);
        println!("    Total Reward:    {:.2}", self.total_reward);
        println!("    Avg Reward:      {:.4}", self.total_reward / self.episode.max(1) as f64);
        
        println!("\n[*] Action Statistics:");
        println!("    Explorations:    {} ({:.1}%)", 
                 self.stats.explorations,
                 100.0 * self.stats.explorations as f64 / self.stats.total_actions.max(1) as f64);
        println!("    Exploitations:   {} ({:.1}%)",
                 self.stats.exploitations,
                 100.0 * self.stats.exploitations as f64 / self.stats.total_actions.max(1) as f64);
        
        println!("\n[*] Discovery Statistics:");
        println!("    Crashes:         {} 💥", self.stats.crashes);
        println!("    New Errors:      {}", self.stats.new_errors);
        println!("    Successes:       {}", self.stats.successes);
        
        println!("\n[*] Top Learned Actions (by Q-value):");
        let top = self.get_top_actions(10);
        for (i, (action, value)) in top.iter().enumerate() {
            let ioctl = self.ioctls.get(action.ioctl_idx).unwrap_or(&0);
            println!("    {}. IOCTL 0x{:08X} | {:?} | {:?} | Q={:.2}",
                     i + 1, ioctl, action.size_bucket, action.pattern, value);
        }
        
        println!("\n[*] IOCTLs with Most Error Diversity:");
        let mut error_counts: Vec<_> = self.seen_errors.iter()
            .map(|(k, v)| (*k, v.len()))
            .collect();
        error_counts.sort_by(|a, b| b.1.cmp(&a.1));
        for (ioctl, count) in error_counts.iter().take(10) {
            if *count > 1 {
                println!("    0x{:08X}: {} different error codes (interesting!)", ioctl, count);
            }
        }
    }
    
    /// Save the RL model to a file
    pub fn save_model(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        
        let mut file = File::create(path)?;
        
        // Header
        writeln!(file, "# RL Fuzzer Model - Q-Table")?;
        writeln!(file, "# Episodes: {}", self.episode)?;
        writeln!(file, "# Epsilon: {}", self.epsilon)?;
        writeln!(file, "# Total Reward: {}", self.total_reward)?;
        writeln!(file, "# Q-Table Entries: {}", self.q_table.len())?;
        writeln!(file, "# IOCTLs: {:?}", self.ioctls)?;
        writeln!(file, "---")?;
        
        // Save Q-table
        for ((state, action), value) in &self.q_table {
            // Serialize state
            let state_str = format!("{:08X}_{:?}_{}_{}",
                state.last_ioctl,
                state.last_result,
                state.error_diversity,
                state.hot_ioctl.map(|x| format!("{:08X}", x)).unwrap_or_default()
            );
            
            // Serialize action
            let action_str = format!("{}_{:?}_{:?}",
                action.ioctl_idx,
                action.size_bucket,
                action.pattern
            );
            
            writeln!(file, "Q|{}|{}|{}", state_str, action_str, value)?;
        }
        
        writeln!(file, "---")?;
        
        // Save metadata
        writeln!(file, "META|epsilon|{}", self.epsilon)?;
        writeln!(file, "META|episode|{}", self.episode)?;
        writeln!(file, "META|total_reward|{}", self.total_reward)?;
        writeln!(file, "META|alpha|{}", self.alpha)?;
        writeln!(file, "META|gamma|{}", self.gamma)?;
        
        // Save seen errors
        for (ioctl, errors) in &self.seen_errors {
            let errors_str: String = errors.iter()
                .map(|e| format!("{:08X}", e))
                .collect::<Vec<_>>()
                .join(",");
            writeln!(file, "ERRORS|{:08X}|{}", ioctl, errors_str)?;
        }
        
        // Save seen outputs (output hash history)
        for (ioctl, outputs) in &self.seen_outputs {
            let outputs_str: String = outputs.iter()
                .map(|o| format!("{:016X}", o))
                .collect::<Vec<_>>()
                .join(",");
            writeln!(file, "OUTPUTS|{:08X}|{}", ioctl, outputs_str)?;
        }
        
        // Save stats
        writeln!(file, "STATS|total_actions|{}", self.stats.total_actions)?;
        writeln!(file, "STATS|explorations|{}", self.stats.explorations)?;
        writeln!(file, "STATS|exploitations|{}", self.stats.exploitations)?;
        writeln!(file, "STATS|crashes|{}", self.stats.crashes)?;
        writeln!(file, "STATS|new_errors|{}", self.stats.new_errors)?;
        writeln!(file, "STATS|successes|{}", self.stats.successes)?;
        writeln!(file, "STATS|best_reward|{}", self.stats.best_reward)?;
        
        Ok(())
    }
    
    /// Load the RL model from a file
    pub fn load_model(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::{BufRead, BufReader};
        
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            let line = line?;
            if line.starts_with('#') || line.starts_with("---") || line.is_empty() {
                continue;
            }
            
            let parts: Vec<&str> = line.split('|').collect();
            
            match parts.get(0) {
                Some(&"META") if parts.len() >= 3 => {
                    match parts[1] {
                        "epsilon" => self.epsilon = parts[2].parse().unwrap_or(self.epsilon),
                        "episode" => self.episode = parts[2].parse().unwrap_or(self.episode),
                        "total_reward" => self.total_reward = parts[2].parse().unwrap_or(self.total_reward),
                        "alpha" => self.alpha = parts[2].parse().unwrap_or(self.alpha),
                        "gamma" => self.gamma = parts[2].parse().unwrap_or(self.gamma),
                        _ => {}
                    }
                }
                Some(&"STATS") if parts.len() >= 3 => {
                    match parts[1] {
                        "total_actions" => self.stats.total_actions = parts[2].parse().unwrap_or(0),
                        "explorations" => self.stats.explorations = parts[2].parse().unwrap_or(0),
                        "exploitations" => self.stats.exploitations = parts[2].parse().unwrap_or(0),
                        "crashes" => self.stats.crashes = parts[2].parse().unwrap_or(0),
                        "new_errors" => self.stats.new_errors = parts[2].parse().unwrap_or(0),
                        "successes" => self.stats.successes = parts[2].parse().unwrap_or(0),
                        "best_reward" => self.stats.best_reward = parts[2].parse().unwrap_or(0.0),
                        _ => {}
                    }
                }
                Some(&"ERRORS") if parts.len() >= 3 => {
                    if let Ok(ioctl) = u32::from_str_radix(parts[1], 16) {
                        let errors: Vec<u32> = parts[2].split(',')
                            .filter(|s| !s.is_empty())
                            .filter_map(|s| u32::from_str_radix(s, 16).ok())
                            .collect();
                        self.seen_errors.insert(ioctl, errors);
                    }
                }
                Some(&"OUTPUTS") if parts.len() >= 3 => {
                    if let Ok(ioctl) = u32::from_str_radix(parts[1], 16) {
                        let outputs: Vec<u64> = parts[2].split(',')
                            .filter(|s| !s.is_empty())
                            .filter_map(|s| u64::from_str_radix(s, 16).ok())
                            .collect();
                        self.seen_outputs.insert(ioctl, outputs);
                    }
                }
                Some(&"Q") if parts.len() >= 4 => {
                    // Parse Q-table entry: Q|state_str|action_str|value
                    // State format: last_ioctl_result_diversity_hot
                    // Action format: ioctl_idx_size_pattern
                    if let Ok(value) = parts[3].parse::<f64>() {
                        if let (Some(state), Some(action)) = (
                            Self::parse_state(parts[1]),
                            Self::parse_action(parts[2])
                        ) {
                            self.q_table.insert((state, action), value);
                        }
                    }
                }
                _ => {}
            }
        }
        
        println!("[+] Loaded RL model: {} episodes, epsilon={:.4}, {} Q-entries, {} error sets, {} output sets",
            self.episode, self.epsilon, self.q_table.len(), 
            self.seen_errors.len(), self.seen_outputs.len());
        
        Ok(())
    }
    
    /// Parse state string from saved model
    /// Format: "last_ioctl_result_diversity_hot"
    fn parse_state(s: &str) -> Option<FuzzState> {
        let parts: Vec<&str> = s.split('_').collect();
        if parts.len() < 3 {
            return None;
        }
        
        let last_ioctl = u32::from_str_radix(parts[0], 16).ok()?;
        let last_result = Self::parse_result_bucket(parts[1])?;
        let error_diversity = parts[2].parse().ok()?;
        let hot_ioctl = if parts.len() > 3 && !parts[3].is_empty() {
            u32::from_str_radix(parts[3], 16).ok()
        } else {
            None
        };
        
        Some(FuzzState {
            last_ioctl,
            last_result,
            error_diversity,
            hot_ioctl,
        })
    }
    
    /// Parse action string from saved model
    /// Format: "ioctl_idx_size_pattern"
    fn parse_action(s: &str) -> Option<FuzzAction> {
        let parts: Vec<&str> = s.split('_').collect();
        if parts.len() < 3 {
            return None;
        }
        
        let ioctl_idx = parts[0].parse().ok()?;
        let size_bucket = Self::parse_size_bucket(parts[1])?;
        let pattern = Self::parse_pattern_type(parts[2])?;
        
        Some(FuzzAction {
            ioctl_idx,
            size_bucket,
            pattern,
        })
    }
    
    /// Parse ResultBucket from debug string
    fn parse_result_bucket(s: &str) -> Option<ResultBucket> {
        // Handle both "Success" and "Error(5)" formats
        if s.starts_with("Error(") || s.starts_with("OtherError") {
            return Some(ResultBucket::OtherError);
        }
        match s {
            "Success" => Some(ResultBucket::Success),
            "AccessDenied" => Some(ResultBucket::AccessDenied),
            "InvalidParameter" => Some(ResultBucket::InvalidParameter),
            "BufferTooSmall" => Some(ResultBucket::BufferTooSmall),
            "Timeout" => Some(ResultBucket::Timeout),
            "Crash" => Some(ResultBucket::Crash),
            _ => Some(ResultBucket::OtherError),
        }
    }
    
    /// Parse SizeBucket from debug string
    fn parse_size_bucket(s: &str) -> Option<SizeBucket> {
        match s {
            "Empty" => Some(SizeBucket::Empty),
            "Tiny" => Some(SizeBucket::Tiny),
            "Small" => Some(SizeBucket::Small),
            "Medium" => Some(SizeBucket::Medium),
            "Large" => Some(SizeBucket::Large),
            "Huge" => Some(SizeBucket::Huge),
            "Massive" => Some(SizeBucket::Massive),
            _ => None,
        }
    }
    
    /// Parse PatternType from debug string
    fn parse_pattern_type(s: &str) -> Option<PatternType> {
        match s {
            "Zeros" => Some(PatternType::Zeros),
            "Ones" => Some(PatternType::Ones),
            "Random" => Some(PatternType::Random),
            "Sequential" => Some(PatternType::Sequential),
            "SizePrefix" => Some(PatternType::SizePrefix),
            "HandleLike" => Some(PatternType::HandleLike),
            "StructuredHeader" => Some(PatternType::StructuredHeader),
            "Overflow" => Some(PatternType::Overflow),
            "NullPointers" => Some(PatternType::NullPointers),
            "MaxValues" => Some(PatternType::MaxValues),
            "SdbHeader" => Some(PatternType::SdbHeader),
            "SdbMalformed" => Some(PatternType::SdbMalformed),
            "SdbTagFuzz" => Some(PatternType::SdbTagFuzz),
            "TpmCommand" => Some(PatternType::TpmCommand),
            "PeAuthRequest" => Some(PatternType::PeAuthRequest),
            "AhcacheQuery" => Some(PatternType::AhcacheQuery),
            "AhcacheLookup" => Some(PatternType::AhcacheLookup),
            "AhcacheNotify" => Some(PatternType::AhcacheNotify),
            "UnicodeString" => Some(PatternType::UnicodeString),
            "ObjectAttrs" => Some(PatternType::ObjectAttrs),
            "IoStatusBlock" => Some(PatternType::IoStatusBlock),
            "VBoxRequest" => Some(PatternType::VBoxRequest),
            "VBoxHGCMCall" => Some(PatternType::VBoxHGCMCall),
            "VBoxGuestInfo" => Some(PatternType::VBoxGuestInfo),
            "VBoxMouse" => Some(PatternType::VBoxMouse),
            "VBoxVideo" => Some(PatternType::VBoxVideo),
            _ => None,
        }
    }
    
    /// Get current statistics as a summary string
    pub fn get_stats_summary(&self) -> String {
        format!(
            "ε={:.3} ep={} expl={}/{} crashes={} new_err={}",
            self.epsilon,
            self.episode,
            self.stats.explorations,
            self.stats.exploitations,
            self.stats.crashes,
            self.stats.new_errors
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rl_fuzzer_basic() {
        let ioctls = vec![0x222000, 0x222004, 0x222008];
        let mut fuzzer = RLFuzzer::new(ioctls);
        
        // Should start with high exploration
        assert!(fuzzer.get_epsilon() > 0.9);
        
        // Run a few episodes
        for _ in 0..100 {
            let action = fuzzer.choose_action();
            let (ioctl, _input) = fuzzer.action_to_input(&action);
            
            // Simulate result
            fuzzer.process_result(action, ioctl, 0x80070057, false, &[], 0, false);
        }
        
        // Epsilon should have decayed
        assert!(fuzzer.get_epsilon() < 1.0);
        assert!(fuzzer.get_episode() == 100);
    }
}
