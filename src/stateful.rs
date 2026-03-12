//! Stateful Fuzzing Module
//!
//! Detects Use-After-Free, Double-Free, and race conditions
//! by tracking sequences of IOCTL calls and their relationships.

#![allow(dead_code)]

use std::collections::HashMap;
use rand::prelude::*;

/// Types of operations for stateful fuzzing
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OpType {
    Allocate,   // Creates/opens a resource
    Use,        // Uses a resource
    Free,       // Frees/closes a resource
    Unknown,
}

/// Tracked resource from IOCTL calls
#[derive(Debug, Clone)]
pub struct Resource {
    pub handle: u64,
    pub ioctl_created: u32,
    pub input_data: Vec<u8>,
    pub is_freed: bool,
    pub free_count: u32,
}

/// IOCTL operation info
#[derive(Debug, Clone)]
pub struct IoctlInfo {
    pub code: u32,
    pub op_type: OpType,
    pub typical_input_size: usize,
    pub returns_handle: bool,
    pub takes_handle: bool,
}

/// Stateful fuzzer that tracks sequences
pub struct StatefulFuzzer {
    /// Known IOCTLs and their behavior
    ioctls: Vec<IoctlInfo>,
    /// Active resources/handles
    resources: HashMap<u64, Resource>,
    /// Freed resources (for UAF testing)
    freed_resources: Vec<Resource>,
    /// Sequence history
    history: Vec<(u32, Vec<u8>)>,
    /// RNG
    rng: StdRng,
    /// Handle counter
    handle_counter: u64,
}

impl StatefulFuzzer {
    pub fn new() -> Self {
        Self {
            ioctls: Vec::new(),
            resources: HashMap::new(),
            freed_resources: Vec::new(),
            history: Vec::new(),
            rng: StdRng::from_entropy(),
            handle_counter: 0,
        }
    }
    
    /// Learn IOCTLs from probing results
    pub fn add_ioctl(&mut self, code: u32) {
        // Heuristically classify IOCTLs based on function code
        let func = (code >> 2) & 0xFFF;
        
        let op_type = match func % 10 {
            0..=2 => OpType::Allocate,  // Low funcs often create/open
            3..=6 => OpType::Use,       // Mid funcs often read/write
            7..=9 => OpType::Free,      // High funcs often close/free
            _ => OpType::Unknown,
        };
        
        self.ioctls.push(IoctlInfo {
            code,
            op_type,
            typical_input_size: 64,
            returns_handle: op_type == OpType::Allocate,
            takes_handle: op_type == OpType::Use || op_type == OpType::Free,
        });
    }
    
    /// Generate a UAF-hunting sequence
    /// Pattern: Allocate → Use → Free → Use (UAF!)
    pub fn generate_uaf_sequence(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut sequence = Vec::new();
        
        // Find allocate, use, and free IOCTLs
        let allocators: Vec<_> = self.ioctls.iter()
            .filter(|i| i.op_type == OpType::Allocate)
            .collect();
        let users: Vec<_> = self.ioctls.iter()
            .filter(|i| i.op_type == OpType::Use)
            .collect();
        let freers: Vec<_> = self.ioctls.iter()
            .filter(|i| i.op_type == OpType::Free)
            .collect();
        
        if allocators.is_empty() || freers.is_empty() {
            // Fallback: random sequence
            return self.generate_random_sequence(4);
        }
        
        // Generate a pseudo-handle to embed in inputs
        let fake_handle = self.rng.gen::<u32>();
        
        // 1. Allocate
        if let Some(alloc) = allocators.choose(&mut self.rng) {
            let mut input = vec![0u8; 64];
            // Put size at start (common pattern)
            input[0..4].copy_from_slice(&64u32.to_le_bytes());
            sequence.push((alloc.code, input));
        }
        
        // 2. Use (with handle embedded)
        if let Some(user) = users.choose(&mut self.rng) {
            let mut input = vec![0u8; 64];
            input[0..4].copy_from_slice(&fake_handle.to_le_bytes());
            sequence.push((user.code, input));
        }
        
        // 3. Free
        if let Some(freer) = freers.choose(&mut self.rng) {
            let mut input = vec![0u8; 64];
            input[0..4].copy_from_slice(&fake_handle.to_le_bytes());
            sequence.push((freer.code, input));
        }
        
        // 4. Use again (UAF attempt!)
        if let Some(user) = users.choose(&mut self.rng) {
            let mut input = vec![0u8; 64];
            input[0..4].copy_from_slice(&fake_handle.to_le_bytes());
            sequence.push((user.code, input));
        }
        
        sequence
    }
    
    /// Generate a double-free sequence
    /// Pattern: Allocate → Free → Free (Double-Free!)
    pub fn generate_double_free_sequence(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut sequence = Vec::new();
        
        let allocators: Vec<_> = self.ioctls.iter()
            .filter(|i| i.op_type == OpType::Allocate)
            .collect();
        let freers: Vec<_> = self.ioctls.iter()
            .filter(|i| i.op_type == OpType::Free)
            .collect();
        
        if allocators.is_empty() || freers.is_empty() {
            return self.generate_random_sequence(3);
        }
        
        let fake_handle = self.rng.gen::<u32>();
        
        // 1. Allocate
        if let Some(alloc) = allocators.choose(&mut self.rng) {
            let mut input = vec![0u8; 64];
            input[0..4].copy_from_slice(&64u32.to_le_bytes());
            sequence.push((alloc.code, input));
        }
        
        // 2. Free
        if let Some(freer) = freers.choose(&mut self.rng) {
            let mut input = vec![0u8; 64];
            input[0..4].copy_from_slice(&fake_handle.to_le_bytes());
            sequence.push((freer.code, input));
        }
        
        // 3. Free again (double-free!)
        if let Some(freer) = freers.choose(&mut self.rng) {
            let mut input = vec![0u8; 64];
            input[0..4].copy_from_slice(&fake_handle.to_le_bytes());
            sequence.push((freer.code, input));
        }
        
        sequence
    }
    
    /// Generate random IOCTL sequence
    pub fn generate_random_sequence(&mut self, length: usize) -> Vec<(u32, Vec<u8>)> {
        let mut sequence = Vec::new();
        
        for _ in 0..length {
            if let Some(ioctl) = self.ioctls.choose(&mut self.rng) {
                let size = self.rng.gen_range(4..256);
                let mut input = vec![0u8; size];
                self.rng.fill(&mut input[..]);
                sequence.push((ioctl.code, input));
            }
        }
        
        sequence
    }
    
    /// Generate sequence targeting a specific pattern
    pub fn generate_sequence(&mut self, pattern: SequencePattern) -> Vec<(u32, Vec<u8>)> {
        match pattern {
            SequencePattern::UseAfterFree => self.generate_uaf_sequence(),
            SequencePattern::DoubleFree => self.generate_double_free_sequence(),
            SequencePattern::Random => {
                let len = rand::thread_rng().gen_range(2..8);
                self.generate_random_sequence(len)
            }
            SequencePattern::SameIoctlRepeated => {
                // Same IOCTL multiple times (finds state issues)
                if let Some(ioctl) = self.ioctls.choose(&mut self.rng) {
                    let code = ioctl.code;
                    (0..5).map(|_| {
                        let mut input = vec![0u8; 64];
                        self.rng.fill(&mut input[..]);
                        (code, input)
                    }).collect()
                } else {
                    vec![]
                }
            }
            SequencePattern::AllocateMany => {
                // Allocate many resources without freeing (resource exhaustion)
                let allocators: Vec<_> = self.ioctls.iter()
                    .filter(|i| i.op_type == OpType::Allocate)
                    .map(|i| i.code)
                    .collect();
                
                if allocators.is_empty() {
                    return self.generate_random_sequence(10);
                }
                
                (0..20).map(|_| {
                    let code = *allocators.choose(&mut self.rng).unwrap();
                    let mut input = vec![0u8; 64];
                    input[0..4].copy_from_slice(&64u32.to_le_bytes());
                    self.rng.fill(&mut input[4..]);
                    (code, input)
                }).collect()
            }
            SequencePattern::InterleavedAllocFree => {
                // Interleaved alloc/free to fragment pool
                let mut seq = Vec::new();
                for i in 0..10 {
                    if i % 2 == 0 {
                        seq.extend(self.generate_uaf_sequence().into_iter().take(1));
                    } else {
                        let freers: Vec<_> = self.ioctls.iter()
                            .filter(|i| i.op_type == OpType::Free)
                            .collect();
                        if let Some(freer) = freers.choose(&mut self.rng) {
                            let mut input = vec![0u8; 64];
                            self.rng.fill(&mut input[..]);
                            seq.push((freer.code, input));
                        }
                    }
                }
                seq
            }
        }
    }
    
    /// Record a response (for learning)
    pub fn record_response(&mut self, ioctl: u32, input: &[u8], output: &[u8], success: bool) {
        // Learn from responses
        if success && output.len() >= 4 {
            // Check if response contains a handle-like value
            let potential_handle = u32::from_le_bytes([output[0], output[1], output[2], output[3]]);
            if potential_handle != 0 && potential_handle != 0xFFFFFFFF {
                // This IOCTL might return handles
                if let Some(info) = self.ioctls.iter_mut().find(|i| i.code == ioctl) {
                    info.returns_handle = true;
                    info.op_type = OpType::Allocate;
                }
                
                self.resources.insert(potential_handle as u64, Resource {
                    handle: potential_handle as u64,
                    ioctl_created: ioctl,
                    input_data: input.to_vec(),
                    is_freed: false,
                    free_count: 0,
                });
            }
        }
        
        self.history.push((ioctl, input.to_vec()));
        
        // Keep history bounded
        if self.history.len() > 1000 {
            self.history.remove(0);
        }
    }
    
    /// Get active resource handles to use in inputs
    pub fn get_active_handles(&self) -> Vec<u64> {
        self.resources.values()
            .filter(|r| !r.is_freed)
            .map(|r| r.handle)
            .collect()
    }
    
    /// Get freed handles (for UAF testing)
    pub fn get_freed_handles(&self) -> Vec<u64> {
        self.freed_resources.iter()
            .map(|r| r.handle)
            .collect()
    }
}

/// Sequence patterns for stateful fuzzing
#[derive(Debug, Clone, Copy)]
pub enum SequencePattern {
    UseAfterFree,
    DoubleFree,
    Random,
    SameIoctlRepeated,
    AllocateMany,
    InterleavedAllocFree,
}

impl SequencePattern {
    pub fn all() -> Vec<Self> {
        vec![
            Self::UseAfterFree,
            Self::DoubleFree,
            Self::Random,
            Self::SameIoctlRepeated,
            Self::AllocateMany,
            Self::InterleavedAllocFree,
        ]
    }
    
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        *Self::all().choose(&mut rng).unwrap()
    }
}

impl Default for StatefulFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

/// HEVD-specific UAF sequence generator
/// HEVD uses specific IOCTLs for its UAF vulnerability:
/// - 0x222013: Allocate UAF Object  
/// - 0x222017: Use UAF Object (also FreeUaFObjectNonPagedPoolNx)
/// - 0x22201B: Free UAF Object
/// - After Free, calling Use again triggers UAF!
pub struct HevdUafFuzzer {
    rng: StdRng,
}

impl HevdUafFuzzer {
    // HEVD IOCTL codes for UAF (NonPagedPoolNx - modern HEVD)
    pub const HEVD_ALLOCATE_UAF: u32 = 0x22201F;
    pub const HEVD_USE_UAF: u32 = 0x222023;  
    pub const HEVD_FREE_UAF: u32 = 0x222027;
    
    pub fn new() -> Self {
        Self {
            rng: StdRng::from_entropy(),
        }
    }
    
    /// Generate the exact UAF trigger sequence for HEVD
    /// Returns: Vec of (ioctl_code, input_buffer)
    pub fn generate_uaf_trigger(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut sequence = Vec::new();
        
        // 1. Allocate UAF Object - creates the vulnerable object
        // HEVD doesn't need special input for allocate
        let alloc_input = vec![0x41u8; 64];
        sequence.push((Self::HEVD_ALLOCATE_UAF, alloc_input));
        
        // 2. Free UAF Object - frees but keeps dangling pointer
        let free_input = vec![0x42u8; 64];
        sequence.push((Self::HEVD_FREE_UAF, free_input));
        
        // 3. Use UAF Object - accesses freed memory = CRASH!
        let use_input = vec![0x43u8; 64];
        sequence.push((Self::HEVD_USE_UAF, use_input));
        
        sequence
    }
    
    /// Generate UAF with heap spray attempt
    pub fn generate_uaf_with_spray(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut sequence = Vec::new();
        
        // 1. Allocate UAF Object
        sequence.push((Self::HEVD_ALLOCATE_UAF, vec![0x41u8; 64]));
        
        // 2. Free UAF Object
        sequence.push((Self::HEVD_FREE_UAF, vec![0x42u8; 64]));
        
        // 3. Try to reallocate the same memory with controlled data
        // (In real exploit, you'd spray the pool here)
        for _ in 0..5 {
            let mut spray_data = vec![0u8; 64];
            self.rng.fill(&mut spray_data[..]);
            // Set "fake vtable" pointer at offset 0
            spray_data[0..8].copy_from_slice(&0x4141414141414141u64.to_le_bytes());
            sequence.push((Self::HEVD_ALLOCATE_UAF, spray_data));
        }
        
        // 4. Use UAF Object - if spray worked, we control execution!
        sequence.push((Self::HEVD_USE_UAF, vec![0x43u8; 64]));
        
        sequence
    }
    
    /// Generate random variations of UAF sequences
    pub fn generate_random_variant(&mut self) -> Vec<(u32, Vec<u8>)> {
        let variant = self.rng.gen_range(0..4);
        
        match variant {
            0 => self.generate_uaf_trigger(),
            1 => self.generate_uaf_with_spray(),
            2 => {
                // Multiple alloc/free cycles
                let mut seq = Vec::new();
                for _ in 0..self.rng.gen_range(1..5) {
                    seq.push((Self::HEVD_ALLOCATE_UAF, vec![0x41u8; 64]));
                    seq.push((Self::HEVD_FREE_UAF, vec![0x42u8; 64]));
                }
                seq.push((Self::HEVD_USE_UAF, vec![0x43u8; 64]));
                seq
            }
            _ => {
                // Interleaved operations
                let mut seq = Vec::new();
                seq.push((Self::HEVD_ALLOCATE_UAF, vec![0x41u8; 64]));
                seq.push((Self::HEVD_USE_UAF, vec![0x43u8; 64])); // Valid use
                seq.push((Self::HEVD_FREE_UAF, vec![0x42u8; 64]));
                seq.push((Self::HEVD_USE_UAF, vec![0x43u8; 64])); // UAF!
                seq
            }
        }
    }
}

impl Default for HevdUafFuzzer {
    fn default() -> Self {
        Self::new()
    }
}
