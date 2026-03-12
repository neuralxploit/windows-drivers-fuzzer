//! Mutation Engine
//! 
//! Provides various mutation strategies for fuzzing input generation.
//! Based on AFL/libFuzzer mutation strategies.

#![allow(dead_code)]

use rand::prelude::*;

/// Mutation engine with AFL-style strategies
pub struct Mutator {
    rng: StdRng,
    /// Interesting byte values for fuzzing
    interesting_8: Vec<u8>,
    /// Interesting 16-bit values
    interesting_16: Vec<u16>,
    /// Interesting 32-bit values  
    interesting_32: Vec<u32>,
    /// Interesting 64-bit values (for kernel pointers/sizes)
    interesting_64: Vec<u64>,
    /// Dictionary of tokens to insert
    dictionary: Vec<Vec<u8>>,
}

impl Mutator {
    pub fn new() -> Self {
        Self {
            rng: StdRng::from_entropy(),
            interesting_8: vec![
                0, 1, 2, 16, 32, 64, 100, 127, 128, 255,
            ],
            interesting_16: vec![
                0, 1, 64, 100, 127, 128, 255, 256, 512, 1000, 1024,
                4096, 32767, 32768, 65535,
            ],
            interesting_32: vec![
                0, 1, 100, 127, 128, 255, 256, 512, 1000, 1024, 4096,
                32767, 32768, 65535, 65536, 100000, 0x7FFFFFFF,
                0x80000000, 0xFFFFFFFF,
                // Additional overflow triggers
                0xFFFFFFFE, 0x7FFFFFFE, 0x80000001,
                0x01010101, 0x10101010, 0x00010000,
                // INTEGER OVERFLOW exploitation patterns
                0xFFFFFFF0, // Near max - size + small offset wraps
                0xFFFFFF00, // Near max - larger additions wrap
                0x40000000, // 1GB - common allocation limit
                0x40000001, // 1GB+1 - multiply by 4 = 4 (overflow!)
                0x20000000, // 512MB boundary
                0x10000001, // Multiply by 16 = 16 (overflow)
                0x00010001, // High word set - structure confusion
                0x00100010, // Unusual alignment
                0xCCCCCCCC, // Uninitialized memory pattern
                0xDEADBEEF, // Debug pattern
                0xFEEEFEEE, // Freed heap pattern (Windows)
                0xBADF00D,  // Bad food - debug marker
            ],
            // 64-bit interesting values for kernel pointers/sizes
            interesting_64: vec![
                0u64, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
                0x100000000, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
                0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE,
                0xFFFF800000000000, // Kernel address range start
                0x0000000041414141, // User-mode fake pointer
                0xDEADBEEFDEADBEEF, // Debug pattern
                // Exploit-specific 64-bit values
                0xFFFFFFFFFFFFFF00, // Near max, alignment
                0xFFFFFFFFFFFFF000, // Page-aligned max
                0xFFFF800000001000, // Kernel base + offset
                0xFFFFF80000000000, // Typical ntoskrnl range
                0xFFFFFA8000000000, // Paged pool range
                0xFFFFFA0000000000, // NonPaged pool range  
                0x0000000080000000, // User/kernel boundary (32-bit)
                0x00007FFF00000000, // User space high
                0x00007FFFFFFFFFFF, // Max user address
                0x0000000100000000, // 4GB boundary (WoW64)
                0xFEEEFEEEFEEEFEEE, // Freed memory pattern
                0xCCCCCCCCCCCCCCCC, // Uninitialized stack
                0xBAADF00DBAADF00D, // Bad memory pattern
                0x4141414141414141, // Overflow pattern
            ],
            dictionary: vec![
                b"AAAA".to_vec(),
                b"%s%s%s%s".to_vec(),
                b"%n%n%n%n".to_vec(),
                b"\x00\x00\x00\x00".to_vec(),
                b"\xFF\xFF\xFF\xFF".to_vec(),
                b"/../../../".to_vec(),
                b"\\..\\..\\..\\".to_vec(),
                // Additional exploitation patterns
                b"\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(), // NULL qword
                b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF".to_vec(), // Max qword
                b"AAAAAAAA".to_vec(), // 8-byte overflow pattern
            ],
        }
    }
    
    /// Apply random mutations to input
    pub fn mutate(&mut self, input: &[u8]) -> Vec<u8> {
        let mut result = input.to_vec();
        
        // Ensure minimum size
        if result.is_empty() {
            result = vec![0u8; 16];
        }
        
        // Apply 1-5 mutations
        let num_mutations = self.rng.gen_range(1..=5);
        
        for _ in 0..num_mutations {
            let strategy = self.rng.gen_range(0..17);
            
            match strategy {
                0 => self.bit_flip(&mut result),
                1 => self.byte_flip(&mut result),
                2 => self.byte_insert(&mut result),
                3 => self.byte_delete(&mut result),
                4 => self.byte_repeat(&mut result),
                5 => self.swap_bytes(&mut result),
                6 => self.swap_words(&mut result),
                7 => self.interesting_byte(&mut result),
                8 => self.interesting_word(&mut result),
                9 => self.interesting_dword(&mut result),
                10 => self.interesting_qword(&mut result),
                11 => self.arithmetic_byte(&mut result),
                12 => self.arithmetic_word(&mut result),
                13 => self.arithmetic_dword(&mut result),
                14 => self.dictionary_insert(&mut result),
                15 => self.kernel_pointer(&mut result),
                16 => self.havoc(&mut result),
                _ => {}
            }
        }
        
        result
    }
    
    /// Flip a random bit
    fn bit_flip(&mut self, data: &mut Vec<u8>) {
        if data.is_empty() { return; }
        let pos = self.rng.gen_range(0..data.len());
        let bit = self.rng.gen_range(0..8);
        data[pos] ^= 1 << bit;
    }
    
    /// Flip a random byte
    fn byte_flip(&mut self, data: &mut Vec<u8>) {
        if data.is_empty() { return; }
        let pos = self.rng.gen_range(0..data.len());
        data[pos] ^= 0xFF;
    }
    
    /// Insert a random byte
    fn byte_insert(&mut self, data: &mut Vec<u8>) {
        if data.len() >= 65536 { return; }  // Max size limit
        let pos = self.rng.gen_range(0..=data.len());
        let byte: u8 = self.rng.gen();
        data.insert(pos, byte);
    }
    
    /// Delete a random byte
    fn byte_delete(&mut self, data: &mut Vec<u8>) {
        if data.len() <= 1 { return; }
        let pos = self.rng.gen_range(0..data.len());
        data.remove(pos);
    }
    
    /// Repeat a byte multiple times
    fn byte_repeat(&mut self, data: &mut Vec<u8>) {
        if data.is_empty() || data.len() >= 65536 { return; }
        let pos = self.rng.gen_range(0..data.len());
        let byte = data[pos];
        let count = self.rng.gen_range(2..=16);
        for _ in 0..count {
            if data.len() >= 65536 { break; }
            data.insert(pos, byte);
        }
    }
    
    /// Swap two random bytes
    fn swap_bytes(&mut self, data: &mut Vec<u8>) {
        if data.len() < 2 { return; }
        let pos1 = self.rng.gen_range(0..data.len());
        let pos2 = self.rng.gen_range(0..data.len());
        data.swap(pos1, pos2);
    }
    
    /// Swap two random 16-bit words
    fn swap_words(&mut self, data: &mut Vec<u8>) {
        if data.len() < 4 { return; }
        let pos1 = self.rng.gen_range(0..data.len() - 1);
        let pos2 = self.rng.gen_range(0..data.len() - 1);
        data.swap(pos1, pos2);
        data.swap(pos1 + 1, pos2 + 1);
    }
    
    /// Replace byte with interesting value
    fn interesting_byte(&mut self, data: &mut Vec<u8>) {
        if data.is_empty() { return; }
        let pos = self.rng.gen_range(0..data.len());
        let val = self.interesting_8[self.rng.gen_range(0..self.interesting_8.len())];
        data[pos] = val;
    }
    
    /// Replace word with interesting value
    fn interesting_word(&mut self, data: &mut Vec<u8>) {
        if data.len() < 2 { return; }
        let pos = self.rng.gen_range(0..data.len() - 1);
        let val = self.interesting_16[self.rng.gen_range(0..self.interesting_16.len())];
        let bytes = if self.rng.gen_bool(0.5) {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        data[pos] = bytes[0];
        data[pos + 1] = bytes[1];
    }
    
    /// Replace dword with interesting value
    fn interesting_dword(&mut self, data: &mut Vec<u8>) {
        if data.len() < 4 { return; }
        let pos = self.rng.gen_range(0..data.len() - 3);
        let val = self.interesting_32[self.rng.gen_range(0..self.interesting_32.len())];
        let bytes = if self.rng.gen_bool(0.5) {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        for (i, &byte) in bytes.iter().enumerate() {
            data[pos + i] = byte;
        }
    }
    
    /// Replace qword with interesting value (64-bit - critical for kernel)
    fn interesting_qword(&mut self, data: &mut Vec<u8>) {
        if data.len() < 8 { return; }
        let pos = (self.rng.gen_range(0..data.len()) / 8) * 8; // Align to 8 bytes
        if pos + 8 > data.len() { return; }
        let val = self.interesting_64[self.rng.gen_range(0..self.interesting_64.len())];
        let bytes = val.to_le_bytes();
        data[pos..pos+8].copy_from_slice(&bytes);
    }
    
    /// Insert kernel-like pointer value (UAF/type confusion trigger)
    fn kernel_pointer(&mut self, data: &mut Vec<u8>) {
        if data.len() < 8 { return; }
        let pos = (self.rng.gen_range(0..data.len()) / 8) * 8;
        if pos + 8 > data.len() { return; }
        // Choose between various pointer patterns
        let ptr: u64 = match self.rng.gen_range(0..6) {
            0 => 0, // NULL
            1 => 0xFFFFFFFF, // 32-bit max (sign extension issues)
            2 => 0xFFFF800000000000 | self.rng.gen::<u64>() & 0xFFFFFFFF, // Kernel range
            3 => 0x0000000041414141, // User-mode fake
            4 => 0xFEEEFEEEFEEEFEEE, // Debug fill (freed memory)
            _ => 0xDEADBEEFDEADBEEF, // Debug pattern
        };
        data[pos..pos+8].copy_from_slice(&ptr.to_le_bytes());
    }
    
    /// Add/subtract from byte
    fn arithmetic_byte(&mut self, data: &mut Vec<u8>) {
        if data.is_empty() { return; }
        let pos = self.rng.gen_range(0..data.len());
        let delta: i8 = self.rng.gen_range(-35..=35);
        data[pos] = data[pos].wrapping_add(delta as u8);
    }
    
    /// Add/subtract from word
    fn arithmetic_word(&mut self, data: &mut Vec<u8>) {
        if data.len() < 2 { return; }
        let pos = self.rng.gen_range(0..data.len() - 1);
        let val = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let delta: i16 = self.rng.gen_range(-35..=35);
        let new_val = val.wrapping_add(delta as u16);
        let bytes = new_val.to_le_bytes();
        data[pos] = bytes[0];
        data[pos + 1] = bytes[1];
    }
    
    /// Add/subtract from dword
    fn arithmetic_dword(&mut self, data: &mut Vec<u8>) {
        if data.len() < 4 { return; }
        let pos = self.rng.gen_range(0..data.len() - 3);
        let val = u32::from_le_bytes([
            data[pos], data[pos + 1], data[pos + 2], data[pos + 3]
        ]);
        let delta: i32 = self.rng.gen_range(-35..=35);
        let new_val = val.wrapping_add(delta as u32);
        let bytes = new_val.to_le_bytes();
        for (i, &byte) in bytes.iter().enumerate() {
            data[pos + i] = byte;
        }
    }
    
    /// Insert dictionary token
    fn dictionary_insert(&mut self, data: &mut Vec<u8>) {
        if self.dictionary.is_empty() || data.len() >= 65536 { return; }
        let token = &self.dictionary[self.rng.gen_range(0..self.dictionary.len())];
        let pos = self.rng.gen_range(0..=data.len());
        for (i, &byte) in token.iter().enumerate() {
            if pos + i >= 65536 { break; }
            data.insert(pos + i, byte);
        }
    }
    
    /// Havoc mode - many random mutations
    fn havoc(&mut self, data: &mut Vec<u8>) {
        let rounds = self.rng.gen_range(1..=16);
        for _ in 0..rounds {
            let mutation = self.rng.gen_range(0..14);
            match mutation {
                0 => self.bit_flip(data),
                1 => self.byte_flip(data),
                2 => self.byte_insert(data),
                3 => self.byte_delete(data),
                4 => self.swap_bytes(data),
                5 => self.interesting_byte(data),
                6 => self.interesting_word(data),
                7 => self.interesting_dword(data),
                8 => self.arithmetic_byte(data),
                9 => self.arithmetic_word(data),
                10 => self.arithmetic_dword(data),
                11..=13 => {
                    // Random overwrite
                    if !data.is_empty() {
                        let len = self.rng.gen_range(1..=16.min(data.len()));
                        let pos = self.rng.gen_range(0..=data.len() - len);
                        for i in 0..len {
                            data[pos + i] = self.rng.gen();
                        }
                    }
                }
                _ => {}
            }
        }
    }
    
    /// Generate a fresh input of given size
    pub fn generate(&mut self, size: usize) -> Vec<u8> {
        let mut data = vec![0u8; size];
        self.rng.fill(&mut data[..]);
        data
    }
    
    /// Add to dictionary
    pub fn add_to_dictionary(&mut self, token: Vec<u8>) {
        if !self.dictionary.contains(&token) {
            self.dictionary.push(token);
        }
    }
}

impl Default for Mutator {
    fn default() -> Self {
        Self::new()
    }
}
