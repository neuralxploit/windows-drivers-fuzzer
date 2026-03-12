//! Race Condition / Multi-threaded Fuzzing
//!
//! Sends concurrent IOCTLs to trigger TOCTOU and race conditions.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Race condition fuzzer configuration
pub struct RaceFuzzer {
    /// Number of threads
    pub thread_count: usize,
    /// Target device path
    pub device_path: String,
    /// IOCTLs to race
    pub ioctls: Vec<u32>,
    /// Running flag
    pub running: Arc<AtomicBool>,
    /// Crash counter
    pub crashes: Arc<AtomicU64>,
}

impl RaceFuzzer {
    pub fn new(device_path: &str, ioctls: Vec<u32>, threads: usize) -> Self {
        Self {
            thread_count: threads,
            device_path: device_path.to_string(),
            ioctls,
            running: Arc::new(AtomicBool::new(false)),
            crashes: Arc::new(AtomicU64::new(0)),
        }
    }
    
    /// Generate racing IOCTL pairs
    /// These are sent simultaneously to trigger TOCTOU bugs
    pub fn generate_race_pairs(&self) -> Vec<(u32, u32)> {
        let mut pairs = Vec::new();
        
        for i in 0..self.ioctls.len() {
            for j in 0..self.ioctls.len() {
                // Same IOCTL racing itself
                if i == j {
                    pairs.push((self.ioctls[i], self.ioctls[j]));
                }
                // Different IOCTLs racing
                pairs.push((self.ioctls[i], self.ioctls[j]));
            }
        }
        
        pairs
    }
}

/// Input for race condition testing - same handle from multiple threads
pub fn generate_race_input(handle: u32, thread_id: usize) -> Vec<u8> {
    let mut input = vec![0u8; 64];
    
    // Same handle in all threads (racing on same resource)
    input[0..4].copy_from_slice(&handle.to_le_bytes());
    
    // Thread-specific data
    input[4..8].copy_from_slice(&(thread_id as u32).to_le_bytes());
    
    // Operation type (read/write alternating)
    input[8] = if thread_id % 2 == 0 { 0 } else { 1 };
    
    input
}

/// Barrier for synchronizing threads (increases race likelihood)
pub struct SpinBarrier {
    count: AtomicU64,
    target: u64,
}

impl SpinBarrier {
    pub fn new(target: u64) -> Self {
        Self {
            count: AtomicU64::new(0),
            target,
        }
    }
    
    /// Wait for all threads to reach this point
    pub fn wait(&self) {
        self.count.fetch_add(1, Ordering::SeqCst);
        
        // Spin until all threads arrive
        while self.count.load(Ordering::SeqCst) < self.target {
            std::hint::spin_loop();
        }
    }
    
    pub fn reset(&self) {
        self.count.store(0, Ordering::SeqCst);
    }
}
