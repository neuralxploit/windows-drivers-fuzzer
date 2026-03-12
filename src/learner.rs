//! Smart IOCTL Learning Module
//!
//! Automatically learns driver behavior by observing:
//! - Return values and output buffers
//! - State changes across IOCTL sequences
//! - Which IOCTLs allocate, use, or free resources
//!
//! No hardcoded addresses - works on ANY driver!

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use rand::prelude::*;
use serde::{Serialize, Deserialize};

/// Observed behavior of an IOCTL
#[derive(Debug, Clone, Default)]
pub struct IoctlBehavior {
    pub code: u32,
    /// How many times we've called it
    pub call_count: u64,
    /// Success count
    pub success_count: u64,
    /// Different return codes seen
    pub return_codes: HashSet<u32>,
    /// Does it write to output buffer?
    pub writes_output: bool,
    /// Average output size when successful
    pub avg_output_size: f64,
    /// Does output look like a handle/pointer? (non-zero, aligned)
    pub returns_handle_like: u32,
    /// Does it need specific input to succeed?
    pub needs_structured_input: bool,
    /// Minimum input size that worked
    pub min_working_input: usize,
    /// Does behavior change based on prior calls?
    pub state_dependent: bool,
    /// Confidence in classification (0.0 - 1.0)
    pub confidence: f64,
    /// Inferred type
    pub inferred_type: IoctlType,
    /// Dependencies - which IOCTLs should come before this one
    pub depends_on: Vec<u32>,
    /// Enables - which IOCTLs work better after this one
    pub enables: Vec<u32>,
}

/// Inferred IOCTL type based on behavior
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum IoctlType {
    #[default]
    Unknown,
    /// Allocates/creates a resource, returns handle
    Allocator,
    /// Uses an existing resource
    User,
    /// Frees/releases a resource
    Freer,
    /// Query/info - doesn't change state
    Query,
    /// Config/set - changes settings
    Config,
}

/// Smart IOCTL learner
pub struct IoctlLearner {
    /// Behavior database
    behaviors: HashMap<u32, IoctlBehavior>,
    /// Sequence history for learning dependencies
    history: Vec<(u32, bool)>, // (ioctl, success)
    /// Learned state machine transitions
    transitions: HashMap<(u32, u32), TransitionInfo>,
    /// RNG
    rng: StdRng,
}

#[derive(Debug, Clone, Default)]
pub struct TransitionInfo {
    pub count: u64,
    pub success_after: u64,
    pub fail_after: u64,
    /// Did the second call behave differently after the first?
    pub state_changed: bool,
}

impl IoctlLearner {
    pub fn new() -> Self {
        Self {
            behaviors: HashMap::new(),
            history: Vec::new(),
            transitions: HashMap::new(),
            rng: StdRng::from_entropy(),
        }
    }
    
    /// Record an IOCTL call result for learning
    pub fn record_call(
        &mut self,
        ioctl: u32,
        input: &[u8],
        output: &[u8],
        bytes_returned: u32,
        error_code: u32,
        success: bool,
    ) {
        let behavior = self.behaviors.entry(ioctl).or_insert_with(|| {
            IoctlBehavior {
                code: ioctl,
                ..Default::default()
            }
        });
        
        behavior.call_count += 1;
        if success {
            behavior.success_count += 1;
        }
        behavior.return_codes.insert(error_code);
        
        // Analyze output buffer
        if bytes_returned > 0 && success {
            behavior.writes_output = true;
            let n = behavior.call_count as f64;
            behavior.avg_output_size = 
                (behavior.avg_output_size * (n - 1.0) + bytes_returned as f64) / n;
            
            // Check if output looks like a handle (pointer-like value)
            if bytes_returned >= 4 {
                let val = u32::from_le_bytes([output[0], output[1], output[2], output[3]]);
                // Handles are typically non-zero, sometimes aligned
                if val != 0 && val > 0x1000 {
                    behavior.returns_handle_like += 1;
                }
            }
            if bytes_returned >= 8 {
                let val = u64::from_le_bytes([
                    output[0], output[1], output[2], output[3],
                    output[4], output[5], output[6], output[7]
                ]);
                if val != 0 && val > 0x10000 && (val & 0xFFF) == 0 {
                    // Page-aligned, looks like kernel pointer
                    behavior.returns_handle_like += 2;
                }
            }
        }
        
        // Track minimum working input size
        if success {
            if behavior.min_working_input == 0 || input.len() < behavior.min_working_input {
                behavior.min_working_input = input.len();
            }
        }
        
        // Record transition from previous IOCTL
        if let Some(&(prev_ioctl, _)) = self.history.last() {
            let transition = self.transitions
                .entry((prev_ioctl, ioctl))
                .or_default();
            transition.count += 1;
            if success {
                transition.success_after += 1;
            } else {
                transition.fail_after += 1;
            }
        }
        
        self.history.push((ioctl, success));
        if self.history.len() > 10000 {
            self.history.remove(0);
        }
    }
    
    /// Analyze and classify all recorded IOCTLs
    pub fn analyze(&mut self) {
        // Calculate statistics for classification
        let total_ioctls = self.behaviors.len();
        if total_ioctls == 0 {
            return;
        }
        
        // Find IOCTLs that return handle-like values (likely allocators)
        let _handle_returners: Vec<u32> = self.behaviors.iter()
            .filter(|(_, b)| b.returns_handle_like > b.call_count as u32 / 3)
            .map(|(k, _)| *k)
            .collect();
        
        // Find IOCTLs that only succeed after certain others (likely users/freers)
        for (&ioctl, behavior) in &mut self.behaviors {
            let mut best_predecessor: Option<(u32, f64)> = None;
            
            for (&(prev, curr), trans) in &self.transitions {
                if curr == ioctl && trans.count > 5 {
                    let success_rate = trans.success_after as f64 / trans.count as f64;
                    if let Some((_, best_rate)) = best_predecessor {
                        if success_rate > best_rate {
                            best_predecessor = Some((prev, success_rate));
                        }
                    } else {
                        best_predecessor = Some((prev, success_rate));
                    }
                }
            }
            
            // If this IOCTL works much better after a specific other IOCTL
            if let Some((prev, rate)) = best_predecessor {
                if rate > 0.7 {
                    behavior.depends_on.push(prev);
                    behavior.state_dependent = true;
                }
            }
        }
        
        // Classify each IOCTL with more nuanced heuristics
        for (&ioctl, behavior) in &mut self.behaviors {
            let success_rate = if behavior.call_count > 0 {
                behavior.success_count as f64 / behavior.call_count as f64
            } else {
                0.0
            };
            
            // How many different return codes does it have?
            let return_code_diversity = behavior.return_codes.len();
            
            // High handle-like returns = Allocator
            if behavior.returns_handle_like > behavior.call_count as u32 / 2 {
                behavior.inferred_type = IoctlType::Allocator;
                behavior.confidence = 0.7 + (success_rate * 0.3);
            }
            // State dependent + doesn't return handles = User or Freer
            else if behavior.state_dependent {
                // If it commonly fails when called twice = likely Freer
                let double_call_fail = self.transitions.get(&(ioctl, ioctl))
                    .map(|t| t.fail_after > t.success_after)
                    .unwrap_or(false);
                
                if double_call_fail {
                    behavior.inferred_type = IoctlType::Freer;
                    behavior.confidence = 0.6;
                } else {
                    behavior.inferred_type = IoctlType::User;
                    behavior.confidence = 0.5;
                }
            }
            // Always works, returns data = Query
            else if success_rate > 0.9 && behavior.writes_output {
                behavior.inferred_type = IoctlType::Query;
                behavior.confidence = 0.8;
            }
            // Always works, no output = Config
            else if success_rate > 0.9 && !behavior.writes_output {
                behavior.inferred_type = IoctlType::Config;
                behavior.confidence = 0.6;
            }
            // NEW: Partial success rate suggests size-sensitive IOCTL (potential allocator)
            else if success_rate > 0.1 && success_rate < 0.8 && return_code_diversity > 1 {
                // Different input sizes produce different results - interesting!
                if behavior.writes_output {
                    behavior.inferred_type = IoctlType::Allocator;
                    behavior.confidence = 0.4;
                } else {
                    behavior.inferred_type = IoctlType::Config;
                    behavior.confidence = 0.35;
                }
            }
            // NEW: Even if all fail, look at return code diversity
            else if return_code_diversity > 2 {
                // Multiple error codes = driver is actually processing input
                behavior.inferred_type = IoctlType::User;
                behavior.confidence = 0.25;
            }
            // NEW: Minimum working size differs = size-dependent
            else if behavior.min_working_input > 0 {
                behavior.inferred_type = IoctlType::Config;
                behavior.confidence = 0.3;
            }
        }
        
        // Update enables relationships
        for (&(prev, curr), trans) in &self.transitions {
            if trans.count > 5 {
                let success_rate = trans.success_after as f64 / trans.count as f64;
                if success_rate > 0.7 {
                    if let Some(behavior) = self.behaviors.get_mut(&prev) {
                        if !behavior.enables.contains(&curr) {
                            behavior.enables.push(curr);
                        }
                    }
                }
            }
        }
    }
    
    /// Get all IOCTLs classified as allocators
    pub fn get_allocators(&self) -> Vec<u32> {
        self.behaviors.iter()
            .filter(|(_, b)| b.inferred_type == IoctlType::Allocator)
            .map(|(k, _)| *k)
            .collect()
    }
    
    /// Get all IOCTLs classified as freers
    pub fn get_freers(&self) -> Vec<u32> {
        self.behaviors.iter()
            .filter(|(_, b)| b.inferred_type == IoctlType::Freer)
            .map(|(k, _)| *k)
            .collect()
    }
    
    /// Get all IOCTLs classified as users
    pub fn get_users(&self) -> Vec<u32> {
        self.behaviors.iter()
            .filter(|(_, b)| b.inferred_type == IoctlType::User)
            .map(|(k, _)| *k)
            .collect()
    }
    
    /// Generate a likely UAF sequence based on learned behavior
    pub fn generate_uaf_sequence(&mut self) -> Option<Vec<(u32, IoctlType)>> {
        let allocators = self.get_allocators();
        let freers = self.get_freers();
        let users = self.get_users();
        
        if allocators.is_empty() {
            return None;
        }
        
        let mut sequence = Vec::new();
        
        // 1. Pick an allocator
        let alloc = *allocators.choose(&mut self.rng)?;
        sequence.push((alloc, IoctlType::Allocator));
        
        // 2. Maybe use it first (optional)
        if !users.is_empty() && self.rng.gen_bool(0.5) {
            let user = *users.choose(&mut self.rng)?;
            sequence.push((user, IoctlType::User));
        }
        
        // 3. Free it
        if !freers.is_empty() {
            let freer = *freers.choose(&mut self.rng)?;
            sequence.push((freer, IoctlType::Freer));
        } else {
            // No known freer - try all IOCTLs as potential freers
            let all_ioctls: Vec<u32> = self.behaviors.keys().cloned().collect();
            if let Some(&ioctl) = all_ioctls.choose(&mut self.rng) {
                sequence.push((ioctl, IoctlType::Unknown));
            }
        }
        
        // 4. Use after free!
        if !users.is_empty() {
            let user = *users.choose(&mut self.rng)?;
            sequence.push((user, IoctlType::User));
        } else {
            let all_ioctls: Vec<u32> = self.behaviors.keys().cloned().collect();
            if let Some(&ioctl) = all_ioctls.choose(&mut self.rng) {
                sequence.push((ioctl, IoctlType::Unknown));
            }
        }
        
        Some(sequence)
    }
    
    /// Generate a double-free sequence
    pub fn generate_double_free_sequence(&mut self) -> Option<Vec<(u32, IoctlType)>> {
        let allocators = self.get_allocators();
        let freers = self.get_freers();
        
        if allocators.is_empty() {
            return None;
        }
        
        let mut sequence = Vec::new();
        
        // Allocate
        let alloc = *allocators.choose(&mut self.rng)?;
        sequence.push((alloc, IoctlType::Allocator));
        
        // Free twice
        if !freers.is_empty() {
            let freer = *freers.choose(&mut self.rng)?;
            sequence.push((freer, IoctlType::Freer));
            sequence.push((freer, IoctlType::Freer));
        }
        
        Some(sequence)
    }
    
    /// Get behavior summary for display
    pub fn get_summary(&self) -> Vec<(u32, IoctlType, f64)> {
        let mut summary: Vec<_> = self.behaviors.iter()
            .map(|(k, b)| (*k, b.inferred_type, b.confidence))
            .collect();
        summary.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
        summary
    }
    
    /// Get detailed behavior for an IOCTL
    pub fn get_behavior(&self, ioctl: u32) -> Option<&IoctlBehavior> {
        self.behaviors.get(&ioctl)
    }
    
    /// Print learned knowledge
    pub fn print_knowledge(&self) {
        println!("\n[*] Learned IOCTL Classifications:");
        println!("    {:10} {:12} {:10} {:8} {:8} {:}", 
                 "IOCTL", "Type", "Confidence", "Success%", "RetCodes", "Notes");
        println!("    {}", "-".repeat(80));
        
        let mut sorted: Vec<_> = self.behaviors.iter().collect();
        sorted.sort_by(|a, b| b.1.confidence.partial_cmp(&a.1.confidence).unwrap());
        
        for (ioctl, behavior) in sorted.iter().take(30) {
            let type_str = match behavior.inferred_type {
                IoctlType::Allocator => "ALLOCATOR",
                IoctlType::User => "USER",
                IoctlType::Freer => "FREER",
                IoctlType::Query => "QUERY",
                IoctlType::Config => "CONFIG",
                IoctlType::Unknown => "UNKNOWN",
            };
            
            let success_pct = if behavior.call_count > 0 {
                (behavior.success_count as f64 / behavior.call_count as f64) * 100.0
            } else {
                0.0
            };
            
            let notes = if behavior.returns_handle_like > 0 {
                "returns handle-like"
            } else if behavior.state_dependent {
                "state-dependent"
            } else if behavior.writes_output {
                "writes output"
            } else if behavior.return_codes.len() > 1 {
                "multi-error"
            } else {
                ""
            };
            
            println!("    0x{:08X} {:12} {:>6.0}%    {:>5.1}%   {:>3}      {}", 
                ioctl, type_str, behavior.confidence * 100.0, 
                success_pct, behavior.return_codes.len(), notes);
        }
        
        // Print raw stats for debugging
        println!("\n[*] Raw Behavior Stats:");
        for (ioctl, behavior) in sorted.iter().take(10) {
            let codes: Vec<_> = behavior.return_codes.iter().collect();
            println!("    0x{:08X}: {} calls, {} success, codes: {:?}", 
                     ioctl, behavior.call_count, behavior.success_count, codes);
        }
        
        println!("\n[*] Potential UAF chains:");
        let allocators = self.get_allocators();
        let freers = self.get_freers();
        let users = self.get_users();
        
        if !allocators.is_empty() && !freers.is_empty() {
            for alloc in allocators.iter().take(3) {
                for freer in freers.iter().take(3) {
                    for user in users.iter().take(3) {
                        println!("    Alloc(0x{:08X}) -> Free(0x{:08X}) -> Use(0x{:08X})",
                            alloc, freer, user);
                    }
                }
            }
        } else if !allocators.is_empty() {
            println!("    Found potential allocators but no freers:");
            for alloc in allocators.iter().take(5) {
                println!("      Allocator: 0x{:08X}", alloc);
            }
        } else {
            println!("    No clear UAF patterns - driver may need structured input");
            println!("    Try: --stateful for sequential testing");
        }
    }
}

impl Default for IoctlLearner {
    fn default() -> Self {
        Self::new()
    }
}

/// Smart fuzzer that uses learning to find vulnerabilities
pub struct SmartFuzzer {
    pub learner: IoctlLearner,
    /// Phase of fuzzing
    phase: FuzzPhase,
    /// IOCTLs to fuzz
    ioctls: Vec<u32>,
    /// Current learning iteration
    learn_iteration: u64,
    /// RNG
    rng: StdRng,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FuzzPhase {
    /// Learning IOCTL behaviors
    Learning,
    /// Hunting for UAF
    UafHunting,
    /// Hunting for double-free
    DoubleFreeHunting,
    /// General stateful fuzzing
    StatefulFuzzing,
}

impl SmartFuzzer {
    pub fn new(ioctls: Vec<u32>) -> Self {
        Self {
            learner: IoctlLearner::new(),
            phase: FuzzPhase::Learning,
            ioctls,
            learn_iteration: 0,
            rng: StdRng::from_entropy(),
        }
    }
    
    /// Get current phase
    pub fn phase(&self) -> FuzzPhase {
        self.phase
    }
    
    /// Check if learning phase is complete
    pub fn learning_complete(&self) -> bool {
        // Need at least 100 calls per IOCTL for better learning
        let min_calls = self.ioctls.len() as u64 * 100;
        self.learn_iteration >= min_calls
    }
    
    /// Transition to hunting phase
    pub fn start_hunting(&mut self) {
        self.learner.analyze();
        self.learner.print_knowledge();
        
        // Pick hunting mode based on what we learned
        let allocators = self.learner.get_allocators();
        let freers = self.learner.get_freers();
        
        if !allocators.is_empty() && !freers.is_empty() {
            self.phase = FuzzPhase::UafHunting;
        } else if !allocators.is_empty() {
            self.phase = FuzzPhase::DoubleFreeHunting;
        } else {
            self.phase = FuzzPhase::StatefulFuzzing;
        }
    }
    
    /// Generate next test case based on current phase
    pub fn next_input(&mut self) -> (u32, Vec<u8>) {
        match self.phase {
            FuzzPhase::Learning => self.generate_learning_input(),
            FuzzPhase::UafHunting => self.generate_uaf_input(),
            FuzzPhase::DoubleFreeHunting => self.generate_double_free_input(),
            FuzzPhase::StatefulFuzzing => self.generate_stateful_input(),
        }
    }
    
    /// Generate input for learning phase - AGGRESSIVE mode
    fn generate_learning_input(&mut self) -> (u32, Vec<u8>) {
        self.learn_iteration += 1;
        
        // Cycle through IOCTLs
        let ioctl = self.ioctls[self.learn_iteration as usize % self.ioctls.len()];
        
        // Vary input sizes and patterns - more aggressive
        let size = match self.learn_iteration % 20 {
            0 => 0,
            1 => 4,
            2 => 8,
            3 => 16,
            4 => 24,
            5 => 32,
            6 => 48,
            7 => 64,
            8 => 128,
            9 => 256,
            10 => 512,
            11 => 1024,
            12 => 2048,
            13 => 4096,
            14 => 8192,
            15 => 12,     // Odd sizes
            16 => 20,
            17 => 36,
            18 => 72,
            _ => self.rng.gen_range(1..4096),
        };
        
        let mut input = vec![0u8; size];
        
        // Try MANY different patterns
        match self.learn_iteration % 15 {
            0 => {}, // zeros
            1 => input.fill(0xFF),
            2 => input.fill(0x41),
            3 => {
                // Size prefix pattern (common in drivers)
                if size >= 4 {
                    input[0..4].copy_from_slice(&(size as u32).to_le_bytes());
                }
            }
            4 => {
                // Version/magic header
                if size >= 8 {
                    input[0..4].copy_from_slice(&0x00010000u32.to_le_bytes()); // version 1.0
                    input[4..8].copy_from_slice(&(size as u32).to_le_bytes());
                }
            }
            5 => {
                // VBox-style request header
                if size >= 24 {
                    input[0..4].copy_from_slice(&(size as u32).to_le_bytes()); // size
                    input[4..8].copy_from_slice(&0x10001u32.to_le_bytes());    // version
                    input[8..12].copy_from_slice(&self.rng.gen::<u32>().to_le_bytes()); // requestType
                    input[12..16].copy_from_slice(&0u32.to_le_bytes());        // rc
                    input[16..20].copy_from_slice(&0u32.to_le_bytes());        // reserved1
                    input[20..24].copy_from_slice(&0u32.to_le_bytes());        // reserved2
                }
            }
            6 => {
                // Pointer-sized fields
                if size >= 8 {
                    for i in (0..size).step_by(8) {
                        if i + 8 <= size {
                            input[i..i+8].copy_from_slice(&0xDEADBEEFCAFEBABEu64.to_le_bytes());
                        }
                    }
                }
            }
            7 => {
                // Incrementing pattern (helps find buffer overflows)
                for (i, b) in input.iter_mut().enumerate() {
                    *b = (i & 0xFF) as u8;
                }
            }
            8 => {
                // Handle-like first field
                if size >= 8 {
                    input[0..8].copy_from_slice(&0x12345678u64.to_le_bytes());
                }
            }
            9 => {
                // Length + data pattern
                if size >= 8 {
                    input[0..4].copy_from_slice(&((size - 4) as u32).to_le_bytes());
                    for b in &mut input[4..] {
                        *b = 0x41;
                    }
                }
            }
            10 => {
                // GUID-like
                if size >= 16 {
                    input[0..16].copy_from_slice(&[
                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
                    ]);
                }
            }
            11 => {
                // Nested structure simulation
                if size >= 32 {
                    input[0..4].copy_from_slice(&32u32.to_le_bytes());  // total size
                    input[4..8].copy_from_slice(&1u32.to_le_bytes());   // type
                    input[8..12].copy_from_slice(&16u32.to_le_bytes()); // offset
                    input[12..16].copy_from_slice(&16u32.to_le_bytes());// length
                    input[16..32].fill(0xCC);
                }
            }
            12 => {
                // TPM-style command
                if size >= 10 {
                    input[0..2].copy_from_slice(&0x8001u16.to_be_bytes()); // tag
                    input[2..6].copy_from_slice(&(size as u32).to_be_bytes()); // commandSize
                    input[6..10].copy_from_slice(&0x0144u32.to_be_bytes()); // commandCode
                }
            }
            13 => {
                // WindowsTrustedRT style
                if size >= 24 {
                    input[0..4].copy_from_slice(&1u32.to_le_bytes());      // operation
                    input[4..8].copy_from_slice(&0u32.to_le_bytes());      // flags
                    input[8..16].copy_from_slice(&0u64.to_le_bytes());     // handle
                    input[16..24].copy_from_slice(&(size as u64).to_le_bytes()); // size
                }
            }
            _ => self.rng.fill(&mut input[..]),
        }
        
        (ioctl, input)
    }
    
    /// Generate UAF-hunting input
    fn generate_uaf_input(&mut self) -> (u32, Vec<u8>) {
        // This returns one IOCTL at a time from a sequence
        // The sequence is: Alloc -> Free -> Use
        // Caller should execute multiple calls in sequence
        
        if let Some(seq) = self.learner.generate_uaf_sequence() {
            if let Some((ioctl, _)) = seq.first() {
                let mut input = vec![0u8; 64];
                self.rng.fill(&mut input[..]);
                return (*ioctl, input);
            }
        }
        
        // Fallback: random IOCTL
        let ioctl = *self.ioctls.choose(&mut self.rng).unwrap_or(&0);
        let mut input = vec![0u8; 64];
        self.rng.fill(&mut input[..]);
        (ioctl, input)
    }
    
    /// Generate double-free hunting input  
    fn generate_double_free_input(&mut self) -> (u32, Vec<u8>) {
        if let Some(seq) = self.learner.generate_double_free_sequence() {
            if let Some((ioctl, _)) = seq.first() {
                let mut input = vec![0u8; 64];
                self.rng.fill(&mut input[..]);
                return (*ioctl, input);
            }
        }
        
        let ioctl = *self.ioctls.choose(&mut self.rng).unwrap_or(&0);
        let mut input = vec![0u8; 64];
        self.rng.fill(&mut input[..]);
        (ioctl, input)
    }
    
    /// Generate stateful fuzzing input
    fn generate_stateful_input(&mut self) -> (u32, Vec<u8>) {
        let ioctl = *self.ioctls.choose(&mut self.rng).unwrap_or(&0);
        let size = self.rng.gen_range(0..2048);
        let mut input = vec![0u8; size];
        self.rng.fill(&mut input[..]);
        (ioctl, input)
    }
    
    /// Generate full UAF sequence for execution
    pub fn generate_full_uaf_sequence(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut sequence = Vec::new();
        
        if let Some(types) = self.learner.generate_uaf_sequence() {
            for (ioctl, _) in types {
                let mut input = vec![0u8; 64];
                self.rng.fill(&mut input[..]);
                sequence.push((ioctl, input));
            }
        } else {
            // Fallback: random sequence
            for _ in 0..4 {
                let ioctl = *self.ioctls.choose(&mut self.rng).unwrap_or(&0);
                let mut input = vec![0u8; 64];
                self.rng.fill(&mut input[..]);
                sequence.push((ioctl, input));
            }
        }
        
        sequence
    }
    
    /// Record result for learning
    pub fn record_result(
        &mut self,
        ioctl: u32,
        input: &[u8],
        output: &[u8],
        bytes_returned: u32,
        error_code: u32,
        success: bool,
    ) {
        self.learner.record_call(ioctl, input, output, bytes_returned, error_code, success);
    }
}

impl Default for SmartFuzzer {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}
// ═══════════════════════════════════════════════════════════════════════════════
// MSFuzz-Style Improvements: NTSTATUS Guidance, Crash Dedup, Dependency Learning
// ═══════════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};

/// NTSTATUS hints for guided mutation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NtStatusHint {
    Success,                    // 0x00000000 - Input accepted!
    BufferTooSmall,             // Need larger buffer
    InvalidParameter,           // Wrong value somewhere
    InvalidBufferSize,          // Specific size required
    AccessDenied,               // Need different access
    NotSupported,               // IOCTL exists but not for this
    InfoLengthMismatch,         // Struct size wrong
    InvalidDeviceRequest,       // IOCTL not supported
    Timeout,                    // Driver busy/stuck
    Other(u32),
}

impl From<u32> for NtStatusHint {
    fn from(code: u32) -> Self {
        match code {
            0x00000000 => NtStatusHint::Success,
            // BUFFER_TOO_SMALL variants
            0xC0000023 | 0x80000005 | 122 | 0x8007007A => NtStatusHint::BufferTooSmall,
            // INVALID_PARAMETER variants
            0xC000000D | 0x80070057 | 87 => NtStatusHint::InvalidParameter,
            // INVALID_BUFFER_SIZE
            0xC0000206 | 24 | 0x80070018 => NtStatusHint::InvalidBufferSize,
            // ACCESS_DENIED
            0xC0000022 | 0x80070005 | 5 => NtStatusHint::AccessDenied,
            // NOT_SUPPORTED
            0xC00000BB => NtStatusHint::NotSupported,
            // INFO_LENGTH_MISMATCH
            0xC0000004 => NtStatusHint::InfoLengthMismatch,
            // INVALID_DEVICE_REQUEST
            0xC0000010 | 1 => NtStatusHint::InvalidDeviceRequest,
            // TIMEOUT
            0xC00000B5 | 0x80070102 => NtStatusHint::Timeout,
            _ => NtStatusHint::Other(code),
        }
    }
}

impl NtStatusHint {
    /// Get suggested action based on this status
    pub fn suggest_action(&self) -> MutationAction {
        match self {
            NtStatusHint::Success => MutationAction::MutateFromThis,
            NtStatusHint::BufferTooSmall => MutationAction::DoubleBufferSize,
            NtStatusHint::InvalidParameter => MutationAction::TryMagicValues,
            NtStatusHint::InvalidBufferSize => MutationAction::TryCommonSizes,
            NtStatusHint::InfoLengthMismatch => MutationAction::TryStructSizes,
            NtStatusHint::AccessDenied => MutationAction::Skip,
            NtStatusHint::NotSupported => MutationAction::Skip,
            NtStatusHint::InvalidDeviceRequest => MutationAction::Skip,
            NtStatusHint::Timeout => MutationAction::ReduceSize,
            NtStatusHint::Other(_) => MutationAction::RandomMutate,
        }
    }
}

/// Suggested mutation action based on NTSTATUS
#[derive(Debug, Clone, Copy)]
pub enum MutationAction {
    MutateFromThis,    // This input is good, mutate from it
    DoubleBufferSize,  // Try larger buffer
    TryMagicValues,    // Try common magic values (0, -1, etc)
    TryCommonSizes,    // Try common struct sizes (8, 16, 32, 64, etc)
    TryStructSizes,    // Try sizes from output buffer
    ReduceSize,        // Try smaller input
    RandomMutate,      // Random mutation
    Skip,              // This IOCTL won't work, skip it
}

/// Crash signature for smart deduplication
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CrashSignature {
    pub ioctl: u32,
    pub error_code: u32,
    pub input_size_bucket: u8,
    pub input_header_hash: [u8; 4],  // Hash of first 16 bytes
}

impl CrashSignature {
    pub fn new(ioctl: u32, error: u32, input: &[u8]) -> Self {
        // Bucket sizes: 0=tiny(0-16), 1=small(17-64), 2=med(65-256), 3=large(257-1024), 4=huge
        let size_bucket = match input.len() {
            0..=16 => 0,
            17..=64 => 1,
            65..=256 => 2,
            257..=1024 => 3,
            _ => 4,
        };
        
        // Hash the header (first 16 bytes) to group similar inputs
        let header = if input.len() >= 16 { &input[..16] } else { input };
        let mut hasher = Sha256::new();
        hasher.update(header);
        let hash = hasher.finalize();
        let mut header_hash = [0u8; 4];
        header_hash.copy_from_slice(&hash[..4]);
        
        Self {
            ioctl,
            error_code: error,
            input_size_bucket: size_bucket,
            input_header_hash: header_hash,
        }
    }
}

/// Per-IOCTL learned constraints (MSFuzz-style)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IoctlConstraint {
    /// Minimum size that got past BUFFER_TOO_SMALL
    pub min_size_learned: Option<usize>,
    /// Sizes that returned SUCCESS
    pub success_sizes: Vec<usize>,
    /// Best inputs that got closest to success
    pub promising_inputs: Vec<Vec<u8>>,
    /// Error code histogram
    pub error_counts: HashMap<u32, u64>,
    /// Output signature when called alone
    pub solo_signature: Option<[u8; 8]>,
}

/// Smart crash deduplicator and constraint learner
/// Smart crash deduplicator and constraint learner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartDedup {
    /// Known crash signatures
    known_crashes: HashSet<CrashSignature>,
    /// Per-IOCTL constraints
    constraints: HashMap<u32, IoctlConstraint>,
    /// IOCTL dependencies (A affects B if calling A changes B's behavior)
    dependencies: HashMap<u32, HashSet<u32>>,  // ioctl -> set of IOCTLs it affects
    /// Reverse dependencies
    prereqs: HashMap<u32, HashSet<u32>>,       // ioctl -> set of IOCTLs that should come before
    /// Total observations
    observation_count: u64,
}

impl SmartDedup {
    pub fn new() -> Self {
        Self {
            known_crashes: HashSet::new(),
            constraints: HashMap::new(),
            dependencies: HashMap::new(),
            prereqs: HashMap::new(),
            observation_count: 0,
        }
    }
    
    /// Initialize with known IOCTLs
    pub fn init_ioctls(&mut self, ioctls: &[u32]) {
        for &ioctl in ioctls {
            self.constraints.entry(ioctl).or_default();
        }
    }
    
    /// Check if crash is unique (returns true if NEW, false if duplicate)
    pub fn is_unique_crash(&mut self, ioctl: u32, error: u32, input: &[u8]) -> bool {
        let sig = CrashSignature::new(ioctl, error, input);
        if self.known_crashes.contains(&sig) {
            false
        } else {
            self.known_crashes.insert(sig);
            true
        }
    }
    
    /// Get number of unique crashes seen
    pub fn unique_crash_count(&self) -> usize {
        self.known_crashes.len()
    }
    
    /// Record IOCTL result and learn from it
    pub fn record_result(&mut self, ioctl: u32, input: &[u8], output: &[u8], status: u32) {
        self.observation_count += 1;
        
        let constraint = self.constraints.entry(ioctl).or_default();
        *constraint.error_counts.entry(status).or_insert(0) += 1;
        
        let hint = NtStatusHint::from(status);
        
        match hint {
            NtStatusHint::Success => {
                // Great! This input works
                constraint.success_sizes.push(input.len());
                if constraint.promising_inputs.len() < 10 {
                    constraint.promising_inputs.push(input.to_vec());
                }
            }
            NtStatusHint::BufferTooSmall => {
                // Learn minimum size
                let current = constraint.min_size_learned.unwrap_or(0);
                if input.len() >= current {
                    // Need even bigger - driver rejected this size
                    constraint.min_size_learned = Some(input.len() * 2);
                }
            }
            NtStatusHint::InvalidParameter | NtStatusHint::InvalidBufferSize => {
                // This input is close - save it
                if constraint.promising_inputs.len() < 20 {
                    constraint.promising_inputs.push(input.to_vec());
                }
            }
            NtStatusHint::InfoLengthMismatch => {
                // Output might contain expected size
                if output.len() >= 4 {
                    let expected = u32::from_le_bytes([output[0], output[1], output[2], output[3]]) as usize;
                    if expected > 0 && expected < 0x10000 {
                        constraint.min_size_learned = Some(expected);
                    }
                }
            }
            _ => {}
        }
        
        // Record solo signature for first few calls (for dependency detection)
        if self.observation_count <= 1000 && constraint.solo_signature.is_none() {
            let mut hasher = Sha256::new();
            hasher.update(&status.to_le_bytes());
            hasher.update(output);
            let hash = hasher.finalize();
            let mut sig = [0u8; 8];
            sig.copy_from_slice(&hash[..8]);
            constraint.solo_signature = Some(sig);
        }
    }
    
    /// Record a sequence and detect dependencies
    pub fn record_sequence(&mut self, first: u32, second: u32, second_output: &[u8], second_status: u32) {
        // Check if second IOCTL's behavior changed after first
        if let Some(constraint) = self.constraints.get(&second) {
            if let Some(solo_sig) = constraint.solo_signature {
                let mut hasher = Sha256::new();
                hasher.update(&second_status.to_le_bytes());
                hasher.update(second_output);
                let hash = hasher.finalize();
                
                // Compare signatures
                if hash[..8] != solo_sig {
                    // Behavior changed! first affects second
                    self.dependencies.entry(first).or_default().insert(second);
                    self.prereqs.entry(second).or_default().insert(first);
                }
            }
        }
    }
    
    /// Get suggested mutation action for an IOCTL based on its last error
    pub fn suggest_mutation(&self, ioctl: u32, last_error: u32) -> MutationAction {
        NtStatusHint::from(last_error).suggest_action()
    }
    
    /// Get suggested input size
    pub fn suggested_size(&self, ioctl: u32) -> usize {
        if let Some(c) = self.constraints.get(&ioctl) {
            // Prefer success sizes
            if !c.success_sizes.is_empty() {
                return c.success_sizes[c.success_sizes.len() / 2]; // median-ish
            }
            // Or use learned minimum
            if let Some(min) = c.min_size_learned {
                return min;
            }
        }
        64 // Default
    }
    
    /// Get a promising input to mutate from
    pub fn get_promising_input(&self, ioctl: u32) -> Option<&Vec<u8>> {
        self.constraints.get(&ioctl)
            .and_then(|c| c.promising_inputs.first())
    }
    
    /// Get IOCTLs that should be called before this one
    pub fn get_prereqs(&self, ioctl: u32) -> Vec<u32> {
        self.prereqs.get(&ioctl)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }
    
    /// Get IOCTLs affected by this one
    pub fn get_affects(&self, ioctl: u32) -> Vec<u32> {
        self.dependencies.get(&ioctl)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }
    
    /// Get the most common error hint for an IOCTL (useful for targeted mutation)
    pub fn get_hint_for_ioctl(&self, ioctl: u32) -> NtStatusHint {
        if let Some(constraint) = self.constraints.get(&ioctl) {
            // Find the most common non-success error
            if let Some((status, _)) = constraint.error_counts.iter()
                .filter(|(&s, _)| s != 0) // Exclude STATUS_SUCCESS
                .max_by_key(|(_, &count)| count) 
            {
                return NtStatusHint::from(*status);
            }
        }
        NtStatusHint::Other(0xFFFFFFFF) // Default - unknown status
    }

    /// Generate a smart input using learned constraints
    pub fn generate_smart_input(&self, ioctl: u32, rng: &mut impl rand::Rng) -> Vec<u8> {
        let size = self.suggested_size(ioctl);
        
        // Start with promising input or zeros
        let mut input = if let Some(base) = self.get_promising_input(ioctl) {
            let mut v = base.clone();
            v.resize(size, 0);
            v
        } else {
            vec![0u8; size]
        };
        
        // Apply some mutations
        let num_mutations = rng.gen_range(1..=3);
        for _ in 0..num_mutations {
            if input.is_empty() { break; }
            let idx = rng.gen_range(0..input.len());
            input[idx] = rng.gen();
        }
        
        input
    }
    
    /// Generate a single prerequisite + target pair for stateful fuzzing
    /// Returns: Some((prereq_ioctl, prereq_data, target_ioctl)) if we have learned dependencies
    pub fn generate_dependent_sequence(&self, rng: &mut impl rand::Rng) -> Option<(u32, Vec<u8>, u32)> {
        use rand::seq::IteratorRandom;
        
        // Find IOCTLs that have prerequisites
        let ioctls_with_prereqs: Vec<_> = self.prereqs.iter()
            .filter(|(_, prereqs)| !prereqs.is_empty())
            .collect();
        
        if ioctls_with_prereqs.is_empty() {
            return None;
        }
        
        // Pick a random target
        let (target, prereqs) = ioctls_with_prereqs.iter().choose(rng)?;
        let prereq = prereqs.iter().choose(rng)?;
        
        let prereq_data = self.generate_smart_input(*prereq, rng);
        Some((*prereq, prereq_data, **target))
    }
    
    /// Generate a full sequence that respects dependencies (for use by other tools)
    pub fn generate_full_sequence(&self, target: u32, rng: &mut impl rand::Rng) -> Vec<(u32, Vec<u8>)> {
        let mut seq = Vec::new();
        
        // Call prerequisites first
        for prereq in self.get_prereqs(target) {
            seq.push((prereq, self.generate_smart_input(prereq, rng)));
        }
        
        // Call target
        seq.push((target, self.generate_smart_input(target, rng)));
        
        // Call affected IOCTLs (might trigger stateful bugs)
        for affected in self.get_affects(target) {
            seq.push((affected, self.generate_smart_input(affected, rng)));
        }
        
        seq
    }
    
    /// Get stats
    pub fn stats(&self) -> (usize, usize, usize) {
        let total_deps: usize = self.dependencies.values().map(|s| s.len()).sum();
        (self.known_crashes.len(), self.observation_count as usize, total_deps)
    }
    
    /// Print summary
    pub fn print_summary(&self) {
        let (crashes, obs, deps) = self.stats();
        println!("\n[SmartDedup] {} unique crashes | {} observations | {} dependencies", crashes, obs, deps);
        
        // Show IOCTLs with dependencies
        for (ioctl, affects) in &self.dependencies {
            if !affects.is_empty() {
                print!("  0x{:08X} affects: ", ioctl);
                for a in affects {
                    print!("0x{:08X} ", a);
                }
                println!();
            }
        }
    }
    
    /// Save learned data to file
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let data = bincode::serialize(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, data)
    }
    
    /// Load learned data from file
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        bincode::deserialize(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl Default for SmartDedup {
    fn default() -> Self {
        Self::new()
    }
}

/// Saved individual from genetic algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedIndividual {
    pub ioctl: u32,
    pub data: Vec<u8>,
    pub pattern: String,
    pub fitness: f64,
    pub generation: u32,
    pub error_code: u32,
}

/// Combined fuzzer state - ALL learning in ONE file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerState {
    /// Version for compatibility
    pub version: u32,
    /// SmartDedup learning
    pub smart_dedup: SmartDedup,
    /// Genetic population
    pub population: Vec<SavedIndividual>,
    /// Interesting inputs
    pub interesting_inputs: Vec<SavedIndividual>,
    /// Total iterations completed
    pub iterations: u64,
    /// Generation counter
    pub generation: u32,
}

impl FuzzerState {
    pub fn new() -> Self {
        Self {
            version: 1,
            smart_dedup: SmartDedup::new(),
            population: Vec::new(),
            interesting_inputs: Vec::new(),
            iterations: 0,
            generation: 0,
        }
    }
    
    /// Save all state to file
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let data = bincode::serialize(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, data)
    }
    
    /// Load state from file
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let data = std::fs::read(path)?;
        bincode::deserialize(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
    
    /// Get stats summary
    pub fn stats(&self) -> String {
        let (crashes, obs, deps) = self.smart_dedup.stats();
        format!("{} iter | {} pop | {} interesting | {} crashes | {} obs | {} deps",
            self.iterations, self.population.len(), self.interesting_inputs.len(),
            crashes, obs, deps)
    }
}

impl Default for FuzzerState {
    fn default() -> Self {
        Self::new()
    }
}