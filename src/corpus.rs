//! Corpus Management Module
//!
//! Manages seed inputs and interesting test cases.
//! Provides corpus mutation scheduling and minimization.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use sha2::{Sha256, Digest};

/// A single corpus entry
#[derive(Clone)]
pub struct CorpusEntry {
    /// Raw input data
    pub data: Vec<u8>,
    /// SHA256 hash of data
    pub hash: String,
    /// Number of times this entry has been selected
    pub exec_count: u64,
    /// Coverage bitmap hash when this was added
    pub coverage_hash: u64,
    /// New edges this entry discovered
    pub new_edges: u32,
    /// Execution time in microseconds
    pub exec_time_us: u64,
    /// Target IOCTL code
    pub ioctl: u32,
    /// Whether this entry caused interesting behavior
    pub is_interesting: bool,
}

impl CorpusEntry {
    pub fn new(data: Vec<u8>, ioctl: u32) -> Self {
        let hash = Self::compute_hash(&data);
        Self {
            data,
            hash,
            exec_count: 0,
            coverage_hash: 0,
            new_edges: 0,
            exec_time_us: 0,
            ioctl,
            is_interesting: false,
        }
    }
    
    fn compute_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }
    
    /// Calculate "energy" for scheduling (AFL-style)
    pub fn energy(&self) -> u64 {
        let base = 100u64;
        
        // Favor entries with more new edges
        let edge_factor = 1 + self.new_edges as u64;
        
        // Penalize over-fuzzed entries
        let exec_penalty = 1 + (self.exec_count / 100);
        
        // Favor fast executions
        let speed_factor = if self.exec_time_us > 0 {
            1000000 / self.exec_time_us.max(1)
        } else {
            100
        };
        
        (base * edge_factor * speed_factor) / exec_penalty
    }
}

/// Corpus manager
pub struct Corpus {
    /// All corpus entries
    entries: Vec<CorpusEntry>,
    /// Map of hash -> index for deduplication
    hash_index: HashMap<String, usize>,
    /// Directory for persistent corpus
    corpus_dir: Option<PathBuf>,
    /// Maximum corpus size
    max_size: usize,
    /// Favored entries for fuzzing
    favored: HashSet<usize>,
}

impl Corpus {
    pub fn new(corpus_dir: Option<PathBuf>, max_size: usize) -> Self {
        let mut corpus = Self {
            entries: Vec::new(),
            hash_index: HashMap::new(),
            corpus_dir: corpus_dir.clone(),
            max_size,
            favored: HashSet::new(),
        };
        
        // Load existing corpus from disk
        if let Some(dir) = corpus_dir {
            corpus.load_from_dir(&dir);
        }
        
        corpus
    }
    
    /// Load corpus entries from directory
    fn load_from_dir(&mut self, dir: &PathBuf) {
        if !dir.exists() {
            return;
        }
        
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(data) = fs::read(entry.path()) {
                    // Try to extract IOCTL from filename (format: ioctl_XXXXXXXX_hash)
                    let filename = entry.file_name();
                    let name = filename.to_string_lossy();
                    let ioctl = if name.starts_with("ioctl_") {
                        u32::from_str_radix(&name[6..14], 16).unwrap_or(0)
                    } else {
                        0
                    };
                    
                    let entry = CorpusEntry::new(data, ioctl);
                    if !self.hash_index.contains_key(&entry.hash) {
                        let idx = self.entries.len();
                        self.hash_index.insert(entry.hash.clone(), idx);
                        self.entries.push(entry);
                    }
                }
            }
        }
    }
    
    /// Add entry to corpus if it's new
    pub fn add(&mut self, mut entry: CorpusEntry) -> bool {
        // Check for duplicate
        if self.hash_index.contains_key(&entry.hash) {
            return false;
        }
        
        // Add to corpus
        let idx = self.entries.len();
        self.hash_index.insert(entry.hash.clone(), idx);
        
        // Save to disk
        if let Some(ref dir) = self.corpus_dir {
            let _ = fs::create_dir_all(dir);
            let filename = format!("ioctl_{:08x}_{:.16}", entry.ioctl, entry.hash);
            let path = dir.join(filename);
            let _ = fs::write(path, &entry.data);
        }
        
        // If entry has new coverage, mark as favored
        if entry.new_edges > 0 {
            self.favored.insert(idx);
            entry.is_interesting = true;
        }
        
        self.entries.push(entry);
        
        // Trim if over max size
        if self.entries.len() > self.max_size {
            self.cull();
        }
        
        true
    }
    
    /// Select next entry for fuzzing (power scheduling)
    pub fn select(&mut self) -> Option<&mut CorpusEntry> {
        if self.entries.is_empty() {
            return None;
        }
        
        // Calculate total energy
        let total_energy: u64 = self.entries.iter().map(|e| e.energy()).sum();
        if total_energy == 0 {
            return Some(&mut self.entries[0]);
        }
        
        // Weighted random selection
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let target = rng.gen_range(0..total_energy);
        
        let mut cumulative = 0u64;
        let mut selected_idx = 0;
        
        for (idx, entry) in self.entries.iter().enumerate() {
            cumulative += entry.energy();
            if cumulative >= target {
                selected_idx = idx;
                break;
            }
        }
        
        // Update exec count and return mutable reference
        self.entries[selected_idx].exec_count += 1;
        Some(&mut self.entries[selected_idx])
    }
    
    /// Get a random entry
    pub fn random(&self) -> Option<&CorpusEntry> {
        if self.entries.is_empty() {
            return None;
        }
        use rand::Rng;
        let idx = rand::thread_rng().gen_range(0..self.entries.len());
        Some(&self.entries[idx])
    }
    
    /// Remove low-value entries when corpus is too large
    fn cull(&mut self) {
        // Sort by energy and keep top entries
        let mut indexed: Vec<(usize, u64)> = self.entries
            .iter()
            .enumerate()
            .map(|(i, e)| (i, e.energy()))
            .collect();
        
        indexed.sort_by(|a, b| b.1.cmp(&a.1));
        
        let keep: HashSet<usize> = indexed
            .iter()
            .take(self.max_size / 2)
            .map(|&(i, _)| i)
            .collect();
        
        // Also keep all favored entries
        let keep: HashSet<usize> = keep.union(&self.favored).copied().collect();
        
        // Rebuild entries vector
        let mut new_entries = Vec::new();
        let mut new_hash_index = HashMap::new();
        
        for (i, entry) in self.entries.drain(..).enumerate() {
            if keep.contains(&i) {
                let new_idx = new_entries.len();
                new_hash_index.insert(entry.hash.clone(), new_idx);
                new_entries.push(entry);
            }
        }
        
        self.entries = new_entries;
        self.hash_index = new_hash_index;
        
        // Rebuild favored set with new indices
        self.favored = self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.is_interesting)
            .map(|(i, _)| i)
            .collect();
    }
    
    /// Get corpus size
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    /// Check if corpus is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    
    /// Get total executions
    pub fn total_execs(&self) -> u64 {
        self.entries.iter().map(|e| e.exec_count).sum()
    }
    
    /// Generate initial corpus for an IOCTL
    pub fn generate_initial(ioctl: u32) -> Vec<CorpusEntry> {
        let mut entries = Vec::new();
        
        // Empty input
        entries.push(CorpusEntry::new(vec![], ioctl));
        
        // Various sizes including LARGE buffers for stack overflows
        // HEVD stack overflow triggers at ~2048+ bytes
        for size in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 3000, 4096] {
            // Zero-filled
            entries.push(CorpusEntry::new(vec![0u8; size], ioctl));
            
            // 0xFF-filled  
            entries.push(CorpusEntry::new(vec![0xFFu8; size], ioctl));
            
            // 'A'-filled (classic overflow pattern)
            entries.push(CorpusEntry::new(vec![0x41u8; size], ioctl));
            
            // Pattern
            entries.push(CorpusEntry::new(
                (0..size).map(|i| (i & 0xFF) as u8).collect(),
                ioctl
            ));
        }
        
        // Standard IOCTL input structures
        // Many IOCTLs expect a size prefix
        let mut with_size = vec![0u8; 36];
        with_size[0..4].copy_from_slice(&32u32.to_le_bytes());
        entries.push(CorpusEntry::new(with_size, ioctl));
        
        // Input with "magic" header
        let magics = [
            b"AAAA".to_vec(),
            vec![0x00, 0x00, 0x00, 0x00],
            vec![0x01, 0x00, 0x00, 0x00],
        ];
        
        for magic in magics {
            let mut data = magic.clone();
            data.extend(vec![0u8; 60]);
            entries.push(CorpusEntry::new(data, ioctl));
        }
        
        entries
    }
}

impl Default for Corpus {
    fn default() -> Self {
        Self::new(None, 10000)
    }
}
