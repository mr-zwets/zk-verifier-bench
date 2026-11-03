// G1 probe: decode the published ZisK v1.4.0-alpha fixtures, verify them with the stock no_std
// verifier, and check that single-word changes in each proof region are rejected.
use std::time::Instant;
use zisk_verifier::{decode_saved, vadcop_vk, verify, verify_saved, VerifyError};

const FIX: &[(&str, &str, &str, bool)] = &[
    ("poseidon2 leaf", "tests/fixtures/poseidon2_leaf.bin", "Poseidon2", false),
    ("poseidon2 compressed", "tests/fixtures/poseidon2_compressed.bin", "Poseidon2", true),
    ("poseidon1 leaf", "tests/fixtures/poseidon1_leaf.bin", "Poseidon1", false),
    ("poseidon1 compressed", "tests/fixtures/poseidon1_compressed.bin", "Poseidon1", true),
    ("blake3 leaf", "tests/fixtures/blake3_leaf.bin", "blake3", false),
    ("blake3 compressed", "tests/fixtures/blake3_compressed.bin", "blake3", true),
];

// Region start offsets (words into the STARK body) for the Poseidon2 FRI leaf, from layout.py.
const P2_FINAL_REGIONS: &[(&str, usize)] = &[
    ("roots", 0), ("evals", 12), ("const_vals", 402), ("const_paths", 2940), ("const_lastlevel", 8124),
    ("cm1_vals", 8188), ("cm1_paths", 10780), ("cm2_vals", 16028), ("cm3_vals", 21924),
    ("cm3_lastlevel", 28242), ("fri_roots", 28306), ("fri1_vals", 28322), ("fri1_paths", 30914),
    ("fri4_vals", 44066), ("fri4_lastlevel", 46010), ("final_pol", 46074), ("nonce", 46170),
];

fn main() {
    for &(name, path, hash, compressed) in FIX {
        let bytes = std::fs::read(path).unwrap();
        let saved = decode_saved(&bytes).unwrap();
        let p = &saved.proof;
        let key = vadcop_vk(hash, compressed).unwrap();
        let t = Instant::now();
        let v = verify(p, &key);
        let dt = t.elapsed();
        println!("== {name}: file {} B, publics {}, stark body {} B, claimed_vk==release_vk {}, verify {:?} in {:?}",
            bytes.len(), p.public_values.len(), p.proof.len() * 8, saved.claimed_vadcop_vk == key, v.is_ok(), dt);
        let v = v.unwrap();
        println!("   program_vk {:?}", v.program_vk);
        println!("   outputs[0..4] {:?}  is_aggregate {:?}", &v.outputs[..4], v.is_aggregate);
        println!("   publics[0..6] {:?}", &p.public_values[..6]);
        assert!(verify_saved(&bytes, Some(&v.program_vk)).is_ok());
        // Rejection checks: publics (each slot), body regions, key.
        let mut rej = 0; let mut tot = 0;
        for i in 0..p.public_values.len() {
            let mut q = p.clone(); q.public_values[i] = (q.public_values[i] + 1) % 0xFFFF_FFFF_0000_0001;
            tot += 1; if verify(&q, &key).is_err() { rej += 1 } else { println!("   !! public {i} change accepted"); }
        }
        let regions: Vec<(String, usize)> = if hash == "Poseidon2" && !compressed {
            P2_FINAL_REGIONS.iter().map(|&(n, o)| (n.to_string(), o)).collect()
        } else {
            (0..16).map(|k| (format!("word@{}/16", k), k * p.proof.len() / 16)).collect()
        };
        for (rn, off) in &regions {
            for d in [0usize, 1, 7] {
                let o = off + d; if o >= p.proof.len() { continue; }
                let mut q = p.clone(); q.proof[o] ^= 1;
                tot += 1;
                match verify(&q, &key) { Err(VerifyError::InvalidProof) => rej += 1, other => println!("   !! {rn}+{d} -> {:?}", other.map(|_| "ACCEPTED")) }
            }
        }
        let mut k2 = key; k2[3] ^= 1; tot += 1; if verify(p, &k2).is_err() { rej += 1 }
        println!("   rejection checks: {rej}/{tot} rejected");
    }
}
