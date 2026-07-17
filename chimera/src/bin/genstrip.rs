//! genstrip — read 16 blocks × 32 luma coeffs (whitespace ints) from stdin, encode
//! one strip with the literal kernel `video::wht::strip`, print the hex. Used by the
//! chroma-AC RE harness to validate the wire decoder against ground-truth kernel bytes.
use std::io::Read;

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let v: Vec<i32> = s.split_whitespace().map(|t| t.parse().unwrap()).collect();
    assert_eq!(v.len(), 16 * 32, "need 16*32 coeffs, got {}", v.len());
    let mut blocks = [[0i32; 32]; 16];
    for k in 0..16 {
        for i in 0..32 {
            blocks[k][i] = v[k * 32 + i];
        }
    }
    let strip = vino_chimera::kvino::strip(&blocks, 0, 0).expect("strip");
    println!("{}", strip.iter().map(|b| format!("{b:02x}")).collect::<String>());
}
