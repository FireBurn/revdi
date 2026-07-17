//! dumpframe — dump the literal kernel `solid_frame_ep08` output for a WxH solid fill to
//! stdout as hex (one transfer per line), so the EP08 record framing can be byte-compared
//! against DLM's real capture (captures/ep08-framing-20260628/).
//! Usage: dumpframe [W H R G B]   (default 2560 1440 200 30 30)
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let g = |i: usize, d: u32| a.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
    let (w, h) = (g(0, 2560) as u16, g(1, 1440) as u16);
    let (r, gr, b) = (g(2, 200) as u8, g(3, 30) as u8, g(4, 30) as u8);
    let (frames, _seq) = vino_chimera::kvino::solid_frame_ep08(w, h, (r, gr, b), 0).expect("frame");
    eprintln!("{} transfer(s), total {} B", frames.len(), frames.iter().map(|f| f.len()).sum::<usize>());
    for f in &frames {
        println!("{}", f.iter().map(|x| format!("{x:02x}")).collect::<String>());
    }
}
