//! Data-gathering harness for the overlapped-capture change: runs N rounds of
//! sequential (RGB then IR) and N rounds of concurrent (RGB+IR on two threads)
//! capture on a given camera pair, and reports per-stream timing and mean
//! brightness distributions. The brightness columns answer the open question
//! from review: does concurrent load silently dim a stream?
//!
//! Usage: cargo run --release --example capture_bench -- <rgb_dev> <ir_dev> [rounds]

fn mean(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    data.iter().map(|&b| b as u64).sum::<u64>() as f32 / data.len() as f32
}

struct Stat {
    label: &'static str,
    vals: Vec<f32>,
}
impl Stat {
    fn new(label: &'static str) -> Self {
        Self {
            label,
            vals: Vec::new(),
        }
    }
    fn push(&mut self, v: f32) {
        self.vals.push(v);
    }
    fn report(&self) {
        if self.vals.is_empty() {
            println!("  {:<22} (no data)", self.label);
            return;
        }
        let n = self.vals.len() as f32;
        let mean = self.vals.iter().sum::<f32>() / n;
        let min = self.vals.iter().cloned().fold(f32::INFINITY, f32::min);
        let max = self.vals.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let var = self.vals.iter().map(|v| (v - mean).powi(2)).sum::<f32>() / n;
        println!(
            "  {:<22} mean {:8.1}  min {:8.1}  max {:8.1}  sd {:7.1}  (n={})",
            self.label,
            mean,
            min,
            max,
            var.sqrt(),
            self.vals.len()
        );
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let rgb_dev = args.next().unwrap_or_else(|| "/dev/video0".into());
    let ir_dev = args.next().unwrap_or_else(|| "/dev/video2".into());
    let rounds: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(10);
    println!("capture_bench: rgb={rgb_dev} ir={ir_dev} rounds={rounds}\n");

    let (mut seq_total, mut seq_rgb_b, mut seq_ir_b) = (
        Stat::new("seq total ms"),
        Stat::new("seq rgb mean bright"),
        Stat::new("seq ir mean bright"),
    );
    for _ in 0..rounds {
        let t0 = std::time::Instant::now();
        let rgb = irlume_camera::capture_rgb_denoised(&rgb_dev);
        let ir = irlume_camera::capture_ir(&ir_dev);
        seq_total.push(t0.elapsed().as_millis() as f32);
        if let Ok(r) = &rgb {
            seq_rgb_b.push(mean(&r.data));
        }
        if let Ok(i) = &ir {
            seq_ir_b.push(mean(&i.data));
        }
    }

    let (mut con_total, mut con_rgb_b, mut con_ir_b) = (
        Stat::new("conc total ms"),
        Stat::new("conc rgb mean bright"),
        Stat::new("conc ir mean bright"),
    );
    for _ in 0..rounds {
        let ir_dev2 = ir_dev.clone();
        let t0 = std::time::Instant::now();
        let (rgb, ir) = std::thread::scope(|s| {
            let ir_t = s.spawn(move || irlume_camera::capture_ir(&ir_dev2));
            let rgb = irlume_camera::capture_rgb_denoised(&rgb_dev);
            (rgb, ir_t.join().expect("ir thread"))
        });
        con_total.push(t0.elapsed().as_millis() as f32);
        if let Ok(r) = &rgb {
            con_rgb_b.push(mean(&r.data));
        }
        if let Ok(i) = &ir {
            con_ir_b.push(mean(&i.data));
        }
    }

    println!("Sequential (RGB then IR, denoised RGB as in production):");
    seq_total.report();
    seq_rgb_b.report();
    seq_ir_b.report();
    println!("\nConcurrent (RGB + IR overlapped, as shipped):");
    con_total.report();
    con_rgb_b.report();
    con_ir_b.report();
}
