use std::fs;
use std::io::{self, Write};
use std::time::Instant;

// NTT (Number Theoretic Transform) Implementation

struct NTT {
    n: usize,
    q: i64,
    // root: i64,      // Not strictly necessary
    // root_inv: i64,  // Not strictly necessary
    omega: Vec<i64>,
    omega_inv: Vec<i64>,
}

impl NTT {
    fn new(n: usize, q: i64) -> Self {
        let root = Self::find_primitive_root(n, q);
        let root_inv = Self::mod_inverse(root, q);
        
        let mut omega = vec![0i64; n];
        let mut omega_inv = vec![0i64; n];
        
        omega[0] = 1;
        omega_inv[0] = 1;
        
        for i in 1..n {
            omega[i] = Self::mod_mul(omega[i - 1], root, q);
            omega_inv[i] = Self::mod_mul(omega_inv[i - 1], root_inv, q);
        }
        
        NTT {
            n,
            q,
            // root,
            // root_inv,
            omega,
            omega_inv,
        }
    }
    
    fn forward(&self, poly: &[i64]) -> Vec<i64> {
        let mut a = poly.to_vec();
        self.transform(&mut a, &self.omega);
        a
    }
    
    fn inverse(&self, poly: &[i64]) -> Vec<i64> {
        let mut a = poly.to_vec();
        self.transform(&mut a, &self.omega_inv);
        
        let n_inv = Self::mod_inverse(self.n as i64, self.q);
        for i in 0..self.n {
            a[i] = Self::mod_mul(a[i], n_inv, self.q);
        }
        a
    }
    
    fn transform(&self, a: &mut [i64], omega: &[i64]) {
        let n = self.n;
        let mut j = 0;
        
        // bit-reversal permutation
        for i in 1..n {
            let mut bit = n >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;
            
            if i < j {
                a.swap(i, j);
            }
        }
        
        // cooley-Tukey NTT
        let mut len = 2;
        while len <= n {
            let step = n / len;
            for i in (0..n).step_by(len) {
                let mut k = 0;
                for j in 0..len / 2 {
                    let u = a[i + j];
                    let v = Self::mod_mul(a[i + j + len / 2], omega[k], self.q);
                    
                    a[i + j] = Self::mod_add(u, v, self.q);
                    a[i + j + len / 2] = Self::mod_sub(u, v, self.q);
                    
                    k += step;
                }
            }
            len *= 2;
        }
    }
    
    fn multiply(&self, a_ntt: &[i64], b_ntt: &[i64]) -> Vec<i64> {
        let mut result = vec![0i64; self.n];
        for i in 0..self.n {
            result[i] = Self::mod_mul(a_ntt[i], b_ntt[i], self.q);
        }
        result
    }
    
    fn mod_add(a: i64, b: i64, q: i64) -> i64 {
        let mut result = (a + b) % q;
        if result < 0 {
            result += q;
        }
        result
    }
    
    fn mod_sub(a: i64, b: i64, q: i64) -> i64 {
        let mut result = (a - b) % q;
        if result < 0 {
            result += q;
        }
        result
    }
    
    fn mod_mul(a: i64, b: i64, q: i64) -> i64 {
        let result = ((a as i128 * b as i128) % q as i128) as i64;
        if result < 0 {
            result + q
        } else {
            result
        }
    }
    
    fn mod_pow(mut base: i64, mut exp: i64, q: i64) -> i64 {
        let mut result = 1i64;
        base %= q;
        
        while exp > 0 {
            if exp & 1 == 1 {
                result = Self::mod_mul(result, base, q);
            }
            base = Self::mod_mul(base, base, q);
            exp >>= 1;
        }
        result
    }
    
    fn mod_inverse(a: i64, q: i64) -> i64 {
        let mut t = 0i64;
        let mut newt = 1i64;
        let mut r = q;
        let mut newr = a;
        
        while newr != 0 {
            let quotient = r / newr;
            let temp_t = t;
            t = newt;
            newt = temp_t - quotient * newt;
            
            let temp_r = r;
            r = newr;
            newr = temp_r - quotient * newr;
        }
        
        if t < 0 {
            t += q;
        }
        t
    }
    
    fn find_primitive_root(n: usize, q: i64) -> i64 {
        let g = 11i64;
        let exp = (q - 1) / (n as i64);
        Self::mod_pow(g, exp, q)
    }
}

// RLWE Implementation

struct RLWEParams {
    n: usize,
    q: i64,
    sigma: f64,
    ntt: NTT,
}

impl RLWEParams {
    fn new() -> Self {
        let n = 1024;
        let q = 3329;
        let sigma = 2.0;
        
        RLWEParams {
            n,
            q,
            sigma,
            ntt: NTT::new(n, q),
        }
    }
    
    fn to_string(&self) -> String {
        format!("{}:{}:{}", self.n, self.q, self.sigma)
    }
    
    fn from_string(s: &str) -> Self {
        let parts: Vec<&str> = s.split(':').collect();
        let n: usize = parts[0].parse().unwrap();
        let q: i64 = parts[1].parse().unwrap();
        let sigma: f64 = parts[2].parse().unwrap();
        
        RLWEParams {
            n,
            q,
            sigma,
            ntt: NTT::new(n, q),
        }
    }
}

struct KeyPair {
    public_key: Vec<i64>,
    secret_key: Vec<i64>,
}

impl KeyPair {
    fn generate(params: &RLWEParams) -> Self {
        let mut seed = 123456789u64;
        let mut lcg = || -> i64 {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            ((seed / 65536) % 32768) as i64
        };
        
        let secret_key: Vec<i64> = (0..params.n)
            .map(|_| (lcg() % 3) - 1)
            .collect();
        
        let a: Vec<i64> = (0..params.n)
            .map(|_| lcg() % params.q)
            .collect();
        
        let e = sample_error(params.n, params.sigma, params.q, &mut seed);
        
        let a_ntt = params.ntt.forward(&a);
        let s_ntt = params.ntt.forward(&secret_key);
        let as_ntt = params.ntt.multiply(&a_ntt, &s_ntt);
        let as_poly = params.ntt.inverse(&as_ntt);
        
        let mut public_key = vec![0i64; params.n];
        for i in 0..params.n {
            public_key[i] = NTT::mod_add(as_poly[i], e[i], params.q);
        }
        
        let mut full_pubkey = a;
        full_pubkey.extend(public_key);
        
        KeyPair {
            public_key: full_pubkey,
            secret_key,
        }
    }
}

fn encrypt(message: &str, public_key: &[i64], params: &RLWEParams) -> (Vec<i64>, Vec<i64>) {
    let mut seed = 987654321u64;
    let mut lcg = || -> i64 {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        ((seed / 65536) % 32768) as i64
    };
    
    let a = &public_key[0..params.n];
    let p = &public_key[params.n..];
    
    let m = encode_message(message, params.n, params.q);
    
    let r: Vec<i64> = (0..params.n)
        .map(|_| (lcg() % 3) - 1)
        .collect();
    
    let e1 = sample_error(params.n, params.sigma, params.q, &mut seed);
    let e2 = sample_error(params.n, params.sigma, params.q, &mut seed);
    
    let a_ntt = params.ntt.forward(a);
    let r_ntt = params.ntt.forward(&r);
    let ar_ntt = params.ntt.multiply(&a_ntt, &r_ntt);
    let ar = params.ntt.inverse(&ar_ntt);
    
    let mut c0 = vec![0i64; params.n];
    for i in 0..params.n {
        c0[i] = NTT::mod_add(ar[i], e1[i], params.q);
    }
    
    let p_ntt = params.ntt.forward(p);
    let pr_ntt = params.ntt.multiply(&p_ntt, &r_ntt);
    let pr = params.ntt.inverse(&pr_ntt);
    
    let mut c1 = vec![0i64; params.n];
    for i in 0..params.n {
        let temp = NTT::mod_add(pr[i], e2[i], params.q);
        c1[i] = NTT::mod_add(temp, m[i], params.q);
    }
    
    (c0, c1)
}

fn decrypt(ciphertext: &(Vec<i64>, Vec<i64>), secret_key: &[i64], params: &RLWEParams) -> String {
    let (c0, c1) = ciphertext;
    
    let c0_ntt = params.ntt.forward(c0);
    let s_ntt = params.ntt.forward(secret_key);
    let c0s_ntt = params.ntt.multiply(&c0_ntt, &s_ntt);
    let c0s = params.ntt.inverse(&c0s_ntt);
    
    let mut m_noisy = vec![0i64; params.n];
    for i in 0..params.n {
        m_noisy[i] = NTT::mod_sub(c1[i], c0s[i], params.q);
    }
    
    decode_message(&m_noisy, params.q)
}

fn encode_message(message: &str, n: usize, q: i64) -> Vec<i64> {
    let mut poly = vec![0i64; n];
    let half_q = q / 2;
    
    let bytes = message.as_bytes();
    let mut coeff_idx = 0;

    for &byte in bytes {
        for bit_pos in 0..8 {
            if coeff_idx >= n { break; }
            let bit = (byte >> bit_pos) & 1;
            if bit == 1 {
                poly[coeff_idx] = half_q;
            } else {
                poly[coeff_idx] = 0;
            }
            coeff_idx += 1;
        }
    }
    
    poly
}

fn decode_message(poly: &[i64], q: i64) -> String {
    let mut bytes = Vec::new();
    let q_fourth = q / 4;
    let three_q_fourth = 3 * q / 4;
    
    // We process coeffs in chunks of 8 to rebuild bytes
    for chunk in poly.chunks(8) {
        if chunk.len() < 8 { break; } // Ignore incomplete bytes
        
        let mut byte: u8 = 0;
        let mut all_zeros = true;

        for (i, &coeff) in chunk.iter().enumerate() {
            // threshold decoding: is coeff closer to 0 or Q/2?
            // if it's between Q/4 and 3Q/4, it's a 1.
            if coeff > q_fourth && coeff < three_q_fourth {
                byte |= 1 << i;
                all_zeros = false;
            }
            // else it's 0 (closer to 0 or Q)
        }

        // null terminator check
        if byte == 0 && all_zeros {
             // In a more real stream we might need length encoding, 
             // but for this implementation, stop at null char
             break;
        }
        bytes.push(byte);
    }
    
    String::from_utf8_lossy(&bytes).to_string()
}

fn sample_error(n: usize, sigma: f64, q: i64, seed: &mut u64) -> Vec<i64> {
    let mut error = vec![0i64; n];
    
    for i in 0..n {
        *seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let u1 = (*seed as f64) / (u64::MAX as f64);
        
        *seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        let u2 = (*seed as f64) / (u64::MAX as f64);
        
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        let sample = (z * sigma).round() as i64;
        
        // Handle negative error values correctly modulo q
        error[i] = sample % q;
        if error[i] < 0 { error[i] += q; }
    }
    
    error
}

// Main Menu and File I/O

fn main() {
    loop {
        println!("\n=== RLWE Encryption System ===");
        println!("1. Generate Keys");
        println!("2. Encrypt");
        println!("3. Decrypt");
        println!("4. Exit");
        print!("\nSelect option: ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();

        match choice.trim() {
            "1" => generate_keys(),
            "2" => encrypt_message(),
            "3" => decrypt_message(),
            "4" => {
                println!("Exiting...");
                break;
            }
            _ => println!("Invalid option. Please try again."),
        }
    }
}

fn generate_keys() {
    println!("\n--- Key Generation ---");
    let start = Instant::now();
    
    let params = RLWEParams::new();
    let keypair = KeyPair::generate(&params);
    
    let duration = start.elapsed();
    
    let pubkey_data = format!("{}\n{}", 
        keypair.public_key.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","),
        params.to_string()
    );
    fs::write("pubkey.txt", pubkey_data).expect("Failed to write public key");
    
    let privkey_data = format!("{}\n{}", 
        keypair.secret_key.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","),
        params.to_string()
    );
    fs::write("privkey.txt", privkey_data).expect("Failed to write private key");
    
    println!("✓ Keys generated successfully!");
    println!("  Public key saved to: pubkey.txt");
    println!("  Private key saved to: privkey.txt");
    println!("Time taken: {:.10} ms", duration.as_secs_f64() * 1000.0);
}

fn encrypt_message() {
    println!("\n--- Encryption ---");
    
    let plaintext = match fs::read_to_string("plaintext.txt") {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            println!("✗ Error: plaintext.txt not found");
            println!("  Please create plaintext.txt with your message");
            return;
        }
    };
    
    // Check message length limitation due to binary encoding
    if plaintext.len() > 64 {
        println!("✗ Error: Message too long.");
        println!("  Max capacity is 64 characters (512 coefficients / 8 bits).");
        return;
    }
    
    let pubkey_content = match fs::read_to_string("pubkey.txt") {
        Ok(content) => content,
        Err(_) => {
            println!("✗ Error: pubkey.txt not found");
            println!("  Please generate keys first (option 1)");
            return;
        }
    };
    
    let (pubkey, params) = parse_key_file(&pubkey_content);
    
    println!("  Plaintext: \"{}\"", plaintext);
    let start = Instant::now();
    
    let ciphertext = encrypt(&plaintext, &pubkey, &params);
    
    let duration = start.elapsed();
    
    let ct_data = format!("{}\n{}", 
        ciphertext.0.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","),
        ciphertext.1.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")
    );
    fs::write("ciphertext.txt", ct_data).expect("Failed to write ciphertext");
    
    println!("✓ Encryption successful!");
    println!("  Ciphertext saved to: ciphertext.txt");
    println!("Time taken: {:.10} ms", duration.as_secs_f64() * 1000.0);
}

fn decrypt_message() {
    println!("\n--- Decryption ---");
    
    let ct_content = match fs::read_to_string("ciphertext.txt") {
        Ok(content) => content,
        Err(_) => {
            println!("✗ Error: ciphertext.txt not found");
            println!("  Please encrypt a message first (option 2)");
            return;
        }
    };
    
    let privkey_content = match fs::read_to_string("privkey.txt") {
        Ok(content) => content,
        Err(_) => {
            println!("✗ Error: privkey.txt not found");
            println!("  Please generate keys first (option 1)");
            return;
        }
    };
    
    let (privkey, params) = parse_key_file(&privkey_content);
    let ciphertext = parse_ciphertext(&ct_content);
    
    let start = Instant::now();
    
    let plaintext = decrypt(&ciphertext, &privkey, &params);
    
    let duration = start.elapsed();
    
    println!("✓ Decryption successful!");
    println!("  Plaintext: \"{}\"", plaintext);
    println!("Time taken: {:.10} ms", duration.as_secs_f64() * 1000.0);
}

fn parse_key_file(content: &str) -> (Vec<i64>, RLWEParams) {
    let lines: Vec<&str> = content.lines().collect();
    let key: Vec<i64> = lines[0].split(',').map(|s| s.parse().unwrap()).collect();
    let params = RLWEParams::from_string(lines[1]);
    (key, params)
}

fn parse_ciphertext(content: &str) -> (Vec<i64>, Vec<i64>) {
    let lines: Vec<&str> = content.lines().collect();
    let c0: Vec<i64> = lines[0].split(',').map(|s| s.parse().unwrap()).collect();
    let c1: Vec<i64> = lines[1].split(',').map(|s| s.parse().unwrap()).collect();
    (c0, c1)
}