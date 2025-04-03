use criterion::{black_box, criterion_group, criterion_main, Criterion, Bencher, BenchmarkId, Throughput};
use salsa20::{
    salsa20_encrypt, salsa20_decrypt, 
    salsa20_encrypt_k16, salsa20_decrypt_k16,
    Salsa20Rng
};
use rand_core::{RngCore, SeedableRng};

fn bench_salsa20_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("salsa20_encrypt");
    
    // Test with different message sizes
    for size in [64, 1024, 8192, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        let message = vec![0u8; *size];
        let k0 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let k1 = [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
            b.iter(|| salsa20_encrypt(black_box(&message), black_box(k0), black_box(k1)))
        });
    }
    
    group.finish();
}

fn bench_salsa20_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("salsa20_decrypt");
    
    // Test with different message sizes
    for size in [64, 1024, 8192, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        let message = vec![0u8; *size];
        let k0 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let k1 = [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        
        let ciphertext = salsa20_encrypt(&message, k0, k1);
        
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
            b.iter(|| salsa20_decrypt(black_box(&ciphertext), black_box(k0), black_box(k1)))
        });
    }
    
    group.finish();
}

fn bench_salsa20_encrypt_k16(c: &mut Criterion) {
    let mut group = c.benchmark_group("salsa20_encrypt_k16");
    
    // Test with different message sizes
    for size in [64, 1024, 8192, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        let message = vec![0u8; *size];
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
            b.iter(|| salsa20_encrypt_k16(black_box(&message), black_box(key)))
        });
    }
    
    group.finish();
}

fn bench_salsa20_decrypt_k16(c: &mut Criterion) {
    let mut group = c.benchmark_group("salsa20_decrypt_k16");
    
    // Test with different message sizes
    for size in [64, 1024, 8192, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        let message = vec![0u8; *size];
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        
        let ciphertext = salsa20_encrypt_k16(&message, key);
        
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
            b.iter(|| salsa20_decrypt_k16(black_box(&ciphertext), black_box(key)))
        });
    }
    
    group.finish();
}

fn bench_salsa20_rng(c: &mut Criterion) {
    let mut group = c.benchmark_group("salsa20_rng");
    
    // Test with different output sizes
    for size in [64, 1024, 8192, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        let seed = [0u8; 32];
        
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let mut rng = Salsa20Rng::from_seed(black_box(seed));
                let mut buffer = vec![0u8; *size];
                rng.fill_bytes(black_box(&mut buffer));
                buffer
            })
        });
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_salsa20_encrypt,
    bench_salsa20_decrypt,
    bench_salsa20_encrypt_k16,
    bench_salsa20_decrypt_k16,
    bench_salsa20_rng
);
criterion_main!(benches);