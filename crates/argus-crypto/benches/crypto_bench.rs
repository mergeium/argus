use criterion::{Criterion, criterion_group, criterion_main};
use zeroize::Zeroizing;

use argus_core::config::CryptoConfig;
use argus_crypto::encryption;
use argus_crypto::hashing::PasswordHasherService;
use argus_crypto::hmac_util;
use argus_crypto::jwt::{self, JwtKeyManager};

/// Benchmark Argon2id password hashing with test-friendly (fast) parameters.
/// Production parameters are deliberately slow (~100ms); we use minimal params here
/// so CI can run this bench without excessive wallclock time.
fn bench_argon2id_hash(c: &mut Criterion) {
    let config = CryptoConfig {
        argon2_memory_kib: 1024,
        argon2_iterations: 1,
        argon2_parallelism: 1,
        ..CryptoConfig::default()
    };
    let hasher = PasswordHasherService::new(&config);

    c.bench_function("argon2id_hash", |b| {
        b.iter(|| {
            hasher
                .hash_password(Zeroizing::new("BenchmarkPassword123!".into()))
                .unwrap();
        });
    });
}

/// Benchmark Ed25519 JWT signing.
fn bench_ed25519_jwt_sign(c: &mut Criterion) {
    let km = JwtKeyManager::new().unwrap();
    let claims =
        jwt::build_access_token_claims("usr_bench", "https://auth.argus.dev", "tnt_bench", 3600);

    c.bench_function("ed25519_jwt_sign", |b| {
        b.iter(|| {
            km.sign(&claims).unwrap();
        });
    });
}

/// Benchmark Ed25519 JWT verification.
fn bench_ed25519_jwt_verify(c: &mut Criterion) {
    let km = JwtKeyManager::new().unwrap();
    let claims =
        jwt::build_access_token_claims("usr_bench", "https://auth.argus.dev", "tnt_bench", 3600);
    let token = km.sign(&claims).unwrap();

    c.bench_function("ed25519_jwt_verify", |b| {
        b.iter(|| {
            let _: jwt::AccessTokenClaims = km.verify(&token, "https://auth.argus.dev").unwrap();
        });
    });
}

/// Benchmark ChaCha20-Poly1305 encrypt + decrypt round-trip.
fn bench_chacha20poly1305(c: &mut Criterion) {
    let key = encryption::derive_key(b"bench-master-key-32-bytes-long!!", b"bench-context");
    let plaintext = vec![0xABu8; 256]; // 256-byte payload

    c.bench_function("chacha20poly1305_encrypt", |b| {
        b.iter(|| {
            encryption::encrypt(&key, &plaintext).unwrap();
        });
    });

    let ciphertext = encryption::encrypt(&key, &plaintext).unwrap();
    c.bench_function("chacha20poly1305_decrypt", |b| {
        b.iter(|| {
            encryption::decrypt(&key, &ciphertext).unwrap();
        });
    });
}

/// Benchmark HMAC-SHA256 signing.
fn bench_hmac_sha256_sign(c: &mut Criterion) {
    let key = b"bench-hmac-secret-key";
    let data = b"POST /webhook {\"event\": \"user.created\", \"ts\": 1700000000}";

    c.bench_function("hmac_sha256_sign", |b| {
        b.iter(|| {
            hmac_util::sign(key, data);
        });
    });
}

criterion_group!(
    benches,
    bench_argon2id_hash,
    bench_ed25519_jwt_sign,
    bench_ed25519_jwt_verify,
    bench_chacha20poly1305,
    bench_hmac_sha256_sign,
);
criterion_main!(benches);
