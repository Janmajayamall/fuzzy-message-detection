use std::{hash, ops::Mul};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
    traits::MultiscalarMul,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha3::{Digest, Sha3_256, Sha3_512};

struct TaggingKey(Vec<RistrettoPoint>);
struct DetectionKey(Vec<Scalar>);

#[derive(Debug, Clone)]
struct Key {
    gamma: usize,
    // xi_s
    secrets: Vec<Scalar>,
}

impl Key {
    pub fn generate<R: RngCore + CryptoRng>(gamma: usize, rng: &mut R) -> Self {
        let sks = (0..gamma)
            .map(|_| {
                let sk = Scalar::random(rng);
                sk
            })
            .collect();

        Self {
            gamma,
            secrets: sks,
        }
    }

    /// returns `DetectionKey` for a false positive rate of
    /// 2^-n. Contains a vector of secret keys upto `n` length.
    fn extract_key(&self, n_log: usize) -> DetectionKey {
        let sliced_sks = self.secrets.as_slice()[..n_log].to_vec();
        DetectionKey(sliced_sks)
    }

    /// returns `TaggingKey` for a false positive
    fn tagging_key(&self) -> TaggingKey {
        let generator = RISTRETTO_BASEPOINT_POINT;
        let hi_s = self.secrets.iter().map(|xi| generator * xi).collect();
        TaggingKey(hi_s)
    }
}

fn tag<R: RngCore + CryptoRng>(tagging_key: &TaggingKey, rng: &mut R) -> Tag {
    let r = Scalar::random(rng);
    let z = Scalar::random(rng);

    let g = RISTRETTO_BASEPOINT_POINT;
    let u = g * r;
    let w = g * z;

    let mut ciphertexts: Vec<u8> = vec![];

    tagging_key.0.iter().for_each(|hi| {
        // ki = Hash(u || hi^r || w)
        let mut hasher = Sha3_256::new();
        hasher.update(u.compress().to_bytes());
        hasher.update(w.compress().to_bytes());

        let hi_r = hi * r;
        hasher.update(hi_r.compress().to_bytes());

        let ki = hasher.finalize().as_slice()[0] & 1u8;

        // ci = ci ^ 1
        let ci = ki ^ 1;
        ciphertexts.push(ci);
    });

    // calculate m
    let mut m_bytes = vec![];
    m_bytes.extend_from_slice(u.compress().to_bytes().as_slice());
    m_bytes.extend_from_slice(&ciphertexts);
    let m = Scalar::hash_from_bytes::<Sha3_512>(&m_bytes);

    let r_inv = r.invert();
    let y = (z - m).mul(r_inv);

    Tag { y, u, ciphertexts }
}

#[derive(Debug, Clone)]
struct Tag {
    y: Scalar,
    u: RistrettoPoint,
    ciphertexts: Vec<u8>,
}

fn test(tag: Tag, detection_key: DetectionKey) -> bool {
    let g = RISTRETTO_BASEPOINT_POINT;
    let u = tag.u;

    // calculate m
    let mut m_bytes = vec![];
    m_bytes.extend_from_slice(u.compress().as_bytes());
    m_bytes.extend_from_slice(&tag.ciphertexts);
    let m = Scalar::hash_from_bytes::<Sha3_512>(&m_bytes);

    let w = RistrettoPoint::multiscalar_mul([m, tag.y], [g, u]);

    let mut count = 0;
    for (xi, ci) in detection_key.0.iter().zip(tag.ciphertexts.iter()) {
        let mut hash = Sha3_256::new();
        hash.update(u.compress().to_bytes());
        hash.update(w.compress().to_bytes());

        let ui_x = u.mul(xi);
        hash.update(ui_x.compress().to_bytes());

        let ki = hash.finalize().as_slice()[0] & 1u8;

        let bi = ki ^ ci;

        if bi == 0 {
            return false;
        }
        count += 1;
    }

    assert!(count == detection_key.0.len());

    true
}

fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key() {
        let gamma = 10;

        // defines false positive rate: 2^-n
        let n_log = 10usize;

        let mut rng = OsRng::default();

        let key = Key::generate(gamma, &mut rng);

        let detection_key = key.extract_key(n_log);
        assert!(detection_key.0.len() == n_log);

        let tagging_key = key.tagging_key();
        assert!(tagging_key.0.len() == gamma);
    }

    #[test]
    fn test_tag() {
        let gamma = 10;

        // defines false positive rate: 2^-n
        let n_log = 10usize;

        let mut rng = OsRng::default();

        let key = Key::generate(gamma, &mut rng);
        let detection_key = key.extract_key(n_log);
        let tagging_key = key.tagging_key();

        let tag = tag(&tagging_key, &mut rng);

        let key2 = Key::generate(gamma, &mut rng);
        let detection_key2 = key2.extract_key(n_log);

        let matches = test(tag, detection_key2);
        assert!(!matches);
    }
}
