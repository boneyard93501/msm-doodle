use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha3::Sha3_512;
use rand::rngs::OsRng;


fn hash_to_ristretto_point(data: &str) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha3_512>(data.as_bytes())
}


fn pedersen_commitment(value: Scalar, blinding: Scalar) -> RistrettoPoint {
    let h = hash_to_ristretto_point("H");
    value * RISTRETTO_BASEPOINT_POINT + blinding * h
}

fn verify_pedersen_commitment(
    commitment: RistrettoPoint,
    value: Scalar,
    blinding: Scalar
) -> bool {
    let h = hash_to_ristretto_point("H");
    let expected_commitment = value * RISTRETTO_BASEPOINT_POINT + blinding * h;
    commitment == expected_commitment
}

fn main() {

    let seed_value = 2024u64;
    let value = Scalar::from(seed_value);
    let blinding = Scalar::random(&mut OsRng);

    // Generate the commitment
    let commitment = pedersen_commitment(value, blinding);
    println!("Pedersen Commitment: {:?}", commitment);

    // Verify the commitment
    let is_valid = verify_pedersen_commitment(commitment, value, blinding);
    println!("Is the commitment valid? {}", is_valid);
}