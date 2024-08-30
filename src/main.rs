use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::scalar::Scalar;
use sha3::Sha3_512;
use rand::rngs::OsRng;


fn hash_to_ristretto_point(data: &str) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha3_512>(data.as_bytes())
}


fn pedersen_commitment(value: Scalar, blinding: Scalar, rp: RistrettoPoint) -> RistrettoPoint {
    let h = hash_to_ristretto_point("H");
    value * rp + blinding * h
}

fn verify_pedersen_commitment(
    commitment: RistrettoPoint,
    value: Scalar,
    blinding: Scalar,
    rp: RistrettoPoint
) -> bool {
    let h = hash_to_ristretto_point("H");
    let expected_commitment = value * rp + blinding * h;
    commitment == expected_commitment
}

fn main() {

    // https://doc.dalek.rs/curve25519_dalek/traits/trait.MultiscalarMul.html

    let a = Scalar::from(87329482u64);
    let b = Scalar::from(37264829u64);
    let c = Scalar::from(98098098u64);

    // Some points
    let P = constants::RISTRETTO_BASEPOINT_POINT;
    let Q = P + P;
    let R = P + Q;

    // A1 = a*P + b*Q + c*R
    let abc = [a,b,c];
    let A1 = RistrettoPoint::multiscalar_mul(&abc, &[P,Q,R]);

    // Note: (&abc).into_iter(): Iterator<Item=&Scalar>

    // A2 = (-a)*P + (-b)*Q + (-c)*R
    let minus_abc = abc.iter().map(|x| -x);
    let A2 = RistrettoPoint::multiscalar_mul(minus_abc, &[P,Q,R]);
    // Note: minus_abc.into_iter(): Iterator<Item=Scalar>

    assert_eq!(A1.compress(), (-A2).compress());

    let seed_value = 2024u64;
    let value = Scalar::from(seed_value);
    let blinding = Scalar::random(&mut OsRng);

    // Generate the commitment
    let commitment = pedersen_commitment(value, blinding, A1);
    println!("Pedersen Commitment: {:?}", commitment);

    // Verify the commitment
    let is_valid = verify_pedersen_commitment(commitment, value, blinding, A1);
    println!("Is the commitment valid? {}", is_valid);
}