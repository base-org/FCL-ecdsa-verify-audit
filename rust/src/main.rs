use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey}, elliptic_curve::{bigint::Encoding, point::AffineCoordinates, sec1::{FromEncodedPoint, ToEncodedPoint}}, pkcs8::EncodePublicKey, AffinePoint, EncodedPoint, ProjectivePoint, U256
};
use hex;

fn main() {

    let x = U256::from_be_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    let y = U256::from_be_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    let x_bytes = x.to_be_bytes();
    let y_bytes = y.to_be_bytes();

    let q = EncodedPoint::from_affine_coordinates((&x_bytes).into(), (&y_bytes).into(), false);
    // let z = AffinePoint::from_encoded_point(&q).expect("error encoding affine");
    let projective = ProjectivePoint::from_encoded_point(&q).expect("error");
    println!("{:?}", q);
    println!("{:?}", hex::encode(projective.to_encoded_point(false).x().unwrap()));
    println!("{:?}",hex::encode( projective.to_encoded_point(false).y().unwrap()));
    println!("{:?}", hex::encode(projective.to_affine().x()));
    let n = projective.add(&projective);
    println!("{:?}", projective);
    println!("{:?}", n);
    println!("{:?}", hex::encode(n.to_encoded_point(false).x().unwrap()));
    println!("{:?}", hex::encode(n.to_encoded_point(false).y().unwrap()));
    // println!("{:?}", hex::encode(projective.to_affine().y().unwrap()));
    
    // let hex_string = "0000000000000000000000000000000000000000000000000000000000000001";
    // let bytes = hex::decode(hex_string).expect("Decoding failed");
    // let bytes_array = bytes.into_iter().collect();

    // let signing_key: SigningKey = SigningKey::from_bytes(&bytes_array).expect("error");
    // println!("{:?}", signing_key.verifying_key());
    // println!("{:?}", hex::encode(signing_key.verifying_key().to_encoded_point(false).x().unwrap()));
    // println!("{:?}", hex::encode(signing_key.verifying_key().to_encoded_point(false).y().unwrap()));
}

