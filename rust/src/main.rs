use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey}, pkcs8::EncodePublicKey,
};
use hex;

fn main() {
    let hex_string = "0000000000000000000000000000000000000000000000000000000000000001";
    let bytes = hex::decode(hex_string).expect("Decoding failed");
    let bytes_array = bytes.into_iter().collect();
    println!("{:?}", bytes_array);

    let signing_key: SigningKey = SigningKey::from_bytes(&bytes_array).expect("error");
    println!("{:?}", signing_key.verifying_key());
    println!("{:?}", hex::encode(signing_key.verifying_key().to_encoded_point(false).x().unwrap()));
    println!("{:?}", hex::encode(signing_key.verifying_key().to_encoded_point(false).y().unwrap()));
}

