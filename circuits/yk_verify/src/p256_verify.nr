use dep::std::ecdsa_secp256r1;
use dep::std::hash::sha256;
use crate::{KEY_BYTES_256, KEY_BYTES_512, utils::insert_32_bytes_into_array};

pub fn verify_p256_sig(
    pub_key_x: [u8; KEY_BYTES_256],
    pub_key_y: [u8; KEY_BYTES_256],
    signature: [u8; KEY_BYTES_512],
    message_hash: [u8; KEY_BYTES_256]
){
    assert(
        ecdsa_secp256r1::verify_signature(
            pub_key_x,
            pub_key_y,
            signature,
            message_hash
        )
    );
}

pub fn get_p256_pubkey_hash(
    pub_key_x: [u8; KEY_BYTES_256],
    pub_key_y: [u8; KEY_BYTES_256]
) -> [u8; KEY_BYTES_256]{
    let mut compressed_pub_key: [u8; KEY_BYTES_512] = [0; KEY_BYTES_512];
    compressed_pub_key = insert_32_bytes_into_array(compressed_pub_key, pub_key_x, 0);
    compressed_pub_key = insert_32_bytes_into_array(compressed_pub_key, pub_key_y, 32);
    sha256(compressed_pub_key)
}