use dep::yk_verify::{
    KEY_BYTES_256, KEY_BYTES_512,
    p256_verify::{verify_p256_sig, get_p256_pubkey_hash}
};

fn main(
    pub_key_x: [u8; KEY_BYTES_256],
    pub_key_y: [u8; KEY_BYTES_256],
    signature: [u8; KEY_BYTES_512],
    pub_key_hash: pub [u8; KEY_BYTES_256],
    message_hash: pub [u8; KEY_BYTES_256]
) {
    assert(get_p256_pubkey_hash(pub_key_x, pub_key_y) == pub_key_hash);
    verify_p256_sig(
        pub_key_x, 
        pub_key_y, 
        signature, 
        message_hash
    );
}
