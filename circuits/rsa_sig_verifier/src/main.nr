use dep::yk_verify::{
    KEY_LIMBS_2048, KEY_BYTES_256,
    rsa_verify::{verify_rsa2048_sig, get_rsa2048_pubkey_hash}
};


fn main(
    pubkey_modulus_limbs: [Field; KEY_LIMBS_2048],
    redc_params_limbs: [Field; KEY_LIMBS_2048],
    signature: [Field; KEY_LIMBS_2048],
    pub_key_hash: pub [u8; KEY_BYTES_256],
    msg_data_hash: pub [u8; KEY_BYTES_256]
) {
    let pub_key_to_check: [u8; KEY_BYTES_256] = get_rsa2048_pubkey_hash(pubkey_modulus_limbs, redc_params_limbs);
    assert(pub_key_to_check == pub_key_hash);

    verify_rsa2048_sig(
        pubkey_modulus_limbs,
        redc_params_limbs,
        msg_data_hash,
        signature
    );
}