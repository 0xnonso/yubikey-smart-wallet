use dep::noir_rsa::bignum::fields::{Params2048};
use dep::noir_rsa::bignum::runtime_bignum::BigNumInstance;
use dep::noir_rsa::bignum::BigNum;
use dep::noir_rsa::types::RSA;
use dep::std::hash::{sha256, sha256_var};
use crate::{
    KEY_BYTES_256, KEY_LIMBS_2048, KEY_BYTES_2048, RSA_EXPONENT,
    utils::{
        reverse_bytes_array,
        match_cert_issuer_name,
        extract_pubkey_hash_from_pattern
    }
};

type BN2048 = BigNum<KEY_LIMBS_2048, Params2048>;
type RSA2048 = RSA<BN2048, BigNumInstance<KEY_LIMBS_2048, Params2048>, KEY_BYTES_2048>;

pub fn verify_rsa2048_sig(
    pubkey_modulus_limbs: [Field; KEY_LIMBS_2048],
    redc_params_limbs: [Field; KEY_LIMBS_2048],
    msg_data_hash: [u8; KEY_BYTES_256],
    signature: [Field; KEY_LIMBS_2048]
) {
    let pub_key: BigNumInstance<KEY_LIMBS_2048, Params2048> = BigNumInstance::new(pubkey_modulus_limbs, redc_params_limbs);
    let signature: BN2048 = BigNum::from_array(signature);
    
    let rsa: RSA2048 = RSA {};
    assert(
        rsa.verify_sha256_pkcs1v15(
            pub_key, 
            msg_data_hash, 
            signature,
            RSA_EXPONENT
        )
    );
}

pub fn verify_rsa2048_attestation_sig<let A_CERT_TBS_MAX_LEN: u32, let I_CERT_TBS_MAX_LEN: u32, let A_CERT_PATTERN_LEN: u32, let I_CERT_PATTERN_LEN: u32>(
    attestation_cert_tbs: [u8; A_CERT_TBS_MAX_LEN],
    attestation_cert_tbs_len: u32,
    attestation_cert_signture: [Field; KEY_LIMBS_2048],
    int_signing_cert_tbs: [u8; I_CERT_TBS_MAX_LEN],
    int_signing_cert_tbs_len: u32,
    int_signing_cert_pubkey_modulus_limbs: [Field; KEY_LIMBS_2048],
    int_signing_cert_pubkey_redc_params_limbs: [Field; KEY_LIMBS_2048],
    int_signing_cert_signature: [Field; KEY_LIMBS_2048],
    root_cert_pubkey_modulus_limbs: [Field; KEY_LIMBS_2048],
    root_cert_pubkey_redc_params_limbs: [Field; KEY_LIMBS_2048],
    attestation_cert_issuer_pattern: [u8; A_CERT_PATTERN_LEN],
    int_signing_cert_issuer_pattern: [u8; I_CERT_PATTERN_LEN],
    attestation_cert_pubkey_hash: [u8; KEY_BYTES_256],
    is_rsa_attestation_cert_pubkey: bool
){
    let int_signing_cert_tbs_hash = sha256_var(int_signing_cert_tbs, int_signing_cert_tbs_len as u64); // = hash(attestation_cert_tbs)
    println(int_signing_cert_tbs_hash);
    match_cert_issuer_name(
        int_signing_cert_tbs,
        int_signing_cert_issuer_pattern
    );
    verify_rsa2048_sig(
        root_cert_pubkey_modulus_limbs,
        root_cert_pubkey_redc_params_limbs,
        int_signing_cert_tbs_hash,
        int_signing_cert_signature
    );

    let attestation_cert_tbs_hash = sha256_var(attestation_cert_tbs, attestation_cert_tbs_len as u64);
    
    // Match the following pattern in `certificate_tbs`:
    //      Subject Public Key Info:
    //        Public Key Algorithm: rsaEncryption
    //          Public-Key: (2048 bit)
    //          Modulus:
    // let pattern: [u8; 66] = [48, 33, 49, 31, 48, 29, 6, 3, 85, 4, 3, 12, 22, 89, 117, 98, 105, 99, 111, 32, 80, 73, 86, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1];
    // let pattern: [u8; 9] = [48, 130, 1, 10, 2, 130, 1, 1, 0];

    let mut pubkey_pattern: [u8; 9] = [48, 130, 1, 10, 2, 130, 1, 1, 0];

    let int_signing_pubkey_hash = extract_pubkey_hash_from_pattern(int_signing_cert_tbs, pubkey_pattern, true);
    // assert hash is equal
    let mut int_signing_pubkey_to_check_hash: [u8; KEY_BYTES_256] = get_rsa2048_pubkey_hash(
        int_signing_cert_pubkey_modulus_limbs,
        int_signing_cert_pubkey_redc_params_limbs
    );

    assert(int_signing_pubkey_hash == int_signing_pubkey_to_check_hash);
    
    match_cert_issuer_name(
        attestation_cert_tbs,
        attestation_cert_issuer_pattern
    );
    verify_rsa2048_sig(
        int_signing_cert_pubkey_modulus_limbs,
        int_signing_cert_pubkey_redc_params_limbs,
        attestation_cert_tbs_hash,
        attestation_cert_signture
    );

    if !is_rsa_attestation_cert_pubkey {
        pubkey_pattern = [206, 61, 3, 1, 7, 3, 66, 0, 4];
    }

    assert(attestation_cert_pubkey_hash == extract_pubkey_hash_from_pattern(attestation_cert_tbs, pubkey_pattern, is_rsa_attestation_cert_pubkey));
}

pub fn get_rsa2048_pubkey_hash(
    pubkey_modulus_limbs: [Field; KEY_LIMBS_2048],
    redc_params_limbs: [Field; KEY_LIMBS_2048]
) -> [u8; KEY_BYTES_256]{
    let pub_key: BigNumInstance<KEY_LIMBS_2048, Params2048> = BigNumInstance::new(
        pubkey_modulus_limbs, redc_params_limbs
    );
    let mut pub_key_to_check: [u8; KEY_BYTES_2048] = pub_key.modulus().to_le_bytes();
    pub_key_to_check = reverse_bytes_array(pub_key_to_check);

    sha256(pub_key_to_check)
}