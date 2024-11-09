use dep::yk_verify::{
    KEY_LIMBS_2048, KEY_BYTES_256,
    rsa_verify::{verify_rsa2048_attestation_sig}
};

global A_CERT_TBS_MAX_LEN: u32 = 600;
global I_CERT_TBS_MAX_LEN: u32 = 540;

fn main(
    attestation_cert_tbs: [u8; A_CERT_TBS_MAX_LEN],
    attestation_cert_tbs_size: u32,
    attestation_cert_signture: [Field; KEY_LIMBS_2048],
    attestation_cert_pubkey_hash: pub [u8; KEY_BYTES_256],
    int_signing_cert_tbs: [u8; I_CERT_TBS_MAX_LEN],
    int_signing_cert_tbs_size: u32,
    int_signing_cert_pubkey_modulus_limbs: [Field; KEY_LIMBS_2048],
    int_signing_cert_pubkey_redc_params_limbs: [Field; KEY_LIMBS_2048],
    int_signing_cert_signature: [Field; KEY_LIMBS_2048],
    root_cert_pubkey_modulus_limbs: pub [Field; KEY_LIMBS_2048],
    root_cert_pubkey_redc_params_limbs: [Field; KEY_LIMBS_2048],
    is_rsa_attestation_cert_pubkey: bool
){
    // Yubico PIV Attestation
    let attestation_cert_issuer_pattern = [89, 117, 98, 105, 99, 111, 32, 80, 73, 86, 32, 65, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110];
    // PIV Root CA Serial 263751
    let int_signing_cert_issuer_pattern = [80, 73, 86, 32, 82, 111, 111, 116, 32, 67, 65, 32, 83, 101, 114, 105, 97, 108, 32, 50, 54, 51, 55, 53, 49];
    verify_rsa2048_attestation_sig(
        attestation_cert_tbs,
        attestation_cert_tbs_size,
        attestation_cert_signture,
        int_signing_cert_tbs,
        int_signing_cert_tbs_size,
        int_signing_cert_pubkey_modulus_limbs,
        int_signing_cert_pubkey_redc_params_limbs,
        int_signing_cert_signature,
        root_cert_pubkey_modulus_limbs,
        root_cert_pubkey_redc_params_limbs,
        attestation_cert_issuer_pattern,
        int_signing_cert_issuer_pattern,
        attestation_cert_pubkey_hash,
        is_rsa_attestation_cert_pubkey
    );
}
