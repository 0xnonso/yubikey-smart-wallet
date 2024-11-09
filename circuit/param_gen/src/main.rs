use std::fs::{write, read, read_to_string};
use noir_bignum_paramgen::{bn_limbs, redc_limbs};
use num_bigint::BigUint;
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use p256::{PublicKey as P256PublicKey, Scalar, elliptic_curve::sec1::{ToEncodedPoint}, elliptic_curve::bigint::U256, ecdsa::Signature};
use sha2::{Sha256, Digest};
use clap::{Command, Arg};
use hex::decode;
use p256::elliptic_curve::ff::PrimeField;
use p256::elliptic_curve::bigint::{Encoding};


fn main() {
    let matches = Command::new("Signature and Attestation Params Generator")
        .about("Handles message signing and attestation verification")
        .subcommand(Command::new("verify-signature")
            .about("Handles RSA2048 and ECCP256 signature verification parameters")
            .arg(Arg::new("key_algo")
                .required(true)
                .help("Algorithm for the key: RSA2048 or ECCP256"))
            .arg(Arg::new("pub_key_file")
                .required(true)
                .help("Path to the public key file"))
            .arg(Arg::new("msg_file")
                .required(true)
                .help("Path to the message file"))
            .arg(Arg::new("sig_data_file")
                .required(true)
                .help("Path to the signature data file")))

        .subcommand(Command::new("verify-attestation")
            .about("Handles RSA2048 attestation verification parameters")
            .arg(Arg::new("attestation_cert_tbs_file")
                .required(true)
                .help("Path to attestation certificate TBS file"))
            .arg(Arg::new("attestation_cert_pub_key_file")
                .required(true)
                .help("Path to attestation public key file"))
            .arg(Arg::new("attestation_cert_sig_file")
                .required(true)
                .help("Path to attestation signature file"))
            .arg(Arg::new("int_signing_cert_tbs_file")
                .required(true)
                .help("Path to intermediate signing certificate TBS file"))
            .arg(Arg::new("int_signing_cert_pub_key_file")
                .required(true)
                .help("Path to intermediate signing public key file"))
            .arg(Arg::new("int_signing_cert_sig_file")
                .required(true)
                .help("Path to intermediate signing signature file"))
            .arg(Arg::new("root_cert_pub_key_file")
                .required(true)
                .help("Path to root certificate public key file")))
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("verify-signature") {
        let key_algo = matches.get_one::<String>("key_algo").unwrap();
        let pub_key_file = matches.get_one::<String>("pub_key_file").unwrap();
        let msg_file = matches.get_one::<String>("msg_file").unwrap();
        let sig_data_file = matches.get_one::<String>("sig_data_file").unwrap();
        if key_algo == "RSA2048" {
            handle_rsa_sig_verifier_params(pub_key_file, msg_file, sig_data_file);
        } else if key_algo == "ECCP256" {
            handle_p256_sig_verifier_params(pub_key_file, msg_file, sig_data_file);
        } else {
            eprintln!("Unsupported key algorithm: {}", key_algo);
        }
    }

    if let Some(matches) = matches.subcommand_matches("verify-attestation") {
        let attestation_cert_tbs_file = matches.get_one::<String>("attestation_cert_tbs_file").unwrap();
        let attestation_cert_pub_key_file = matches.get_one::<String>("attestation_cert_pub_key_file").unwrap();
        let attestation_cert_sig_file = matches.get_one::<String>("attestation_cert_sig_file").unwrap();
        let int_signing_cert_tbs_file = matches.get_one::<String>("int_signing_cert_tbs_file").unwrap();
        let int_signing_cert_pub_key_file = matches.get_one::<String>("int_signing_cert_pub_key_file").unwrap();
        let int_signing_cert_sig_file = matches.get_one::<String>("int_signing_cert_sig_file").unwrap();
        let root_cert_pub_key_file = matches.get_one::<String>("root_cert_pub_key_file").unwrap();
        handle_rsa_attestation_verifier_params(
            attestation_cert_tbs_file, 
            attestation_cert_pub_key_file, 
            attestation_cert_sig_file, 
            int_signing_cert_tbs_file, 
            int_signing_cert_pub_key_file, 
            int_signing_cert_sig_file, 
            root_cert_pub_key_file
        );
    }  
}

fn handle_rsa_sig_verifier_params(
    pub_key_file: &str,
    msg_file: &str,
    sig_data_file: &str
){
    let pub_key_der = read(pub_key_file).expect("Unable to read rsa2048 public key file");
    let pub_key = RsaPublicKey::from_public_key_der(&pub_key_der).unwrap();

    let pub_key_hash = Sha256::digest(&pub_key_der[33..289]).to_vec();

    let msg_data_hex = read_to_string(msg_file).expect("Unable to read msg file");
    // Decode the hex string into binary data
    let msg_data = decode(msg_data_hex.trim()).expect("Failed to decode hex data");
    let msg_data_hash = Sha256::digest(&msg_data).to_vec();


    let sig_data = read(sig_data_file).expect("Unable to read rsa2048 signature file");
    
    
    gen_rsa_sig_toml(
        &msg_data_hash,
        &pub_key_hash,
        &sig_data,
        &pub_key
    );
}

fn handle_p256_sig_verifier_params(
    pub_key_file: &str,
    msg_file: &str,
    sig_data_file: &str
){
    let pub_key_data = read(pub_key_file).expect("Unable to read p256 public key file");
    let pub_key = P256PublicKey::from_public_key_der(&pub_key_data).unwrap();
    let encoded_point = pub_key.to_encoded_point(false);

    let pub_key_x = encoded_point.x().expect("Invalid public key x coordinate").to_vec();
    let pub_key_y = encoded_point.y().expect("Invalid public key y coordinate").to_vec();
    let compressed_pub_key: Vec<u8> = [pub_key_x.clone(), pub_key_y.clone()].concat();
    let pub_key_hash = Sha256::digest(&compressed_pub_key).to_vec();

    let msg_data_hex = read_to_string(msg_file).expect("Unable to read msg file");
    // Decode the hex string into binary data
    let msg_data = decode(msg_data_hex.trim()).expect("Failed to decode hex data");
    println!("{:?}", msg_data);

    // let msg_data = read(msg_file).expect("Unable to read msg file");
    let msg_data_hash = Sha256::digest(&msg_data).to_vec();
    println!("{:?}", msg_data_hash);
    let sig_data = read(sig_data_file).expect("Unable to read p256 signature file");
    println!("{:?}", sig_data);
    let signature = Signature::from_der(&sig_data).expect("Invalid p256 signature format");
    // println!("{:?}", sig_data);

    let s_uint = U256::from_be_slice(&signature.s().to_bytes());

    // Get the curve order n
    let n = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let half_n = U256::from_be_hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");

    let s_normalized_uint = if s_uint > half_n { n.wrapping_sub(&s_uint) } else { s_uint };
    let s_normalized_bytes =  s_normalized_uint.to_be_bytes();
    let s_normalized_scalar = Scalar::from_repr(s_normalized_bytes.into()).expect("Invalid scalar");
    let normalized_signature = Signature::from_scalars(*signature.r(), s_normalized_scalar).expect("Invalid normalized signature");

    let mut conc_sig = Vec::with_capacity(64); // Allocate space for 64 bytes
    conc_sig.extend_from_slice(&normalized_signature.r().to_bytes()); // Append `r`
    conc_sig.extend_from_slice(&normalized_signature.s().to_bytes()); // Append `s

    gen_p526_sig_toml(
        &msg_data_hash,
        &pub_key_hash,
        &conc_sig,
        &pub_key_x,
        &pub_key_y
    );
}

fn handle_rsa_attestation_verifier_params(
    attestation_cert_tbs_file: &str,
    attestation_cert_pub_key_file: &str,
    attestation_cert_sig_file: &str,
    int_signing_cert_tbs_file: &str,
    int_signing_cert_pub_key_file: &str,
    int_signing_cert_sig_file: &str,
    root_cert_pub_key_file: &str
){
    let mut attestation_cert_tbs = read(attestation_cert_tbs_file).expect("Unable to read attestation cert file");
    
    let attestation_cert_pub_key_data = read(attestation_cert_pub_key_file).expect("Unable to read attestation cert pubkey");

    let is_attestation_cert_pub_key_rsa2048 = attestation_cert_pub_key_data.len() > 256;
    let attestation_cert_pub_key_hash;
    if is_attestation_cert_pub_key_rsa2048 {
        attestation_cert_pub_key_hash = Sha256::digest(&attestation_cert_pub_key_data[33..289]).to_vec();
    } else {
        attestation_cert_pub_key_hash = Sha256::digest(&attestation_cert_pub_key_data[27..91]).to_vec();
    }

    let attestation_cert_sig_data = read(attestation_cert_sig_file).expect("Unable to read attestation cert sig file");
    let mut int_signing_cert_tbs = read(int_signing_cert_tbs_file).expect("Unable to read int cert file");
    let int_signing_cert_pub_key_data = read(int_signing_cert_pub_key_file).expect("Unable to read int cert pubkey file");

    let int_signing_cert_pub_key = RsaPublicKey::from_public_key_der(&int_signing_cert_pub_key_data).unwrap();
    // let int_signing_cert_pub_key_hash = Sha256::digest(&int_signing_cert_pub_key_data[33..289]).to_vec();

    let int_signing_cert_sig_data = read(int_signing_cert_sig_file).expect("Unable to read int cert sig file");
    let root_cert_pub_key_data = read(root_cert_pub_key_file).expect("Unable to read root cert pubkey file");

    let root_cert_pub_key = RsaPublicKey::from_public_key_der(&root_cert_pub_key_data).unwrap();

    gen_rsa_attestation_verifier_toml(
        &mut attestation_cert_tbs,
        &attestation_cert_pub_key_hash,
        &attestation_cert_sig_data,
        &mut int_signing_cert_tbs,
        &int_signing_cert_pub_key,
        // &int_signing_cert_pub_key_hash,
        &int_signing_cert_sig_data,
        &root_cert_pub_key,
        is_attestation_cert_pub_key_rsa2048
    );
}

fn gen_rsa_sig_toml(
    msg_data_hash: &Vec<u8>,
    pub_key_hash: &Vec<u8>,
    signature: &Vec<u8>,
    public_key: &RsaPublicKey
){
    let pubkey_modulus = format!(
        "pubkey_modulus_limbs = {}",
        quote_hex(bn_limbs(public_key.n().clone(), 2048))
    );
    // make the reduction parameter for the pubkey
    let redc_params = format!(
        "redc_params_limbs = {}",
        quote_hex(redc_limbs(public_key.n().clone(), 2048))
    );
    let pubk_hash = format!("pub_key_hash = {:?}", pub_key_hash);
    let msg_hash = format!("msg_data_hash = {:?}", msg_data_hash);
    let sig = format!(
        "signature = {}", 
        quote_hex(bn_limbs(BigUint::from_bytes_be(signature), 2048))
    );
    // format for toml content
    let toml_content = format!(
        "{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n",
        pubkey_modulus,
        redc_params,
        pubk_hash,
        msg_hash,
        sig
    );
    // save to fs
    let current_dir = std::env::current_dir().expect("Failed to get current directory");
    let file_path = current_dir.join("../rsa_sig_verifier").join("Prover.toml");
    write(file_path, toml_content).expect("Failed to write to Prover.toml");
}

fn gen_p526_sig_toml(
    msg_data_hash: &Vec<u8>,
    pub_key_hash: &Vec<u8>,
    signature: &Vec<u8>,
    enc_pub_key_x: &Vec<u8>,
    enc_pub_key_y: &Vec<u8>
){
    // // Extract the x and y coordinates
    // let x = encoded_point.x().expect("No x coordinate").to_vec();
    // let y = encoded_point.y().expect("No y coordinate").to_vec();
    let pub_key_x = format!(
        "pub_key_x = {:?}",
        enc_pub_key_x
    );
    // make the reduction parameter for the pubkey
    let pub_key_y = format!(
        "pub_key_y = {:?}",
        enc_pub_key_y
    );
    let pubk_hash = format!(
        "pub_key_hash = {:?}",
        pub_key_hash
    );
    let msg_hash = format!(
        "message_hash = {:?}", msg_data_hash);
    let sig = format!("signature = {:?}", signature);
    // format for toml content
    let toml_content = format!(
        "{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n",
        sig,
        pub_key_x,
        pub_key_y,
        pubk_hash,
        msg_hash
    );
    // save to fs
    let current_dir = std::env::current_dir().expect("Failed to get current directory");
    let file_path = current_dir.join("../p256_sig_verifier").join("Prover.toml");
    write(file_path, toml_content).expect("Failed to write to Prover.toml");
}


fn gen_rsa_attestation_verifier_toml(
    attestation_cert_tbs: &mut Vec<u8>,
    attestation_cert_pub_key_hash: &Vec<u8>,
    attestation_cert_sig_data: &Vec<u8>,
    int_signing_cert_tbs: &mut Vec<u8>,
    int_signing_cert_pub_key: &RsaPublicKey,
    // int_signing_cert_pub_key_hash: &Vec<u8>,
    int_signing_cert_sig_data: &Vec<u8>,
    root_cert_pub_key: &RsaPublicKey,
    _is_attestation_cert_pub_key_rsa2048: bool
){
    let attestation_cert_tbs_len = format!(
        "attestation_cert_tbs_size = {}", attestation_cert_tbs.len()
    );
    attestation_cert_tbs.resize(600, 0);
    let padded_attestation_cert_tbs = format!(
        "attestation_cert_tbs = {:?}", attestation_cert_tbs
    );
    let attestation_cert_sig = format!(
        "attestation_cert_signture = {}", 
        quote_hex(bn_limbs(BigUint::from_bytes_be(attestation_cert_sig_data), 2048))
    );
    let int_signing_cert_tbs_len = format!(
        "int_signing_cert_tbs_size = {}", int_signing_cert_tbs.len()
    );
    int_signing_cert_tbs.resize(540, 0);
    let padded_int_signing_cert_tbs = format!(
        "int_signing_cert_tbs = {:?}", int_signing_cert_tbs
    );
    let int_signing_cert_pub_key_modulus = format!(
        "int_signing_cert_pubkey_modulus_limbs = {}",
        quote_hex(bn_limbs(int_signing_cert_pub_key.n().clone(), 2048))
    );
    let int_signing_cert_pub_key_redc_params = format!(
        "int_signing_cert_pubkey_redc_params_limbs = {}",
        quote_hex(redc_limbs(int_signing_cert_pub_key.n().clone(), 2048))
    );
    let int_signing_cert_sig = format!(
        "int_signing_cert_signature = {}", 
        quote_hex(bn_limbs(BigUint::from_bytes_be(int_signing_cert_sig_data), 2048))
    );
    let root_cert_pub_key_modulus = format!(
        "root_cert_pubkey_modulus_limbs = {}",
        quote_hex(bn_limbs(root_cert_pub_key.n().clone(), 2048))
    );
    let root_cert_pub_key_redc_params = format!(
        "root_cert_pubkey_redc_params_limbs = {}",
        quote_hex(redc_limbs(root_cert_pub_key.n().clone(), 2048))
    );
    // let attestation_cert_issuer_pattern = format!(
    //     "attestation_cert_issuer_pattern = {:?}",
    //     "Yubico PIV Attestation".as_bytes()
    // );
    // let int_signing_cert_issuer_pattern = format!(
    //     "int_signing_cert_issuer_pattern = {:?}",
    //     "PIV Root CA Serial 263751".as_bytes()
    // );
    println!("{:X?}", attestation_cert_pub_key_hash);
    let attestation_cert_pubkey_hash = format!(
        "attestation_cert_pubkey_hash = {:?}",
        attestation_cert_pub_key_hash
    );

    let is_attestation_cert_pub_key_rsa2048 = format!(
        "is_rsa_attestation_cert_pubkey = {}", _is_attestation_cert_pub_key_rsa2048
    );
    // format for toml content
    let toml_content = format!(
        "{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n",
        padded_attestation_cert_tbs,
        padded_int_signing_cert_tbs,
        int_signing_cert_pub_key_modulus,
        int_signing_cert_pub_key_redc_params,
        root_cert_pub_key_modulus,
        root_cert_pub_key_redc_params,
        attestation_cert_pubkey_hash,
        attestation_cert_sig,
        int_signing_cert_sig,
        is_attestation_cert_pub_key_rsa2048,
        attestation_cert_tbs_len,
        int_signing_cert_tbs_len
    );
    // save to fs
    let current_dir = std::env::current_dir().expect("Failed to get current directory");
    let file_path = current_dir.join("../rsa_attestation_verifier").join("Prover.toml");
    write(file_path, toml_content).expect("Failed to write to Prover.toml");
}

pub fn quote_hex(input: String) -> String {
    let hex_values: Vec<&str> = input
        .trim_matches(|c| c == '[' || c == ']')
        .split(", ")
        .collect();
    let quoted_hex_values: Vec<String> = hex_values
        .iter()
        .map(|&value| format!("\"{}\"", value))
        .collect();
    format!("[{}]", quoted_hex_values.join(", "))
}