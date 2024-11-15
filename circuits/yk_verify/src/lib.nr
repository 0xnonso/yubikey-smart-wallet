mod utils;
mod rsa_verify;
mod p256_verify;

global KEY_BYTES_256: u32 = 32;
global KEY_BYTES_512: u32 = 64;
global KEY_LIMBS_2048: u32 = 18;
global KEY_BYTES_2048: u32 = 256;
global RSA_EXPONENT: u32 = 65537;