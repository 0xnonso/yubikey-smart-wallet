use dep::std::hash::{sha256};
use dep::string_search::{StringBody, StringBody1024, SubString, SubString32, SubString64, SubString128};

use crate::{KEY_BYTES_512, KEY_BYTES_2048};

// https://github.com/ocelots-app/passport-verifier/blob/main/src/utils.nr#L22
// Reverse the bytes of an array so you can switch from
// big endian to little endian order and vice versa
pub fn reverse_bytes_array<let N: u32>(arr: [u8; N]) -> [u8; N] {
    let mut reversed_arr = [0 as u8; N];
    for i in 0..N {
        // Reverse
        reversed_arr[i] = arr[N - 1 - i];
    }
    reversed_arr
}

// https://github.com/ocelots-app/passport-verifier/blob/main/src/utils.nr#L52
pub fn insert_32_bytes_into_array<let N: u32>(mut arr: [u8; N], sub_arr: [u8; 32], index: u32) -> [u8; N] {
    arr[index] = sub_arr[0];
    arr[index + 1] = sub_arr[1];
    arr[index + 2] = sub_arr[2];
    arr[index + 3] = sub_arr[3];
    arr[index + 4] = sub_arr[4];
    arr[index + 5] = sub_arr[5];
    arr[index + 6] = sub_arr[6];
    arr[index + 7] = sub_arr[7];
    arr[index + 8] = sub_arr[8];
    arr[index + 9] = sub_arr[9];
    arr[index + 10] = sub_arr[10];

    arr[index + 11] = sub_arr[11];
    arr[index + 12] = sub_arr[12];
    arr[index + 13] = sub_arr[13];
    arr[index + 14] = sub_arr[14];
    arr[index + 15] = sub_arr[15];
    arr[index + 16] = sub_arr[16];
    arr[index + 17] = sub_arr[17];
    arr[index + 18] = sub_arr[18];
    arr[index + 19] = sub_arr[19];
    arr[index + 20] = sub_arr[20];

    arr[index + 21] = sub_arr[21];
    arr[index + 22] = sub_arr[22];
    arr[index + 23] = sub_arr[23];
    arr[index + 24] = sub_arr[24];
    arr[index + 25] = sub_arr[25];
    arr[index + 26] = sub_arr[26];
    arr[index + 27] = sub_arr[27];
    arr[index + 28] = sub_arr[28];
    arr[index + 29] = sub_arr[29];
    arr[index + 30] = sub_arr[30];

    arr[index + 31] = sub_arr[31];

    arr
}

pub fn extract_pubkey_hash_from_pattern<let N: u32, let PUBKEY_PATTERN_LEN: u32>(
    cert: [u8; N],
    pattern: [u8; PUBKEY_PATTERN_LEN],
    is_rsa_pubkey: bool
) -> [u8; 32] {
    
    let pattern_len = pattern.len();
    let haystack: StringBody1024 = StringBody::new(cert, cert.len());
    let needle: SubString32 = SubString::new(pattern, pattern_len);
    // println(cert);
    let (result, index): (bool, u32) = haystack.substring_match(needle);
    assert(result);
    let start: u32 = index + pattern_len; // 66 + (1 -> repr extra 00 byte in the begining of pubkey modulus)
    if is_rsa_pubkey {
        let mut pub_key: [u8; KEY_BYTES_2048] = [0; KEY_BYTES_2048];
        // let end: u32 = start + pub_key_len;
        for i  in 0..KEY_BYTES_2048 {
            pub_key[i] = cert[start + i];
        }

        sha256(pub_key)
    } else {
        let mut pub_key: [u8; KEY_BYTES_512] = [0; KEY_BYTES_512];
        for i in 0..KEY_BYTES_512{
            pub_key[i] = cert[start + i];
        }
        println(pub_key);
        println(sha256(pub_key));
        sha256(pub_key)
        
    }
}

pub fn match_cert_issuer_name<let N: u32, let M: u32>(
    cert: [u8; N], 
    pattern: [u8; M]
) {
    let haystack: StringBody1024 = StringBody::new(cert, cert.len());
    let needle: SubString64 = SubString::new(pattern, pattern.len());

    let (result, _): (bool, u32) = haystack.substring_match(needle);
    assert(result);
}