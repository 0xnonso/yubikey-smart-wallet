// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library Utils {
    function packPubKeyModulus(bytes32[] memory rootCertPubKeyModulusLimbs) internal pure {
        rootCertPubKeyModulusLimbs[0]  = bytes32(uint256(0xad5f4d9dc61427192ecae813b441ef));
        rootCertPubKeyModulusLimbs[1]  = bytes32(uint256(0xbdce5f83ce3486a7d22154f895b467));
        rootCertPubKeyModulusLimbs[2]  = bytes32(uint256(0x8741f61dd83c246aac519cb6cd5722));
        rootCertPubKeyModulusLimbs[3]  = bytes32(uint256(0xa04f75d59937a2c2f0524dcb728bd9));
        rootCertPubKeyModulusLimbs[4]  = bytes32(uint256(0xce6ebc6a0e0fbd7ce75287381fc02a));
        rootCertPubKeyModulusLimbs[5]  = bytes32(uint256(0x6ae6fdce88ed63c8b65e2aa66831b3));
        rootCertPubKeyModulusLimbs[6]  = bytes32(uint256(0xf7a6f9166910361f70c0f6dec7fc73));
        rootCertPubKeyModulusLimbs[7]  = bytes32(uint256(0x5bf622b0a40ce2778a070552c88660));
        rootCertPubKeyModulusLimbs[8]  = bytes32(uint256(0x45958464dad43d19c7582839aa53e7));
        rootCertPubKeyModulusLimbs[9]  = bytes32(uint256(0xbb39fc0ebe4cbff805c837ff57a745));
        rootCertPubKeyModulusLimbs[10] = bytes32(uint256(0xffc211297553aa8e85343f97b58f5c));
        rootCertPubKeyModulusLimbs[11] = bytes32(uint256(0x82c762f043889810e6f5965828b55a));
        rootCertPubKeyModulusLimbs[12] = bytes32(uint256(0x90d869b2b6a067c59b006b72aa6620));
        rootCertPubKeyModulusLimbs[13] = bytes32(uint256(0x56344d848a553ce6e60a7c414ff5de));
        rootCertPubKeyModulusLimbs[14] = bytes32(uint256(0x1a33c7dcf301c2f9399bf7c8e636f8));
        rootCertPubKeyModulusLimbs[15] = bytes32(uint256(0x4f69b467e66ea927e9d21341d15a9a));
        rootCertPubKeyModulusLimbs[16] = bytes32(uint256(0x7670c4cd47a60275c4c5471b8fcb7d));
        rootCertPubKeyModulusLimbs[17] = bytes32(uint256(0xc3));
    }
}