// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {RSA2048AttestationVerifier} from "./RSA2048AttestationVerifier.sol";
import {P256} from "openzeppelin-contracts/contracts/utils/cryptography/P256.sol";
import {RSA as RSA2048} from "openzeppelin-contracts/contracts/utils/cryptography/RSA.sol";
import {IVerifier2} from "../interfaces/IVerifier2.sol";
import {AttestationProofInputs} from "../libraries/StructInputs.sol";

contract Verifier2 is IVerifier2 {
    // uint256 public constant RSA_EXPONENT = 65537;
    // bytes public constant RSA_EXPONENT = hex'010001';

    RSA2048AttestationVerifier public immutable rsa2048AttestationVerifier;

    bytes32 public immutable rootCertPubKeyModulusLimbs1;
    bytes32 public immutable rootCertPubKeyModulusLimbs2;
    bytes32 public immutable rootCertPubKeyModulusLimbs3;
    bytes32 public immutable rootCertPubKeyModulusLimbs4;
    bytes32 public immutable rootCertPubKeyModulusLimbs5;
    bytes32 public immutable rootCertPubKeyModulusLimbs6;
    bytes32 public immutable rootCertPubKeyModulusLimbs7;
    bytes32 public immutable rootCertPubKeyModulusLimbs8;
    bytes32 public immutable rootCertPubKeyModulusLimbs9;
    bytes32 public immutable rootCertPubKeyModulusLimbs10;
    bytes32 public immutable rootCertPubKeyModulusLimbs11;
    bytes32 public immutable rootCertPubKeyModulusLimbs12;
    bytes32 public immutable rootCertPubKeyModulusLimbs13;
    bytes32 public immutable rootCertPubKeyModulusLimbs14;
    bytes32 public immutable rootCertPubKeyModulusLimbs15;
    bytes32 public immutable rootCertPubKeyModulusLimbs16;
    bytes32 public immutable rootCertPubKeyModulusLimbs17;
    bytes32 public immutable rootCertPubKeyModulusLimbs18;

    // bytes32 public immutable rootCertIssuerName;
    // bytes32 public immutable intSigningCertIssuerName;

    constructor(
        bytes32[] memory _pubKeyModulusLimbs
    ) {
        rsa2048AttestationVerifier  = new RSA2048AttestationVerifier();

        rootCertPubKeyModulusLimbs1  = _pubKeyModulusLimbs[0];
        rootCertPubKeyModulusLimbs2  = _pubKeyModulusLimbs[1];
        rootCertPubKeyModulusLimbs3  = _pubKeyModulusLimbs[2];
        rootCertPubKeyModulusLimbs4  = _pubKeyModulusLimbs[3];
        rootCertPubKeyModulusLimbs5  = _pubKeyModulusLimbs[4];
        rootCertPubKeyModulusLimbs6  = _pubKeyModulusLimbs[5];
        rootCertPubKeyModulusLimbs7  = _pubKeyModulusLimbs[6];
        rootCertPubKeyModulusLimbs8  = _pubKeyModulusLimbs[7];
        rootCertPubKeyModulusLimbs9  = _pubKeyModulusLimbs[8];
        rootCertPubKeyModulusLimbs10 = _pubKeyModulusLimbs[9];
        rootCertPubKeyModulusLimbs11 = _pubKeyModulusLimbs[10];
        rootCertPubKeyModulusLimbs12 = _pubKeyModulusLimbs[11];
        rootCertPubKeyModulusLimbs13 = _pubKeyModulusLimbs[12];
        rootCertPubKeyModulusLimbs14 = _pubKeyModulusLimbs[13];
        rootCertPubKeyModulusLimbs15 = _pubKeyModulusLimbs[14];
        rootCertPubKeyModulusLimbs16 = _pubKeyModulusLimbs[15];
        rootCertPubKeyModulusLimbs17 = _pubKeyModulusLimbs[16];
        rootCertPubKeyModulusLimbs18 = _pubKeyModulusLimbs[17];
    }

    function verifyRSA2048Signature(
        bytes32 messageHash, bytes calldata s, bytes calldata n
    ) external view returns(bool){
        return RSA2048.pkcs1Sha256(
            messageHash,
            s,
            hex'010001',
            n
        );
    }

    function verifyECP256Signature(
        bytes32 messageHash, bytes32 r, bytes32 s, bytes32 qx, bytes32 qy
    ) external view returns(bool){
        return P256.verify(
            messageHash,
            r,
            s,
            qx,
            qy
        );
    }

    function verifyRSA2048Attestation(
        AttestationProofInputs memory inputs
    ) external view returns(bool){
        bytes32[] memory publicInputs = new bytes32[](50);
        
        publicInputs[31] = bytes32(uint256(inputs.pubKeyHash)        & 0xFF);
        publicInputs[30] = bytes32(uint256(inputs.pubKeyHash >> 8)   & 0xFF);
        publicInputs[29] = bytes32(uint256(inputs.pubKeyHash >> 16)  & 0xFF);
        publicInputs[28] = bytes32(uint256(inputs.pubKeyHash >> 24)  & 0xFF);
        publicInputs[27] = bytes32(uint256(inputs.pubKeyHash >> 32)  & 0xFF);
        publicInputs[26] = bytes32(uint256(inputs.pubKeyHash >> 40)  & 0xFF);
        publicInputs[25] = bytes32(uint256(inputs.pubKeyHash >> 48)  & 0xFF);
        publicInputs[24] = bytes32(uint256(inputs.pubKeyHash >> 56)  & 0xFF);
        publicInputs[23] = bytes32(uint256(inputs.pubKeyHash >> 64)  & 0xFF);
        publicInputs[22] = bytes32(uint256(inputs.pubKeyHash >> 72)  & 0xFF);
        publicInputs[21] = bytes32(uint256(inputs.pubKeyHash >> 80)  & 0xFF);
        publicInputs[20] = bytes32(uint256(inputs.pubKeyHash >> 88)  & 0xFF);
        publicInputs[19] = bytes32(uint256(inputs.pubKeyHash >> 96)  & 0xFF);
        publicInputs[18] = bytes32(uint256(inputs.pubKeyHash >> 104) & 0xFF);
        publicInputs[17] = bytes32(uint256(inputs.pubKeyHash >> 112) & 0xFF);
        publicInputs[16] = bytes32(uint256(inputs.pubKeyHash >> 120) & 0xFF);
        publicInputs[15] = bytes32(uint256(inputs.pubKeyHash >> 128) & 0xFF);
        publicInputs[14] = bytes32(uint256(inputs.pubKeyHash >> 136) & 0xFF);
        publicInputs[13] = bytes32(uint256(inputs.pubKeyHash >> 144) & 0xFF);
        publicInputs[12] = bytes32(uint256(inputs.pubKeyHash >> 152) & 0xFF);
        publicInputs[11] = bytes32(uint256(inputs.pubKeyHash >> 160) & 0xFF);
        publicInputs[10] = bytes32(uint256(inputs.pubKeyHash >> 168) & 0xFF);
        publicInputs[9]  = bytes32(uint256(inputs.pubKeyHash >> 176) & 0xFF);
        publicInputs[8]  = bytes32(uint256(inputs.pubKeyHash >> 184) & 0xFF);
        publicInputs[7]  = bytes32(uint256(inputs.pubKeyHash >> 192) & 0xFF);
        publicInputs[6]  = bytes32(uint256(inputs.pubKeyHash >> 200) & 0xFF);
        publicInputs[5]  = bytes32(uint256(inputs.pubKeyHash >> 208) & 0xFF);
        publicInputs[4]  = bytes32(uint256(inputs.pubKeyHash >> 216) & 0xFF);
        publicInputs[3]  = bytes32(uint256(inputs.pubKeyHash >> 224) & 0xFF);
        publicInputs[2]  = bytes32(uint256(inputs.pubKeyHash >> 232) & 0xFF);
        publicInputs[1]  = bytes32(uint256(inputs.pubKeyHash >> 240) & 0xFF);
        publicInputs[0]  = bytes32(uint256(inputs.pubKeyHash >> 248) & 0xFF);

        publicInputs[32] = rootCertPubKeyModulusLimbs1;
        publicInputs[33] = rootCertPubKeyModulusLimbs2;
        publicInputs[34] = rootCertPubKeyModulusLimbs3;
        publicInputs[35] = rootCertPubKeyModulusLimbs4;
        publicInputs[36] = rootCertPubKeyModulusLimbs5;
        publicInputs[37] = rootCertPubKeyModulusLimbs6;
        publicInputs[38] = rootCertPubKeyModulusLimbs7;
        publicInputs[39] = rootCertPubKeyModulusLimbs8;
        publicInputs[40] = rootCertPubKeyModulusLimbs9;
        publicInputs[41] = rootCertPubKeyModulusLimbs10;
        publicInputs[42] = rootCertPubKeyModulusLimbs11;
        publicInputs[43] = rootCertPubKeyModulusLimbs12;
        publicInputs[44] = rootCertPubKeyModulusLimbs13;
        publicInputs[45] = rootCertPubKeyModulusLimbs14;
        publicInputs[46] = rootCertPubKeyModulusLimbs15;
        publicInputs[47] = rootCertPubKeyModulusLimbs16;
        publicInputs[48] = rootCertPubKeyModulusLimbs17;
        publicInputs[49] = rootCertPubKeyModulusLimbs18;

        return rsa2048AttestationVerifier.verify(inputs.proof, publicInputs);
    }
}