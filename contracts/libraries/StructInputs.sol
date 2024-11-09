// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

enum SignatureType {
    RSA2048,
    ECP256
}

struct SignatureProofInputs {
    bytes32 messageHash;
    bytes32 pubKeyHash;
    bytes proof;
}

struct AttestationProofInputs {
    bytes32 pubKeyHash;
    bytes proof;
}

struct Call {
    address target;
    uint256 value;
    bytes data;
}