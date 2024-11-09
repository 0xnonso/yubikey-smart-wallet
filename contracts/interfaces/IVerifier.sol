// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import{
    AttestationProofInputs,
    SignatureProofInputs
} from "../libraries/StructInputs.sol";

interface IVerifier {
    function verifyRSA2048Attestation(
        AttestationProofInputs memory inputs
    ) external view returns (bool);

    function verifyRSA2048Signature(
        SignatureProofInputs memory _signatureProof
    ) external view returns (bool);

    function verifyECP256Signature(
        SignatureProofInputs memory _signatureProof
    ) external view returns (bool);
}