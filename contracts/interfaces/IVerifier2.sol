// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import{AttestationProofInputs} from "../libraries/StructInputs.sol";

interface IVerifier2 {
    function verifyRSA2048Attestation(
        AttestationProofInputs memory inputs
    ) external view returns (bool);

    function verifyRSA2048Signature(
        bytes32 messageHash, bytes calldata s, bytes calldata n
    ) external view returns(bool);

    function verifyECP256Signature(
        bytes32 messageHash, bytes32 r, bytes32 s, bytes32 qx, bytes32 qy
    ) external view returns(bool);
}