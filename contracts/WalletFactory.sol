// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import {IVerifier} from "./interfaces/IVerifier.sol";
import {Wallet} from "./Wallet.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {
    SignatureType,
    AttestationProofInputs
} from "./libraries/StructInputs.sol";

/// @author Coinbase (https://github.com/coinbase/smart-wallet/blob/main/src/CoinbaseSmartWalletFactory.sol)
contract WalletFactory {

    IVerifier public immutable VERIFIER;
    address public immutable implementation;

    event WalletCreated(Wallet indexed wallet, SignatureType sigType, bytes32[] signers, bytes32 pubKeyHash);

    constructor(address _implementation, address _verifier) payable {
        implementation = _implementation;
        VERIFIER = IVerifier(_verifier);
    }

    function createWallet(
        SignatureType sigType,
        AttestationProofInputs memory inputs,
        bytes32[] calldata signers,
        uint64[] calldata signerExpirations,
        uint256 nonce
    ) external payable returns(Wallet wallet){
        require(
            VERIFIER.verifyRSA2048Attestation(inputs),
            "yubikey attestation proof is invalid"
        );

        (bool alreadyDeployed, address walletAddr) = LibClone.createDeterministicERC1967(msg.value, implementation, getSalt(sigType, inputs.pubKeyHash, signers, nonce));
        wallet = Wallet(payable(walletAddr));
        if (!alreadyDeployed) {
            wallet.initialize(sigType, inputs.pubKeyHash, signers, signerExpirations);
        }
        emit WalletCreated(wallet, sigType, signers, inputs.pubKeyHash);
    }

    function getWalletAddress(
        SignatureType sigType,
        bytes32 pubKeyHash,
        bytes32[] calldata signers,
        uint256 nonce
    ) public view returns(address){
        return LibClone.predictDeterministicAddress(initCodeHash(), getSalt(sigType, pubKeyHash, signers, nonce), address(this));
    }

    function initCodeHash() public view virtual returns (bytes32) {
        return LibClone.initCodeHashERC1967(implementation);
    }

    function getSalt(SignatureType sigType, bytes32 pubKeyHash, bytes32[] calldata signers, uint256 nonce) internal view virtual returns(bytes32){
        return keccak256(abi.encode(sigType, pubKeyHash, signers, nonce));
    }
}