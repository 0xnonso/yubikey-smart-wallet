// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import {IVerifier2} from "./interfaces/IVerifier2.sol";
import {Wallet2} from "./Wallet2.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {
    SignatureType,
    AttestationProofInputs
} from "./libraries/StructInputs.sol";
import {Test, console} from "forge-std/Test.sol";

/// @author Coinbase (https://github.com/coinbase/smart-wallet/blob/main/src/CoinbaseSmartWalletFactory.sol)
contract WalletFactory2 {

    IVerifier2 public immutable VERIFIER;
    address public immutable implementation;

    event WalletCreated(Wallet2 indexed wallet, bytes indexed ykPubKey, bytes[] signers);

    constructor(address _implementation, address _verifier) payable {
        implementation = _implementation;
        VERIFIER = IVerifier2(_verifier);
    }

    function createWallet(
        bytes calldata ykPublicKey,
        AttestationProofInputs calldata inputs,
        bytes[] calldata signers,
        uint64[] calldata signerExpirations,
        uint256 nonce
    ) external payable returns(Wallet2 wallet){
        require(
            VERIFIER.verifyRSA2048Attestation(inputs),
            "yubikey attestation proof is invalid"
        );
        // console.logBytes32(sha256(ykPublicKey));
        // console.logBytes32(inputs.pubKeyHash); 
        if(inputs.pubKeyHash != sha256(ykPublicKey)) revert();

        (bool alreadyDeployed, address walletAddr) = LibClone.createDeterministicERC1967(msg.value, implementation, getSalt(ykPublicKey, signers, nonce));
        wallet = Wallet2(payable(walletAddr));
        if (!alreadyDeployed) {
            wallet.initialize(ykPublicKey, signers, signerExpirations);
        }
        // ykWalletCreated[walletAddr] = true;
        emit WalletCreated(wallet, ykPublicKey, signers);
    }

    function getWalletAddress(
        bytes calldata ykPublicKey,
        bytes[] calldata signers,
        uint256 nonce
    ) public view returns(address){
        return LibClone.predictDeterministicAddress(initCodeHash(), getSalt(ykPublicKey, signers, nonce), address(this));
    }

    function initCodeHash() public view virtual returns (bytes32) {
        return LibClone.initCodeHashERC1967(implementation);
    }

    function getSalt(bytes calldata ykPublicKey, bytes[] calldata signers, uint256 nonce) internal view virtual returns(bytes32){
        return keccak256(abi.encode(ykPublicKey, signers,  nonce));
    }
}