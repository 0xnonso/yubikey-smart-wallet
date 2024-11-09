// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ERC1271} from "./core/ERC1271.sol";
import {MultiSignable} from "./core/MultiSignable.sol";
import {CustomSlotInitializable} from "./core/CustomSlotInitializable.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {
    Call,
    SignatureType,
    SignatureProofInputs
} from "./libraries/StructInputs.sol";
// import {Test, console} from "forge-std/Test.sol";

/// @author Coinbase (https://github.com/coinbase/smart-wallet)
contract Wallet is ERC1271, BaseAccount, CustomSlotInitializable, MultiSignable, UUPSUpgradeable, Receiver {

    IVerifier internal immutable VERIFIER;
    IEntryPoint internal immutable ENTRY_POINT;

    bytes32 internal constant _INITIALIZABLE_STORAGE_POSITION =
        0x33e4b41198cc5b8053630ed667ea7c0c4c873f7fc8d9a478b5d7259cec0a4a00;

    struct SignatureWrapper {
        bytes signerData;
        bytes signatureData;
    }

    uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

    error InvalidNonceKey(uint256 key);
    error SelectorNotAllowed(bytes4 selector);

    modifier onlyEntryPoint() virtual {
        if (msg.sender != address(entryPoint())) {
            revert Unauthorized();
        }
        _;
    }

    modifier onlyAuthorized(bytes memory data, bytes memory _proof) virtual {
        if(msg.sender != address(entryPoint()) || msg.sender != address(this)){
            bytes32 dataHash = keccak256(abi.encode(keccak256(data), block.chainid, nonce()));
            bytes32 msgHash = sha256(abi.encode(_hashStruct(dataHash)));
            _incrementNonce();

            require(
                _checkProof(msgHash, pubKeyHash(), accountSigType(), _proof)
            );
        }
        _;
    }

    constructor(address _entryPoint, address _verifier) CustomSlotInitializable(_INITIALIZABLE_STORAGE_POSITION) {
        VERIFIER = IVerifier(_verifier);
        ENTRY_POINT = IEntryPoint(_entryPoint);
        _disableInitializers();
    }

    function initialize(SignatureType sigType, bytes32 _pubKeyHash, bytes32[] calldata signers, uint64[] calldata signerExpirations) public {
        _initializeSigners(sigType, _pubKeyHash, signers, signerExpirations);
    }

    function execute(bytes calldata data, bytes calldata proof) external virtual onlyAuthorized(data, proof){
        (Call[] memory calls) = abi.decode(data, (Call[]));
        _executeCalls(calls);
    }

    function executeWithoutChainIdValidation(bytes calldata data) external payable virtual onlyEntryPoint {
        (Call[] memory calls) = abi.decode(data, (Call[]));
        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];
            bytes4 selector = bytes4(call.data);
            if (!canSkipChainIdValidation(selector)) {
                revert SelectorNotAllowed(selector);
            }
        }
        _executeCalls(calls);
    }

    function getUserOpHashWithoutChainId(PackedUserOperation calldata userOp) public view virtual returns (bytes32) {
        return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
    }

    function implementation() public view returns (address $) {
        assembly {
            $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
        if (
            functionSelector == MultiSignable.grantSignerPriviledge.selector
                || functionSelector == MultiSignable.revokeSignerPriviledge.selector
                || functionSelector == UUPSUpgradeable.upgradeToAndCall.selector
        ) {
            return true;
        }
        return false;
    }
    
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256 validationData){
        // if replayable ensure the call bundle contains only one call tx to permissioned function
        uint256 key = userOp.nonce >> 64;

        if (bytes4(userOp.callData) == this.executeWithoutChainIdValidation.selector) {
            userOpHash = getUserOpHashWithoutChainId(userOp);
            if (key != REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }
        } else {
            if (key == REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }
        }

        // Return 0 if the recovered address matches the owner.
        if (_isValidSignature(userOpHash, userOp.signature)) {
            return 0;
        }

        // Else return 1
        return 1;
    }

    function _checkProof(
        bytes32 dataHash,
        bytes32 _pubKeyHash,
        SignatureType _signatureType,
        bytes memory _proof
    ) internal view returns(bool success){
        SignatureProofInputs memory inputs = SignatureProofInputs({
            messageHash: dataHash,
            pubKeyHash: _pubKeyHash,
            proof: _proof
        });
        
        if(_signatureType == SignatureType.RSA2048){
            success = VERIFIER.verifyRSA2048Signature(inputs);
        } else {
            success = VERIFIER.verifyECP256Signature(inputs);
        }
    }

    function _executeCalls(Call[] memory calls) internal {
        bool success; bytes memory result;
        for(uint256 i; i < calls.length; i++){
            (success, result) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) {
                assembly ("memory-safe") {
                    revert(add(result, 32), mload(result))
                }
            }
        }
    }

    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view override returns(bool){
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));
        (bytes32 signer, SignatureType sigType) = abi.decode(sigWrapper.signerData, (bytes32, SignatureType));
        if(!hasSignerPriviledge(signer)){
            revert Unauthorized();
        }
        if(uint256(signer) > type(uint160).max){
            return _checkProof(hash, signer, sigType, sigWrapper.signatureData);
        } else {
            return SignatureCheckerLib.isValidSignatureNow(address(uint160(uint256(signer))), hash, sigWrapper.signatureData);
        }
    }

    /// @inheritdoc UUPSUpgradeable
    ///
    /// @dev Authorization logic is only based on the `msg.sender` being an owner of this account,
    ///      or `address(this)`.
    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlySelf {}

    function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
        return ("Yubikey Smart Wallet", "1");
    }
}