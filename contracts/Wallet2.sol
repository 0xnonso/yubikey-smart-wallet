// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC1271} from "./core/ERC1271.sol";
import {MultiSignable2} from "./core/MultiSignable2.sol";
import {CustomSlotInitializable} from "./core/CustomSlotInitializable.sol";
import {CustomSlotInitializable} from "./core/CustomSlotInitializable.sol";
import {IVerifier2} from "./interfaces/IVerifier2.sol";
import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {Call} from "./libraries/StructInputs.sol";
// import {Test, console} from "forge-std/Test.sol";

/// @author Coinbase (https://github.com/coinbase/smart-wallet)
contract Wallet2 is ERC1271, BaseAccount, CustomSlotInitializable, MultiSignable2, UUPSUpgradeable, Receiver {

    IVerifier2 internal immutable VERIFIER2;
    IEntryPoint internal immutable ENTRY_POINT;

    bytes32 internal constant _INITIALIZABLE_STORAGE_POSITION =
        0x33e4b41198cc5b8053630ed667ea7c0c4c873f7fc8d9a478b5d7259cec0a4a00;
    
    struct SignatureWrapper {
        uint256 ownerIndex;
        bytes signatureData;
    }

    uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

    error AlreadyInitialized();

    error SelectorNotAllowed(bytes4 selector);

    error InvalidNonceKey(uint256 key);

    modifier onlyEntryPoint() virtual {
        if (msg.sender != address(entryPoint())) {
            revert Unauthorized();
        }

        _;
    }

    modifier onlyAuthorized(bytes memory data, bytes memory signature) virtual {
        if(msg.sender != address(entryPoint()) || msg.sender != address(this)){
            bytes32 msgHash = keccak256(abi.encode(_MESSAGE_TYPEHASH, keccak256(abi.encode(keccak256(data), block.chainid, nonce()))));
            _incrementNonce();
            bytes memory signerBytes = signerAtIndex(0);

            require(
                _checkSignature(msgHash, signerBytes, signature),
                "invalid signature"
            );
        }
        _;
    }


     constructor(address _entryPoint, address _verifier) CustomSlotInitializable(_INITIALIZABLE_STORAGE_POSITION) {
        VERIFIER2 = IVerifier2(_verifier);
        ENTRY_POINT = IEntryPoint(_entryPoint);
        _disableInitializers();
    }

    function initialize(bytes calldata ykPubKey, bytes[] calldata signers, uint64[] calldata signerExpiries) external payable virtual {
        if (nextSignerIndex() != 0) {
            revert AlreadyInitialized();
        }

        _initializeSigners(ykPubKey, signers, signerExpiries);
    }

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual override returns (uint256 validationData){
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

    function executeWithoutChainIdValidation(bytes calldata data) external payable virtual onlyEntryPoint {
        (Call[] memory calls) = abi.decode(data, (Call[]));
        for (uint256 i; i < calls.length; i++) {
            Call memory call = calls[i];
            bytes4 selector = bytes4(call.data);
            if (!canSkipChainIdValidation(selector)) {
                revert SelectorNotAllowed(selector);
            }
        }
        _executeCalls(calls);
    }

    function execute(bytes calldata data, bytes calldata signature) external virtual onlyAuthorized(data, signature){
        (Call[] memory calls) = abi.decode(data, (Call[]));
        _executeCalls(calls);
    }


    function entryPoint() public view virtual override returns (IEntryPoint) {
        return ENTRY_POINT;
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
            functionSelector == MultiSignable2.addSignerAddress.selector
                || functionSelector == MultiSignable2.addSignerP256PublicKey.selector
                || functionSelector == MultiSignable2.addSignerRSA2048PublicKey.selector
                || functionSelector == MultiSignable2.removeSignerAtIndex.selector
                || functionSelector == MultiSignable2.removeLastSigner.selector
                || functionSelector == UUPSUpgradeable.upgradeToAndCall.selector
        ) {
            return true;
        }
        return false;
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

    function _checkSignature(bytes32 hash, bytes memory signerBytes, bytes memory signatureData) internal view returns(bool) {
        if (signerBytes.length == 64) {
                (bytes32 r, bytes32 s) = abi.decode(signatureData, (bytes32, bytes32));
                (bytes32 x, bytes32 y) = abi.decode(signerBytes, (bytes32, bytes32));
                return VERIFIER2.verifyECP256Signature(sha256(abi.encode(hash)), r, s, x, y);
            }

            if (signerBytes.length == 256) {
                return VERIFIER2.verifyRSA2048Signature(sha256(abi.encode(hash)), signatureData, signerBytes);
            }
            revert InvalidSignerBytesLength(signerBytes);
    }

    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view virtual override returns (bool) {
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));
        bytes memory signerBytes = signerAtIndex(sigWrapper.ownerIndex);

        if (canSign(signerBytes)){
            if (signerBytes.length == 32) {
                if (uint256(bytes32(signerBytes)) > type(uint160).max) {
                    // technically should be impossible given signers can only be added with
                    // addSignerAddress and addSignerPublicKey, but we leave incase of future changes.
                    revert InvalidEthereumAddressSigner(signerBytes);
                }

                address owner;
                assembly ("memory-safe") {
                    owner := mload(add(signerBytes, 32))
                }

                return SignatureCheckerLib.isValidSignatureNow(owner, hash, sigWrapper.signatureData);
            } else {
                _checkSignature(hash, signerBytes, sigWrapper.signatureData);
            }
        }

        revert();        
    }

    /// @inheritdoc UUPSUpgradeable
    ///
    /// @dev Authorization logic is only based on the `msg.sender` being an owner of this account,
    ///      or `address(this)`.
    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlySelf {}

    /// @inheritdoc ERC1271
    function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
        return ("Yubikey Smart Wallet", "1");
    }
}