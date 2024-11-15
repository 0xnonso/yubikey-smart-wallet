// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC1271} from "./core/ERC1271.sol";
import {MultiSignable2} from "./core/MultiSignable2.sol";
import {CustomSlotInitializable} from "./core/CustomSlotInitializable.sol";
import {CustomSlotInitializable} from "./core/CustomSlotInitializable.sol";
import {IVerifier2} from "./interfaces/IVerifier2.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {Call} from "./libraries/StructInputs.sol";
// import {Test, console} from "forge-std/Test.sol";

/// @author Coinbase (https://github.com/coinbase/smart-wallet)
/// modified from https://github.com/coinbase/smart-wallet/blob/main/src/CoinbaseSmartWallet.sol
contract Wallet2 is ERC1271, IAccount, CustomSlotInitializable, MultiSignable2, UUPSUpgradeable, Receiver {
    /// @notice Verifier contract to verfy user signature.
    IVerifier2 internal immutable VERIFIER2;
    /// @notice Entrypoint contract.
    IEntryPoint internal immutable ENTRY_POINT;
    /// @dev Computed from keccak256(abi.encode(uint256(keccak256("YkWallet.storage.initializable")) - 1)) & ~bytes32(uint256(0xff)); 
    bytes32 internal constant _INITIALIZABLE_STORAGE_POSITION =
        0x449b64fc4e5b10ff03eeced669eb8cc5176fdc16ed36656dc722af4fee461700;
    
    /// @notice A wrapper struct used for signature validation so that callers
    ///         can identify the signer.
    struct SignatureWrapper {
        /// @dev The index of the signer, see `MultiOwnable.ownerAtIndex`
        uint256 ownerIndex;
        /// @dev If `MultiOwnable.ownerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
        /// @dev If `MultiOwnable.ownerAtIndex` is a Yubikey P256 public key, this should be `abi.encodePacked(r, s)`
        /// @dev If `MultiOwnable.ownerAtIndex` is a Yubikey RSA2048 public key, this should be `abi.encodePacked(s)`
        bytes signatureData;
    }

    /// @notice Reserved nonce key (upper 192 bits of `PackedUserOperation.nonce`) for cross-chain replayable
    ///         transactions.
    ///
    /// @dev MUST BE the `PackedUserOperation.nonce` key when `PackedUserOperation.calldata` is calling
    ///      `executeWithoutChainIdValidation`and MUST NOT BE `PackedUserOperation.nonce` key when `PackedUserOperation.calldata` is
    ///      NOT calling `executeWithoutChainIdValidation`.
    ///
    /// @dev Helps enforce sequential sequencing of replayable transactions.
    uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

    /// @notice Thrown when a call is passed to `executeWithoutChainIdValidation` that is not allowed by
    ///         `canSkipChainIdValidation`
    ///
    /// @param selector The selector of the call.
    error SelectorNotAllowed(bytes4 selector);

    /// @notice Thrown in validateUserOp if the key of `PackedUserOperation.nonce` does not match the calldata.
    ///
    /// @dev Calls to `this.executeWithoutChainIdValidation` MUST use `REPLAYABLE_NONCE_KEY` and
    ///      calls NOT to `this.executeWithoutChainIdValidation` MUST NOT use `REPLAYABLE_NONCE_KEY`.
    ///
    /// @param key The invalid `PackedUserOperation.nonce` key.
    error InvalidNonceKey(uint256 key);

     /// @notice Reverts if the caller is not the EntryPoint.
    modifier onlyEntryPoint() virtual {
        if (msg.sender != address(entryPoint())) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Reverts if the caller is neither the EntryPoint, the yubikey, nor the account itself.
    /// @dev If called directly, verifies yubikey's `data` `signature`.
    modifier onlyAuthorized(bytes memory data, bytes memory signature) virtual {
        if(msg.sender != address(entryPoint()) || msg.sender != address(this)){
            bytes32 msgHash = _hashStruct(keccak256(abi.encode(keccak256(data), block.chainid, nonce())));
            _incrementNonce();
            bytes memory signerBytes = signerAtIndex(0);

            require(
                _checkSignature(msgHash, signerBytes, signature),
                "invalid signature"
            );
        }
        _;
    }

    /// @notice Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
    ///
    /// @dev Subclass MAY override this modifier for better funds management (e.g. send to the
    ///      EntryPoint more than the minimum required, so that in future transactions it will not
    ///      be required to send again).
    ///
    /// @param missingAccountFunds The minimum value this modifier should send the EntryPoint which
    ///                            MAY be zero, in case there is enough deposit, or the userOp has a
    ///                            paymaster.
    modifier payPrefund(uint256 missingAccountFunds) virtual {
        _;

        assembly ("memory-safe") {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

     constructor(address _entryPoint, address _verifier) CustomSlotInitializable(_INITIALIZABLE_STORAGE_POSITION) {
        VERIFIER2 = IVerifier2(_verifier);
        ENTRY_POINT = IEntryPoint(_entryPoint);
        _disableInitializers();
    }

    function initialize(
        bytes calldata ykPubKey, 
        bytes[] calldata signers, 
        uint64[] calldata signerExpiries
    ) public payable initializer {
        _initializeSigners(ykPubKey, signers, signerExpiries);
    }

    /// @inheritdoc IAccount
    ///
    /// @notice ERC-4337 `validateUserOp` method. The EntryPoint will
    ///         call `PackedUserOperation.sender.call(PackedUserOperation.callData)` only if this validation call returns
    ///         successfully.
    ///
    /// @dev Signature failure should be reported by returning 1 (see: `this._isValidSignature`). This
    ///      allows making a "simulation call" without a valid signature. Other failures (e.g. invalid signature format)
    ///      should still revert to signal failure.
    /// @dev Reverts if the `PackedUserOperation.nonce` key is invalid for `PackedUserOperation.calldata`.
    /// @dev Reverts if the signature format is incorrect or invalid for owner type.
    ///
    /// @param userOp              The `PackedUserOperation` to validate.
    /// @param userOpHash          The `PackedUserOperation` hash, as computed by `EntryPoint.getUserOpHash(PackedUserOperation)`.
    /// @param missingAccountFunds The missing account funds that must be deposited on the Entrypoint.
    ///
    /// @return validationData The encoded `ValidationData` structure:
    ///                        `(uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)`
    ///                        where `validUntil` is 0 (indefinite) and `validAfter` is 0.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual onlyEntryPoint payPrefund(missingAccountFunds) returns (uint256 validationData){
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

    /// @notice Executes calldata `data` on this account (i.e. self call).
    ///
    /// @dev Can only be called by the Entrypoint.
    /// @dev Reverts if the given call is not authorized to skip the chain ID validtion.
    /// @dev `IAccount.validateUserOp()` will recompute the `userOpHash` without the chain ID before validating
    ///      it if the `PackedUserOperation.calldata` is calling this function. This allows certain UserOperations
    ///      to be replayed for all accounts sharing the same address across chains. E.g. This may be
    ///      useful for syncing signer changes.
    ///
    /// @param data Tx calldata to execute.
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

    /// @notice Executes the given call from this account(with signature proof?).
    ///
    /// @dev Can only be called by the Entrypoint or an owner of this account (including itself).
    /// @dev `signature` is only required when invoking the function directly.
    ///
    /// @param data Tx calldata to execute.
    /// @param signature Tx signature to verify.
    function execute(bytes calldata data, bytes calldata signature) external virtual onlyAuthorized(data, signature){
        (Call[] memory calls) = abi.decode(data, (Call[]));
        _executeCalls(calls);
    }

    /// @notice Returns the address of the EntryPoint v0.7.
    ///
    /// @return The address of the EntryPoint v0.7.
    function entryPoint() public view virtual returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    /// @notice Computes the hash of the `PackedUserOperation` in the same way as EntryPoint v0.7, but
    ///         leaves out the chain ID.
    ///
    /// @dev This allows accounts to sign a hash that can be used on many chains.
    ///
    /// @param userOp The `PackedUserOperation` to compute the hash for.
    ///
    /// @return The `PackedUserOperation` hash, which does not depend on chain ID.
     function getUserOpHashWithoutChainId(PackedUserOperation calldata userOp) public view virtual returns (bytes32) {
        return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
    }

    /// @notice Returns the implementation of the ERC1967 proxy.
    ///
    /// @return $ The address of implementation contract.
    function implementation() public view returns (address $) {
        assembly {
            $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    /// @notice Returns whether `functionSelector` can be called in `executeWithoutChainIdValidation`.
    ///
    /// @param functionSelector The function selector to check.
    ////
    /// @return `true` is the function selector is allowed to skip the chain ID validation, else `false`.
    function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
        if (
            functionSelector == MultiSignable2.addSignerAddress.selector
                || functionSelector == MultiSignable2.addSignerP256PublicKey.selector
                || functionSelector == MultiSignable2.addSignerRSA2048PublicKey.selector
                || functionSelector == MultiSignable2.removeSignerAtIndex.selector
                || functionSelector == UUPSUpgradeable.upgradeToAndCall.selector
        ) {
            return true;
        }
        return false;
    }

    /// @notice Executes `calls` from this account.
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

    /// @notice Checks if signature `signatureData` is valid.
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

    /// @inheritdoc ERC1271
    ///
    /// @dev Used by both `ERC1271.isValidSignature` AND `IAccount.validateUserOp` signature validation.
    /// @dev Reverts if signer is not compatible with `signature` format.
    ///
    /// @param signature ABI encoded `SignatureWrapper`.
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

        revert Unauthorized();        
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