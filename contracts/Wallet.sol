// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ERC1271} from "./core/ERC1271.sol";
import {MultiSignable} from "./core/MultiSignable.sol";
import {CustomSlotInitializable} from "./core/CustomSlotInitializable.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
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
/// modified from https://github.com/coinbase/smart-wallet/blob/main/src/CoinbaseSmartWallet.sol
contract Wallet is ERC1271, IAccount, CustomSlotInitializable, MultiSignable, UUPSUpgradeable, Receiver {

    /// @notice Verifier contract to verfy signature proof.
    IVerifier internal immutable VERIFIER;
    /// @notice Entrypoint contract.
    IEntryPoint internal immutable ENTRY_POINT;
    /// @dev Computed from keccak256(abi.encode(uint256(keccak256("YkWallet.storage.initializable")) - 1)) & ~bytes32(uint256(0xff)); 
    bytes32 internal constant _INITIALIZABLE_STORAGE_POSITION =
        0x449b64fc4e5b10ff03eeced669eb8cc5176fdc16ed36656dc722af4fee461700;

    /// @notice A wrapper struct used for signature validation so that callers
    ///         can identify the signer.
    struct SignatureWrapper {
        /// @notice The signer key data.
        /// @dev If the signer is a yubikey wallet account, this should be `abi.encode(keyHash, sigType)`
        /// @dev If the signer is an ethereum address, the should be padded i.e `abi.encode(address, 0)`
        bytes signerData;
        /// @dev If the signer is an ethereum address, this should be `abi.encodePacked(r, s, v)`
        /// @dev If the signer is a yubikey wallet account, this should be `signatureProof`
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

    /// @notice Thrown in validateUserOp if the key of `PackedUserOperation.nonce` does not match the calldata.
    ///
    /// @dev Calls to `this.executeWithoutChainIdValidation` MUST use `REPLAYABLE_NONCE_KEY` and
    ///      calls NOT to `this.executeWithoutChainIdValidation` MUST NOT use `REPLAYABLE_NONCE_KEY`.
    ///
    /// @param key The invalid `PackedUserOperation.nonce` key.
    error InvalidNonceKey(uint256 key);

    /// @notice Thrown when a call is passed to `executeWithoutChainIdValidation` that is not allowed by
    ///         `canSkipChainIdValidation`
    ///
    /// @param selector The selector of the call.
    error SelectorNotAllowed(bytes4 selector);

    /// @notice Reverts if the caller is not the EntryPoint.
    modifier onlyEntryPoint() virtual {
        if (msg.sender != address(entryPoint())) {
            revert Unauthorized();
        }
        _;
    }

    /// @notice Reverts if the caller is neither the EntryPoint, the yubikey, nor the account itself.
    /// @dev If called directly, verifies signature proof `_proof` to prove `data` was signed by yubikey.
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
        VERIFIER = IVerifier(_verifier);
        ENTRY_POINT = IEntryPoint(_entryPoint);
        _disableInitializers();
    }
    
    /// @notice Initializes this account.
    ///
    /// @param sigType Yubikey signing key algorithm. i.e RSA2048 or ECCP256(secp256r1).
    /// @param _pubKeyHash Hash(SHA256) of the yubikey signing key.
    /// @param signers Initial account signers alongside the yubikey signing key.
    /// @param signerExpiries Timestamp when initial account signers become invalid(can no longer sign txs).
    function initialize(
        SignatureType sigType, 
        bytes32 _pubKeyHash, 
        bytes32[] calldata signers, 
        uint64[] calldata signerExpiries
    ) public payable initializer {
        _initializeSigners(sigType, _pubKeyHash, signers, signerExpiries);
    }

    /// @notice Executes the given call from this account(with signature proof?).
    ///
    /// @dev Can only be called by the Entrypoint or an owner of this account (including itself).
    /// @dev `proof` is only required when invoking the function directly.
    ///
    /// @param data Tx calldata to execute.
    /// @param proof Signature proof to prove `data` was signed by yubikey.
    function execute(bytes calldata data, bytes calldata proof) external virtual onlyAuthorized(data, proof){
        (Call[] memory calls) = abi.decode(data, (Call[]));
        _executeCalls(calls);
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
        for (uint256 i = 0; i < calls.length; i++) {
            Call memory call = calls[i];
            bytes4 selector = bytes4(call.data);
            if (!canSkipChainIdValidation(selector)) {
                revert SelectorNotAllowed(selector);
            }
        }
        _executeCalls(calls);
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
            functionSelector == MultiSignable.grantSignerPriviledge.selector
                || functionSelector == MultiSignable.revokeSignerPriviledge.selector
                || functionSelector == UUPSUpgradeable.upgradeToAndCall.selector
        ) {
            return true;
        }
        return false;
    }
    
    /// @notice Returns the address of the EntryPoint v0.7.
    ///
    /// @return The address of the EntryPoint v0.7.
    function entryPoint() public view virtual returns (IEntryPoint) {
        return ENTRY_POINT;
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

    /// @notice Checks if signature proof `_proof` is valid.
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

    /// @inheritdoc ERC1271
    ///
    /// @dev Used by both `ERC1271.isValidSignature` AND `IAccount.validateUserOp` signature validation.
    /// @dev Reverts if signer is not compatible with `signature` format.
    ///
    /// @param signature ABI encoded `SignatureWrapper`.
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

    /// @inheritdoc ERC1271
    function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
        return ("Yubikey Smart Wallet", "1");
    }
}