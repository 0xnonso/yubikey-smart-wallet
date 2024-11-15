// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

struct MultiSignableStorage {
    /// @dev Tracks the index of the next signer to add.
    uint256 nextSignerIndex;
    /// @dev Tracks number of signers that have been removed.
    uint256 removedSignersCount;
    /// @dev Account nonce. Only incremented when this account is called directly.
    uint256 nonce;

    /// @dev Maps index to signer bytes, used to idenfitied signers via a uint256 index.
    ///
    ///      Some uses—-such as signature validation for secp256r1 public key owners—-
    ///      requires the caller to assert the public key of the caller. To economize calldata,
    ///      we allow an index to identify a signer, so that the full signer bytes do
    ///      not need to be passed.
    ///
    ///      The `signer` bytes should either be
    ///         - An ABI encoded Ethereum address
    ///         - An ABI encoded public key
    mapping(uint256 index => bytes signer) signerAtIndex;
    /// @dev Mapping of bytes to booleans indicating whether or not
    ///      bytes_ is an signer of this contract.
    mapping(bytes bytes_ => bool isSigner_) isSigner;
    /// @dev Mapping of signer bytes to expiry.
    mapping(bytes signer_ => uint64 expiry) signerExpiry;
}

/// @author Coinbase (https://github.com/coinbase/smart-wallet/blob/main/src/MultiOwnable.sol)
/// modified from https://github.com/coinbase/smart-wallet/blob/main/src/MultiOwnable.sol
contract MultiSignable2 {
    /// @dev Slot for the `MultiSignableStorage` struct in storage.
    ///      Computed from
    ///      keccak256(abi.encode(uint256(keccak256("YkWallet.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
    ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
    bytes32 private constant MUTLI_SIGNABLE_STORAGE_LOCATION =
        0xf2dda4478a12a4e5211f1b1922c7639f86fd0fb1505a408fba3d9fa61afcc600;

    /// @notice Thrown when the `msg.sender` is not a signer and is trying to call a privileged function.
    error Unauthorized();

    // @notice Thrown when trying to add an already registered signer.
    ///
    /// @param signer The signer bytes.
    error AlreadySigner(bytes signer);

    /// @notice Thrown when trying to remove a signer from an index that is empty.
    ///
    /// @param index The targeted index for removal.
    error NoSignerAtIndex(uint256 index);

    /// @notice Thrown when `signer` argument does not match signer found at index.
    ///
    /// @param index         The index of the signer to be removed.
    /// @param expectedSigner The signer passed in the remove call.
    /// @param actualSigner   The actual signer at `index`.
    error WrongSignerAtIndex(uint256 index, bytes expectedSigner, bytes actualSigner);

    /// @notice Thrown when a provided signer is neither of valid bytes length (for public key)
    ///         nor a ABI encoded address.
    ///
    /// @param signer The invalid signer.
    error InvalidSignerBytesLength(bytes signer);

    /// @notice Thrown if a provided signer is 32 bytes long but does not fit in an `address` type.
    ///
    /// @param signer The invalid signer.
    error InvalidEthereumAddressSigner(bytes signer);

    /// @notice Thrown when removeSignerAtIndex is called and there is only one current signer.
    error LastSigner();

    /// @notice Thrown when there is an attempt to modify yubikey public-key.
    error CannotRemoveYKPublicKey();

    /// @notice Emitted when a new signer is registered.
    ///
    /// @param index The signer index of the signer added.
    /// @param signer The signer added.
    event AddSigner(uint256 indexed index, bytes signer);

    /// @notice Emitted when an signer is removed.
    ///
    /// @param index The signer index of the signer removed.
    /// @param signer The signer removed.
    event RemoveSigner(uint256 indexed index, bytes signer);


    /// @notice Access control modifier ensuring the caller is only self.
    modifier onlySelf() virtual {
        if (msg.sender != address(this)) {
            revert Unauthorized();
        }
        _;
    }

    /// @notice Adds a new Ethereum-address signer.
    ///
    /// @param signer The signer address.
    /// @param _expiry The signer address expiry.
    function addSignerAddress(address signer, uint64 _expiry) external virtual onlySelf {
        _addSignerAtIndex(abi.encode(signer), _getMultiSignableStorage().nextSignerIndex++, _expiry);
    }

    /// @notice Adds a new P256 public-key signer.
    ///
    /// @param x The signer P256 public key x coordinate.
    /// @param y The signer P256 public key y coordinate.
    /// @param _expiry The signer public-key expiry.
    function addSignerP256PublicKey(bytes32 x, bytes32 y, uint64 _expiry) external virtual onlySelf {
        _addSignerAtIndex(abi.encode(x, y), _getMultiSignableStorage().nextSignerIndex++, _expiry);
    }

    /// @notice Adds a new RSA2048 public-key signer.
    ///
    /// @param pubKeyModulus The signer RSA2048 public key.
    /// @param _expiry The signer public-key expiry.
    function addSignerRSA2048PublicKey(bytes memory pubKeyModulus, uint64 _expiry) external virtual onlySelf {
        if(pubKeyModulus.length != 256) revert();
        _addSignerAtIndex(pubKeyModulus, _getMultiSignableStorage().nextSignerIndex++, _expiry);
    }

    /// @notice Removes signer at the given `index`.
    ///
    /// @dev Reverts if the signer is not registered at `index`.
    /// @dev Reverts if there is currently more than one signer.
    /// @dev Reverts if `signer` does not match bytes found at `index`.
    ///
    /// @param index The index of the signer to be removed.
    /// @param signer The ABI encoded bytes of the signer to be removed.
    function removeSignerAtIndex(uint256 index, bytes calldata signer) external virtual onlySelf {
        if (signerCount() == 1) {
            revert LastSigner();
        }

        _removeSignerAtIndex(index, signer);
    }

    /// @dev Increments account tx nonce.
    function _incrementNonce() internal {
        _getMultiSignableStorage().nonce++;
    }

    /// @notice Returns account tx nonce.
    function nonce() internal view returns(uint256){
        return _getMultiSignableStorage().nonce;
    }

    /// @notice Checks if `signer` is a valid signer.
    function canSign(bytes memory signer) public view virtual returns(bool){
        return _getMultiSignableStorage().signerExpiry[signer] >= block.timestamp;
    }

    /// @notice Checks if the given `account` address is registered as signer.
    ///
    /// @param account The account address to check.
    ///
    /// @return `true` if the account is a signer else `false`.
    function isSignerAddress(address account) public view virtual returns (bool) {
        return _getMultiSignableStorage().isSigner[abi.encode(account)];
    }

    /// @notice Checks if the given `x`, `y` P256 public key is registered as signer.
    ///
    /// @param x The P256 public key x coordinate.
    /// @param y The P256 public key y coordinate.
    ///
    /// @return `true` if the account is a signer else `false`.
    function isSignerP256PublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) {
        return _getMultiSignableStorage().isSigner[abi.encode(x, y)];
    }

     /// @notice Checks if the given RSA2048 public key is registered as signer.
    ///
    /// @param pubKeyModulus The RSA2048 public key modulus.
    ///
    /// @return `true` if the account is a signer else `false`.
    function isSignerRSA2048PublicKey(bytes memory pubKeyModulus) public view virtual returns (bool) {
        return _getMultiSignableStorage().isSigner[pubKeyModulus];
    }

    /// @notice Checks if the given `account` bytes is registered as a signer.
    ///
    /// @param account The account, should be ABI encoded address or public key.
    ///
    /// @return `true` if the account is a signer else `false`.
    function isSignerBytes(bytes memory account) public view virtual returns (bool) {
        return _getMultiSignableStorage().isSigner[account];
    }

    /// @notice Returns the signer bytes at the given `index`.
    ///
    /// @param index The index to lookup.
    ///
    /// @return The signer bytes (empty if no signer is registered at this `index`).
    function signerAtIndex(uint256 index) public view virtual returns (bytes memory) {
        return _getMultiSignableStorage().signerAtIndex[index];
    }

    /// @notice Returns the next index that will be used to add a new signer.
    ///
    /// @return The next index that will be used to add a new signer.
    function nextSignerIndex() public view virtual returns (uint256) {
        return _getMultiSignableStorage().nextSignerIndex;
    }

    /// @notice Returns the current number of signers
    ///
    /// @return The current signer count
    function signerCount() public view virtual returns (uint256) {
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        return $.nextSignerIndex - $.removedSignersCount;
    }

    /// @notice Tracks the number of signers removed
    ///
    /// @dev Used with `this.nextOwnerIndex` to avoid removing all signers
    ///
    /// @return The number of signers that have been removed.
    function removedSignersCount() public view virtual returns (uint256) {
        return _getMultiSignableStorage().removedSignersCount;
    }

    /// @notice Initialize the signers of this contract.
    ///
    /// @dev Intended to be called when contract is first deployed and never again.
    /// @dev `ykPubKey` public key cannot be removed after initialization and is always set to max expiry.
    ///
    /// @param ykPubKey Yubikey public key.
    /// @param signers The initial set of signers.
    /// @param _expiries The signers expiries.
    function _initializeSigners(bytes calldata ykPubKey, bytes[] calldata signers, uint64[] calldata _expiries) internal virtual {
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        if (ykPubKey.length != 64 && ykPubKey.length != 256) {
            revert InvalidSignerBytesLength(ykPubKey);
        }
        _addSignerAtIndex(ykPubKey, 0, type(uint64).max);

        uint256 nextSignerIndex_ = $.nextSignerIndex;
        for (uint256 i; i < signers.length; i++) {
            if (signers[i].length != 32 && signers[i].length != 64 && signers[i].length != 256) {
                revert InvalidSignerBytesLength(signers[i]);
            }

            if (signers[i].length == 32 && uint256(bytes32(signers[i])) > type(uint160).max) {
                revert InvalidEthereumAddressSigner(signers[i]);
            }

            _addSignerAtIndex(signers[i], nextSignerIndex_++, _expiries[i]);
        }
        $.nextSignerIndex = nextSignerIndex_;
    }

    /// @notice Adds a signer at the given `index`.
    ///
    /// @dev Reverts if `signer` is already registered as an signer.
    ///
    /// @param signer The signer raw bytes to register.
    /// @param index The index to write to.
    /// @param expiry The Signer public key expiry.
    function _addSignerAtIndex(bytes memory signer, uint256 index, uint64 expiry) internal virtual {
        if (isSignerBytes(signer)) revert AlreadySigner(signer);
        if (index == 0 && signerAtIndex(index).length != 0) revert CannotRemoveYKPublicKey(); // Cannot remove OG Signer;
        if (expiry < block.timestamp) revert();
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        $.isSigner[signer] = true;
        $.signerAtIndex[index] = signer;
        $.signerExpiry[signer] = expiry;

        emit AddSigner(index, signer);
    }

    /// @notice Removes signer at the given `index`.
    ///
    /// @dev Reverts if the signer is not registered at `index`.
    /// @dev Reverts if `signer` does not match bytes found at `index`.
    /// @dev Reverts if `signer` to remove is yubikey public-key at index 0.
    ///
    /// @param index The index of the signer to be removed.
    /// @param signer The ABI encoded bytes of the signer to be removed.
    function _removeSignerAtIndex(uint256 index, bytes calldata signer) internal virtual {
        bytes memory signer_ = signerAtIndex(index);
        if (index == 0) revert CannotRemoveYKPublicKey(); // Cannot remove OG Signer;
        if (signer_.length == 0) revert NoSignerAtIndex(index);
        if (keccak256(signer_) != keccak256(signer)) {
            revert WrongSignerAtIndex({index: index, expectedSigner: signer, actualSigner: signer_});
        }

        MultiSignableStorage storage $ = _getMultiSignableStorage();
        delete $.isSigner[signer];
        delete $.signerAtIndex[index];
        delete $.signerExpiry[signer];
        $.removedSignersCount++;

        emit RemoveSigner(index, signer);
    }

    /// @notice Helper function to get a storage reference to the `MultiSignableStorage` struct.
    ///
    /// @return $ A storage reference to the `MultiSignableStorage` struct.
    function _getMultiSignableStorage() internal pure returns (MultiSignableStorage storage $) {
        assembly ("memory-safe") {
            $.slot := MUTLI_SIGNABLE_STORAGE_LOCATION
        }
    }
}