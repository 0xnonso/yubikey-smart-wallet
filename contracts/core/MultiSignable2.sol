// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

struct MultiSignableStorage {
    uint256 nextSignerIndex;
    uint256 removedSignersCount;
    uint256 nonce;

    mapping(uint256 index => bytes signer) signerAtIndex;
    mapping(bytes bytes_ => bool isSigner_) isSigner;
    mapping(bytes signer_ => uint64 expiry) signerExpiry;
}

/// @author Coinbase (https://github.com/coinbase/smart-wallet/blob/main/src/MultiOwnable.sol)
contract MultiSignable2 {
    /// @dev Slot for the `MultiSignableStorage` struct in storage.
    ///      Computed from
    ///      keccak256(abi.encode(uint256(keccak256("YkWallet.storage.MultiOwnable")) - 1)) & ~bytes32(uint256(0xff))
    ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
    bytes32 private constant MUTLI_SIGNABLE_STORAGE_LOCATION =
        0xf2dda4478a12a4e5211f1b1922c7639f86fd0fb1505a408fba3d9fa61afcc600;

    error Unauthorized();

    error AlreadySigner(bytes signer);

    error NoSignerAtIndex(uint256 index);

    error WrongSignerAtIndex(uint256 index, bytes expectedSigner, bytes actualSigner);

    error InvalidSignerBytesLength(bytes signer);

    error InvalidEthereumAddressSigner(bytes signer);

    error LastSigner();

    error NotLastSigner(uint256 signersRemaining);

    event AddSigner(uint256 indexed index, bytes signer);

    event RemoveSigner(uint256 indexed index, bytes signer);

    event CannotRemoveYKSigner();

    modifier onlySelf() virtual {
        if (msg.sender != address(this)) {
            revert Unauthorized();
        }
        _;
    }

    function addSignerAddress(address signer, uint64 _expiry) external virtual onlySelf {
        _addSignerAtIndex(abi.encode(signer), _getMultiSignableStorage().nextSignerIndex++, _expiry);
    }

    function addSignerP256PublicKey(bytes32 x, bytes32 y, uint64 _expiry) external virtual onlySelf {
        _addSignerAtIndex(abi.encode(x, y), _getMultiSignableStorage().nextSignerIndex++, _expiry);
    }

    function addSignerRSA2048PublicKey(bytes memory pubKeyModulus, uint64 _expiry) external virtual onlySelf {
        if(pubKeyModulus.length != 256) revert();
        _addSignerAtIndex(pubKeyModulus, _getMultiSignableStorage().nextSignerIndex++, _expiry);
    }

    function removeSignerAtIndex(uint256 index, bytes calldata signer) external virtual onlySelf {
        if (signerCount() == 1) {
            revert LastSigner();
        }

        _removeSignerAtIndex(index, signer);
    }

    function removeLastSigner(uint256 index, bytes calldata signer) external virtual onlySelf {
        uint256 signersRemaining = signerCount();
        if (signersRemaining > 1) {
            revert NotLastSigner(signersRemaining);
        }

        _removeSignerAtIndex(index, signer);
    }

    function _incrementNonce() internal {
        _getMultiSignableStorage().nonce++;
    }

    function nonce() internal view returns(uint256){
        return _getMultiSignableStorage().nonce;
    }

    function canSign(bytes memory signer) public view virtual returns(bool){
        return _getMultiSignableStorage().signerExpiry[signer] >= block.timestamp;
    }

    function isSignerAddress(address account) public view virtual returns (bool) {
        return _getMultiSignableStorage().isSigner[abi.encode(account)];
    }

    function isSignerP256PublicKey(bytes32 x, bytes32 y) public view virtual returns (bool) {
        return _getMultiSignableStorage().isSigner[abi.encode(x, y)];
    }

    function isSignerRSA2048PublicKey(bytes memory pubKeyModulus) public view virtual returns (bool) {
        return _getMultiSignableStorage().isSigner[pubKeyModulus];
    }

    function isSignerBytes(bytes memory account) public view virtual returns (bool) {
        return _getMultiSignableStorage().isSigner[account];
    }

    function signerAtIndex(uint256 index) public view virtual returns (bytes memory) {
        return _getMultiSignableStorage().signerAtIndex[index];
    }

    function nextSignerIndex() public view virtual returns (uint256) {
        return _getMultiSignableStorage().nextSignerIndex;
    }

    function signerCount() public view virtual returns (uint256) {
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        return $.nextSignerIndex - $.removedSignersCount;
    }

    function removedSignersCount() public view virtual returns (uint256) {
        return _getMultiSignableStorage().removedSignersCount;
    }

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

    function _addSignerAtIndex(bytes memory signer, uint256 index, uint64 expiry) internal virtual {
        if (isSignerBytes(signer)) revert AlreadySigner(signer);
        if (index == 0 && signerAtIndex(index).length != 0) revert(); // Cannot remove OG Signer;
        if (expiry < block.timestamp) revert();
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        $.isSigner[signer] = true;
        $.signerAtIndex[index] = signer;
        $.signerExpiry[signer] = expiry;

        emit AddSigner(index, signer);
    }

    function _removeSignerAtIndex(uint256 index, bytes calldata signer) internal virtual {
        bytes memory signer_ = signerAtIndex(index);
        if (index == 0) revert(); // Cannot remove OG Signer;
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

    function _getMultiSignableStorage() internal pure returns (MultiSignableStorage storage $) {
        assembly ("memory-safe") {
            $.slot := MUTLI_SIGNABLE_STORAGE_LOCATION
        }
    }
}