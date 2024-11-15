// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import {SignatureType} from "../libraries/StructInputs.sol";
import {EnumerableSet} from "openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

struct MultiSignableStorage {
    /// @dev Yubikey public-key hash.
    bytes32 ykPubKeyHash;
    /// @dev Account nonce and signature type bitpacked together.
    uint256 accountSigTypeWithNonce;
    /// @dev All Account's signers.
    EnumerableSet.Bytes32Set signers;
    /// @dev Mapping of signers to their various expiry.
    mapping(bytes32 signer_ => uint64 expiry) signerExpiry;
}

/// modified from (https://github.com/coinbase/smart-wallet/blob/main/src/MultiOwnable.sol)
contract MultiSignable {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    /// @dev Slot for the `MultiSignableStorage` struct in storage.
    ///      Computed from
    ///      keccak256(abi.encode(uint256(keccak256("YkWallet.storage.MultiSignable")) - 1)) & ~bytes32(uint256(0xff))
    ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
    bytes32 private constant MUTLI_SIGNABLE_STORAGE_LOCATION =
        0xf2dda4478a12a4e5211f1b1922c7639f86fd0fb1505a408fba3d9fa61afcc600;

    /// @notice Thrown when the `msg.sender` is not a signer and is trying to call a privileged function.
    error Unauthorized();
    /// @notice Thrown when trying to re-initialize contract.
    error AlreadyInitialized();

    /// @notice Emitted when a new signer is registered.
    ///
    /// @param signer The signer added.
    event AddSigner(bytes32 indexed signer);

    /// @notice Emitted when an signer is removed.
    ///
    /// @param signer The signer removed.
    event RemoveSigner(bytes32 indexed signer);

    /// @notice Access control modifier ensuring the caller is only self.
    modifier onlySelf(){
        if(msg.sender != address(this)){
            revert Unauthorized();
        }
        _;
    }

    /// @notice Adds a new signer ID.
    /// @dev signer ID can be either an ethereum-address or yubikey key hash.
    ///
    /// @param _signer The signer ID to add.
    /// @param _expiry The signer's expiry.
    function grantSignerPriviledge(bytes32 _signer, uint64 _expiry) public virtual onlySelf {
        _addSigner(_signer, _expiry);
    }


    /// @notice Removes signer ID `_signer`.
    ///
    /// @param _signer signer to be removed.
    function revokeSignerPriviledge(bytes32 _signer) public virtual onlySelf {
        _removeSigner(_signer);
    }

    /// @notice Checks if `signer` is a valid signer.
    function hasSignerPriviledge(bytes32 signer) internal view returns(bool){
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        if(signer != $.ykPubKeyHash){
            return $.signerExpiry[signer] >= block.timestamp;
        }
        return true;
    }

    /// @notice Returns yubikey signer key algo.
    function accountSigType() internal view returns(SignatureType){
        return SignatureType(_getMultiSignableStorage().accountSigTypeWithNonce >> 248);
    }

    /// @notice Returns yubikey signer key hash.
    function pubKeyHash() internal view returns(bytes32){
        return _getMultiSignableStorage().ykPubKeyHash;
    }

    /// @notice Returns account tx nonce.
    function nonce() internal view returns(uint256){
        return uint256(_getMultiSignableStorage().accountSigTypeWithNonce) & 0xFF;
    }

    /// @notice Initialize the signers of this contract.
    ///
    /// @dev Intended to be called when contract is first deployed and never again.
    ///
    /// @param _sigType Yubikey signer key algo.
    /// @param _ykPubKeyHash Yubikey public key hash
    /// @param signers The initial set of signers.
    /// @param _expiries The signers expiries.
    function _initializeSigners(
        SignatureType _sigType, 
        bytes32 _ykPubKeyHash,
        bytes32[] calldata signers,
        uint64[] calldata _expiries
    ) internal {
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        if($.ykPubKeyHash != bytes32(0)){
            revert AlreadyInitialized();
        }
        $.ykPubKeyHash = _ykPubKeyHash;
        $.accountSigTypeWithNonce = uint256(uint8(_sigType)) << 248;
        for (uint256 i; i < signers.length; i++) {
            _addSigner(signers[i], _expiries[i]);
        }
    }

    /// @dev Increments account tx nonce.
    function _incrementNonce() internal {
        _getMultiSignableStorage().accountSigTypeWithNonce++;
    }

     /// @notice Adds signer ID.
    ///
    /// @param _signer The signer  to register.
    /// @param _expiry The Signer public key expiry.
    function _addSigner(bytes32 _signer, uint64 _expiry) internal {
        require(_expiry > block.timestamp, "invalid expiry timestamp");
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        $.signerExpiry[_signer] = _expiry;
        $.signers.add(_signer);
        emit AddSigner(_signer);
    }

    /// @notice Removes signer.
    ///
    /// @param _signer The signer to be removed.
    function _removeSigner(bytes32 _signer) internal {
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        require($.signerExpiry[_signer] > 0, "signer doesn't exist yet");
        $.signerExpiry[_signer] = 0;
        $.signers.remove(_signer);
        emit RemoveSigner(_signer);
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