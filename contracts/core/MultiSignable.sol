// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import {SignatureType} from "../libraries/StructInputs.sol";
import {EnumerableSet} from "openzeppelin-contracts/contracts/utils/structs/EnumerableSet.sol";

struct MultiSignableStorage {
    bytes32 ykPubKeyHash;
    uint256 accountSigTypeWithNonce;
    EnumerableSet.Bytes32Set signers;
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

    error Unauthorized();
    error InvalidPubKeyHash();
    error AlreadyInitialized();

    event AddSigner(bytes32 indexed signer);
    event RemoveSigner(bytes32 indexed signer);

    modifier onlySelf(){
        if(msg.sender != address(this)){
            revert Unauthorized();
        }
        _;
    }

    function grantSignerPriviledge(bytes32 _signer, uint64 _expiry) public virtual onlySelf {
        _addSigner(_signer, _expiry);
    }

    function revokeSignerPriviledge(bytes32 _signer) public virtual onlySelf {
        _removeSigner(_signer);
    }

    function hasSignerPriviledge(bytes32 signer) internal view returns(bool){
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        if(signer != $.ykPubKeyHash){
            return $.signerExpiry[signer] >= block.timestamp;
        }
        return true;
    }

    function accountSigType() internal view returns(SignatureType){
        return SignatureType(_getMultiSignableStorage().accountSigTypeWithNonce >> 248);
    }

    function pubKeyHash() internal view returns(bytes32){
        return _getMultiSignableStorage().ykPubKeyHash;
    }

    function nonce() internal view returns(uint256){
        return uint256(_getMultiSignableStorage().accountSigTypeWithNonce) & 0xFF;
    }

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

    function _incrementNonce() internal {
        _getMultiSignableStorage().accountSigTypeWithNonce++;
    }

    function _addSigner(bytes32 _signer, uint64 _expiry) internal {
        require(_expiry > block.timestamp, "invalid expiry timestamp");
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        $.signerExpiry[_signer] = _expiry;
        $.signers.add(_signer);
        emit AddSigner(_signer);
    }

    function _removeSigner(bytes32 _signer) internal {
        MultiSignableStorage storage $ = _getMultiSignableStorage();
        require($.signerExpiry[_signer] > 0, "signer doesn't exist yet");
        $.signerExpiry[_signer] = 0;
        $.signers.remove(_signer);
        emit RemoveSigner(_signer);
    }
   
    function _getMultiSignableStorage() internal pure returns (MultiSignableStorage storage $) {
        assembly ("memory-safe") {
            $.slot := MUTLI_SIGNABLE_STORAGE_LOCATION
        }
    }
}