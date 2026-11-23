// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title PrivShare audit contract
/// @notice Dual-party approval of query types and a tamper-evident log of executed queries.
///         Only fingerprints (SHA-256 of the off-chain audit record) are stored - never personal data.
contract PrivShareAudit {
    uint256 public constant K_MIN = 10;

    address public immutable university;   // data owner's account
    address public immutable partner;      // labor-market partner's account
    address public immutable logger;       // PrivShare backend account that records executed queries

    struct Record {
        bytes32 recordHash;   // SHA-256 of the off-chain audit record
        bytes32 queryType;    // keccak256 of the query type name
        uint64 timestamp;
    }

    mapping(bytes32 => bool) public approvedByUniversity;
    mapping(bytes32 => bool) public approvedByPartner;
    Record[] private records;

    event ApprovalChanged(bytes32 indexed queryType, address indexed party, bool approved);
    event QueryLogged(uint256 indexed index, bytes32 indexed queryType, bytes32 recordHash);

    error NotAParty();
    error NotLogger();
    error NotApproved();
    error GroupTooSmall();
    error EmptyHash();
    error NoSuchRecord();

    constructor(address _university, address _partner, address _logger) {
        university = _university;
        partner = _partner;
        logger = _logger;
    }

    /// @notice The caller approves a query type for its own side only.
    function approveQueryType(bytes32 queryType) external {
        _setApproval(queryType, true);
    }

    /// @notice The caller withdraws its own side's approval.
    function revokeQueryType(bytes32 queryType) external {
        _setApproval(queryType, false);
    }

    function _setApproval(bytes32 queryType, bool value) private {
        if (msg.sender == university) {
            approvedByUniversity[queryType] = value;
        } else if (msg.sender == partner) {
            approvedByPartner[queryType] = value;
        } else {
            revert NotAParty();
        }
        emit ApprovalChanged(queryType, msg.sender, value);
    }

    /// @notice True only when BOTH parties approved the query type.
    function isApproved(bytes32 queryType) public view returns (bool) {
        return approvedByUniversity[queryType] && approvedByPartner[queryType];
    }

    /// @notice Record the fingerprint of an executed query. Enforces approval and k >= 10.
    function logQuery(bytes32 queryType, bytes32 recordHash, uint256 groupSize) external returns (uint256 index) {
        if (msg.sender != logger) revert NotLogger();
        if (!isApproved(queryType)) revert NotApproved();
        if (groupSize < K_MIN) revert GroupTooSmall();
        if (recordHash == bytes32(0)) revert EmptyHash();
        records.push(Record(recordHash, queryType, uint64(block.timestamp)));
        index = records.length - 1;
        emit QueryLogged(index, queryType, recordHash);
    }

    function count() external view returns (uint256) {
        return records.length;
    }

    function getRecord(uint256 index) external view returns (bytes32 recordHash, bytes32 queryType, uint64 timestamp) {
        if (index >= records.length) revert NoSuchRecord();
        Record storage r = records[index];
        return (r.recordHash, r.queryType, r.timestamp);
    }
}
