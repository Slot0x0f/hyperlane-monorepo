// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "./AbstractOptimisticIsm.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {Message} from "../../libs/Message.sol";

/// @title OptimisticIsm Contract
/// @notice This contract is a part of the optimistic verification flow, enabling pre-verification of messages and fraud marking.
contract OptimisticIsm is AbstractOptimisticIsm {
    using Message for bytes;
    using Address for address;
    // State variables
    address public currentSubmodule;
    // Struct to represent a pre-verified message
    struct PreVerifiedMessage {
        bool isVerified;
        uint256 timestamp;
    }

    /**
     * @notice Emitted when a module is set for a domain
     * @param module The ISM to use.
     */
    event ModuleSet(address module);

    event ModuleMarked(address module);

    event ModuleFraudulent(address module);

    // Mapping from messageID to its verification status and timestamp
    mapping(bytes32 => PreVerifiedMessage) public preVerifiedMessages;
    mapping(address => mapping(address => bool))
        private watcherMarkedFraudulent;
    mapping(address => uint8) private fraudCount;
    uint8 public threshold;

    constructor(
        address _owner,
        uint32 _fraudWindow,
        address[] memory _watchers,
        uint8 _threshold
    ) AbstractOptimisticIsm(_owner, _fraudWindow, _watchers) {
        threshold = _threshold;
    }

    function setSubmodule(address _submodule) external onlyOwner {
        require(_submodule.isContract(), "!contract");
        currentSubmodule = _submodule;
        emit ModuleSet(_submodule);
    }

    function markFraudulent(address _submodule) external override onlyWatcher {
        require(
            !watcherMarkedFraudulent[_submodule][msg.sender],
            "Watcher has already marked this submodule as fraudulent"
        );

        watcherMarkedFraudulent[_submodule][msg.sender] = true;
        fraudCount[_submodule] = fraudCount[_submodule] + 1;

        emit ModuleMarked(_submodule);

        if (fraudCount[_submodule] >= threshold) {
            fraudulentSubmodules[_submodule] = true;
            emit ModuleFraudulent(_submodule);
        }
    }

    function preVerify(bytes calldata _metadata, bytes calldata _message)
        external
        override
        returns (bool)
    {
        IInterchainSecurityModule _submodule = IInterchainSecurityModule(
            currentSubmodule
        );
        require(
            _submodule.verify(_metadata, _message),
            "Submodule verification failed"
        );
        bytes32 messageId = Message.id(_message);
        // Check if the message hasn't been pre-verified before
        require(
            !preVerifiedMessages[messageId].isVerified,
            "Message already pre-verified"
        );
        // Store the message as pre-verified
        preVerifiedMessages[messageId] = PreVerifiedMessage({
            isVerified: true,
            timestamp: block.timestamp
        });

        return true;
    }

    /// @notice Returns the current submodule.
    /// @param _message The message for which the submodule is needed.
    /// @return IInterchainSecurityModule instance of the current submodule.
    function submodule(bytes calldata _message)
        external
        view
        override
        returns (IInterchainSecurityModule)
    {
        /// Implement custom logic if dealing with many submodules
        return IInterchainSecurityModule(currentSubmodule);
    }

    /// @notice Returns the type of this module.
    /// @return A uint8 representing the type of this module.
    function moduleType() external view override returns (uint8) {
        return uint8(Types.OPTIMISTIC);
    }

    /// @notice Verifies a message.
    /// @param _metadata Metadata associated with the message.
    /// @param _message The message to verify.
    /// @return A boolean indicating success.
    function verify(bytes calldata _metadata, bytes calldata _message)
        external
        override
        returns (bool)
    {
        bytes32 messageId = Message.id(_message);
        require(
            preVerifiedMessages[messageId].isVerified,
            "Message not pre-verified"
        );
        require(
            !isSubmoduleCompromised(address(currentSubmodule)),
            "Submodule is compromised"
        );
        require(
            block.timestamp >=
                preVerifiedMessages[messageId].timestamp + fraudWindow,
            "Fraud window has not elapsed"
        );
        // Clear the pre-verified status to prevent potential re-entry
        preVerifiedMessages[messageId].isVerified = false;

        return true;
    }

    /// @notice Returns the threshold for marking a submodule as fraudulent.
    /// @return A uint8 value representing the threshold.
    function getWatcherThreshold() public view override returns (uint8) {
        return threshold;
    }

    /// @notice Checks if an address is a watcher.
    /// @param _address The address to check.
    /// @return A boolean indicating if the address is a watcher.
    function isWatcher(address _address) public view override returns (bool) {
        return watcherBool[_address];
    }

    /// @notice Checks if a submodule is compromised.
    /// @param _submodule The address of the submodule to check.
    /// @return A boolean indicating if the submodule is compromised.
    function isSubmoduleCompromised(address _submodule)
        public
        view
        returns (bool)
    {
        return fraudCount[_submodule] >= threshold;
    }

    function getSubmoduleFraudMarks(address _submodule)
        public
        view
        returns (uint256)
    {
        return fraudCount[_submodule];
    }
}
