// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "./AbstractOptimisticIsm.sol";

contract OptimisticIsm is AbstractOptimisticIsm {
    // State variables
    address public currentSubmodule;
    // Struct to represent a pre-verified message
    struct PreVerifiedMessage {
        bool isVerified;
        uint256 timestamp;
    }

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
        currentSubmodule = _submodule;
    }

    function markFraudulent(address _submodule) external override onlyWatcher {
        require(
            !watcherMarkedFraudulent[_submodule][msg.sender],
            "Watcher has already marked this submodule as fraudulent"
        );

        watcherMarkedFraudulent[_submodule][msg.sender] = true;
        fraudCount[_submodule]++;

        if (fraudCount[_submodule] >= threshold) {
            fraudulentSubmodules[_submodule] = true;
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

    function submodule(bytes calldata _message)
        external
        view
        override
        returns (IInterchainSecurityModule)
    {
        return IInterchainSecurityModule(currentSubmodule);
    }

    function moduleType() external view override returns (uint8) {
        return uint8(Types.ROUTING);
    }

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

    function getWatcherThreshold() public view override returns (uint8) {
        return threshold;
    }

    function isWatcher(address _address) public view override returns (bool) {
        return watcherBool[_address];
    }

    function isSubmoduleCompromised(address _submodule)
        public
        view
        returns (bool)
    {
        return fraudCount[_submodule] >= threshold;
    }
}
