// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

import "../../interfaces/isms/IOptimisticIsm.sol";
import "../../libs/Message.sol";

abstract contract AbstractOptimisticIsm is IOptimisticIsm {
    using Message for bytes;

    address public owner;
    mapping(bytes32 => uint256) internal preVerifiedMessagesTimestamps;
    mapping(address => bool) internal fraudulentSubmodules;
    mapping(address => uint8) internal fraudVotes;
    mapping(address => mapping(address => bool)) private alreadyMarked; // submodule => watcher => marked
    address[] public watchers;
    mapping(address => bool) public watcherBool;

    uint32 public fraudWindow; // Example: 10 blocks

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    modifier onlyWatcher() {
        require(watcherBool[msg.sender], "Caller is not a watcher");
        _;
    }

    constructor(
        address _owner,
        uint32 _fraudWindow,
        address[] memory _watchers
    ) {
        owner = _owner;
        fraudWindow = _fraudWindow;
        require(_watchers.length > 0, "Watchers list cannot be empty");

        for (uint256 i = 0; i < _watchers.length; i++) {
            require(!watcherBool[_watchers[i]], "Duplicate watcher detected");

            watcherBool[_watchers[i]] = true;
            watchers.push(_watchers[i]);
        }
    }

    // Function to set the fraud window duration.
    function setFraudWindow(uint32 _fraudWindow) external onlyOwner {
        fraudWindow = _fraudWindow;
    }

    // Abstract functions to be implemented by the child contract.
    function isWatcher(address _address) public view virtual returns (bool);

    function getWatcherThreshold() public view virtual returns (uint8);

    function markFraudulent(address _ism) external virtual override {
        require(isWatcher(msg.sender), "Only a watcher can mark as fraudulent");
        require(
            !alreadyMarked[_ism][msg.sender],
            "Watcher has already marked this submodule"
        );

        fraudVotes[_ism] += 1;
        alreadyMarked[_ism][msg.sender] = true;

        if (fraudVotes[_ism] >= getWatcherThreshold()) {
            fraudulentSubmodules[_ism] = true;
        }
    }

    function submodule(bytes calldata _message)
        external
        view
        virtual
        override
        returns (IInterchainSecurityModule)
    {
        // Placeholder: The child contract will implement how to fetch the appropriate submodule.
        return IInterchainSecurityModule(address(0));
    }
}
