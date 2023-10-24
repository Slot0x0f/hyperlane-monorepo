// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import {OptimisticIsm} from "../../contracts/isms/optimistic/OptimisticIsm.sol";
import {IInterchainSecurityModule} from "../../contracts/interfaces/IInterchainSecurityModule.sol";
import {MessageUtils, TestIsm} from "./IsmTestUtils.sol";
import {TestMailbox} from "../../contracts/test/TestMailbox.sol";

contract OptimisticIsmTest is Test {
    address private constant NON_OWNER =
        0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe;

    address owner = address(1);
    uint32 fraudWindow = 100000;
    address[] watchers = [address(2), address(3), address(4)];
    uint8 threshold = 2;

    event ModuleSet(uint32 indexed domain, IInterchainSecurityModule module);

    OptimisticIsm internal ism;

    function setUp() public virtual {
        ism = new OptimisticIsm(owner, fraudWindow, watchers, threshold);
    }

    function deployTestIsm(bytes32 requiredMetadata)
        internal
        returns (TestIsm)
    {
        return new TestIsm(abi.encode(requiredMetadata));
    }

    function getMetadata() internal view returns (bytes memory) {
        return TestIsm(address(ism.currentSubmodule())).requiredMetadata();
    }

    function testSet(uint32 domain) public {
        TestIsm _ism = deployTestIsm(bytes32(0));
        emit ModuleSet(domain, _ism);
        vm.prank(owner);
        ism.setSubmodule(address(_ism));
        assertEq(address(ism.currentSubmodule()), address(_ism));
    }

    function testSetNonOwner(IInterchainSecurityModule _ism) public {
        vm.prank(NON_OWNER);
        vm.expectRevert();
        ism.setSubmodule(address(_ism));
    }

    function testVerify(uint32 domain, bytes32 seed) public {
        vm.prank(owner);
        ism.setSubmodule(address(deployTestIsm(seed)));

        bytes memory metadata = getMetadata();
        assertTrue(ism.verify(metadata, MessageUtils.build(domain)));
    }

    function testGetWatcherThreshold() public {
        assert(ism.getWatcherThreshold() == threshold);
    }

    function testisWatcher() public {
        assert(ism.isWatcher(watchers[0]));
        assert(ism.isWatcher(watchers[1]));
        assert(ism.isWatcher(watchers[2]));
    }

    function testMarkFradulent() public {
        TestIsm _ism = deployTestIsm(bytes32(0));

        vm.prank(owner);
        ism.setSubmodule(address(_ism));

        vm.prank(watchers[0]);
        ism.markFraudulent(address(_ism));

        vm.prank(watchers[1]);
        ism.markFraudulent(address(_ism));

        assert(ism.getSubmoduleFraudMarks(address(_ism)) > 0);
    }

    function testisSubmoduleCompromised() public {
        TestIsm _ism = deployTestIsm(bytes32(0));

        vm.prank(owner);
        ism.setSubmodule(address(_ism));

        vm.prank(watchers[0]);
        ism.markFraudulent(address(_ism));

        vm.prank(watchers[1]);
        ism.markFraudulent(address(_ism));

        assert(ism.isSubmoduleCompromised(address(_ism)));
    }
}
