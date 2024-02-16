// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import {FCL_ecdsa_utils} from "FreshCryptoLib/FCL_ecdsa_utils.sol";
import {FCL} from "../src/FCL.sol";

contract IsOnCurve is Test {
    using stdJson for string;

    struct Keys {
        bytes32 d;
        bytes32 x;
        bytes32 y;
    }

    function test_ecAff_isOnCurve() public {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, "/go/gen/keys.json");
        string memory json = vm.readFile(path);
        bytes memory raw = json.parseRaw(".data");
        Keys[] memory keys = abi.decode(raw, (Keys[]));
        for (uint256 i = 0; i < keys.length; i++) {
            Keys memory k = keys[i];
            assertTrue(FCL.ecAff_isOnCurve(uint256(k.x), uint256(k.y)));
            (uint256 FCL_x, uint256 FCL_y) = FCL_ecdsa_utils.ecdsa_derivKpub(uint256(k.d));
            assertEq(uint256(k.x), FCL_x);
            assertEq(uint256(k.y), FCL_y);
        }
    }
}
