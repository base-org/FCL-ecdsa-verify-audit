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

    function test_vectors() public {
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, "/go/keys.json");
        string memory json = vm.readFile(path);
        bytes memory raw = json.parseRaw(".data");
        Keys[] memory keys = abi.decode(raw, (Keys[]));
        for (uint i = 0; i < keys.length; i++) {
            Keys memory k = keys[i];
            console2.logBytes32(k.d);
            console2.logBytes32(k.x);
            console2.logBytes32(k.y);
            assertTrue(FCL.ecAff_isOnCurve(uint(k.x), uint(k.y)));
            (uint FCL_x, uint FCL_y) = FCL_ecdsa_utils.ecdsa_derivKpub(uint(k.d));
            assertEq(uint(k.x), FCL_x);
            assertEq(uint(k.y), FCL_y);
        }
    }

}