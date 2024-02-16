// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console, console2} from "forge-std/Test.sol";
import {FCL_ecdsa_utils} from "FreshCryptoLib/FCL_ecdsa_utils.sol";
import {FCL} from "../src/FCL.sol";

contract FCLTest is Test {
    function setUp() public {}

    function test_basecasesFC_nModInv() public {
        // array of base cases
        uint256[] memory basecases = new uint256[](8);
        uint256[] memory results = new uint256[](8);
        for (uint256 i = 0; i < 4; i++) {
            basecases[i] = i;
            results[i] = 1;
        }
        for (uint256 i = 0; i < 4; i++) {
            basecases[7 - i] = FCL.n - i;
            results[i + 4] = 1;
        }
        // 0 and N are not invertible
        results[0] = 0;
        results[7] = 0;

        for (uint256 i = 0; i < 8; i++) {
            uint256 inv = FCL.FCL_nModInv(basecases[i]);
            uint256 mul = mulmod(basecases[i], inv, FCL.n);
            assertEq(mul, results[i]);
        }
    }

    function test_basecasesFC_pModInv() public {
        // array of base cases
        uint256[] memory basecases = new uint256[](8);
        uint256[] memory results = new uint256[](8);
        for (uint256 i = 0; i < 4; i++) {
            basecases[i] = i;
            results[i] = 1;
        }
        for (uint256 i = 0; i < 4; i++) {
            basecases[7 - i] = FCL.p - i;
            results[i + 4] = 1;
        }
        // 0 and N are not invertible
        results[0] = 0;
        results[7] = 0;

        for (uint256 i = 0; i < 8; i++) {
            uint256 inv = FCL.FCL_pModInv(basecases[i]);
            uint256 mul = mulmod(basecases[i], inv, FCL.p);
            assertEq(mul, results[i]);
        }
    }

    function test_fuzzFC_nModInv(uint256 u) public {
        u = u % FCL.n;
        uint256 inv = FCL.FCL_nModInv(u);
        uint256 mul = mulmod(u, inv, FCL.n);
        if (u == 0) {
            assertEq(mul, 0);
        } else {
            assertEq(mul, 1);
        }
    }

    function test_fuzzFC_pModInv(uint256 u) public {
        u = u % FCL.p;
        uint256 inv = FCL.FCL_pModInv(u);
        uint256 mul = mulmod(u, inv, FCL.p);
        if (u == 0) {
            assertEq(mul, 0);
        } else {
            assertEq(mul, 1);
        }
    }

    function test_DBL_Add(uint256 pk, uint256 z) public {
        vm.assume(z > 0 && pk > 0);
        (uint256 x, uint256 y) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
        (uint256 xPrime, uint256 yPrime, uint256 zz, uint256 zzz) = _convertXY(x, y, z);
        (uint256 p0, uint256 p1, uint256 p2, uint256 p3) = FCL.ecZZ_Dbl(xPrime, yPrime, zz, zzz);
        (uint256 p0_2, uint256 p1_2, uint256 p2_2, uint256 p3_2) = FCL.ecZZ_AddN(xPrime, yPrime, zz, zzz, x, y);
        assertEq(p0, p0_2);
        assertEq(p1, p1_2);
        assertEq(p2, p2_2);
        assertEq(p3, p3_2);
    }

    // function test_powermod(uint y_) public {
    //     vm.assume(y_ > 0);
    //     uint y = y_ % FCL.p;
    //     uint yy = mulmod(y, y, FCL.p);
    //     FixedPointMathLib.powWad(int256(yy), int256((FCL.p + 1) / 2));
    //     // uint yPrime = yy ** ((FCL.p + 1) / 2) % FCL.p;

    //     // assertEq(y, yPrime);
    // }

    function test_values() public {
        // choose (x1, y1)
        (uint256 x, uint256 y) = FCL_ecdsa_utils.ecdsa_derivKpub(1);
        console2.log("x", x);
        console2.log("y", y);
        // convert it to (x’1, y’1, zz, zzz)
        (uint256 xPrime, uint256 yPrime, uint256 zz, uint256 zzz) = _convertXY(x, y, 1);
        console2.log("xPrime", xPrime);
        console2.log("yPrime", yPrime);
        console2.log("zz", zz);
        console2.log("zzz", zzz);
        // and double it
        (uint256 p0, uint256 p1, uint256 p2, uint256 p3) = FCL.ecZZ_Dbl(xPrime, yPrime, zz, zzz);
        // call the affine#Add Go function with (x1, y1) and (x1, y1)
        (uint256 go_x, uint256 go_y) = _ecdsaAdd(x, y);
        console2.log("go_x", go_x);
        console2.log("go_y", go_y);
        // convert its output to projective
        (uint256 go_p0, uint256 go_p1, uint256 go_p2, uint256 go_p3) = _convertXY(go_x, go_y, 1);
        // then compare that the two are the same
        console2.log("p0", p0);
        console2.log("go_p0", go_p0);
        console2.log("p1", p1);
        console2.log("go_p1", go_p1);
        console2.log("p2", p2);
        console2.log("go_p2", go_p2);
        console2.log("p3", p3);
        console2.log("go_p3", go_p3);
        assertEq(p0, go_p0);
        assertEq(p1, go_p1);
        assertEq(p2, go_p2);
        assertEq(p3, go_p3);
    }

    function _validXY(uint256 x_) internal returns (uint256 x, uint256 y) {
        while (true) {
            x = x_ % FCL.p;
            uint256 yy = addmod(mulmod(mulmod(x, x, FCL.p), x, FCL.p), mulmod(x, FCL.a, FCL.p), FCL.p); // x^3+ax
            uint256 exp = (FCL.p - 1) / 2;
            uint256 jacobiSymb = _power(yy, exp, FCL.p);
            if (jacobiSymb != 1) {
                x_ = x_ + 1;
                continue;
            }
            y = _squareRoot(yy);
            break;
        }
    }

    function test_add() public {
        (uint256 x, uint256 y) = _ecdsaAdd(
            48439561293906451759052585252797914202762949526041747995844080717082404635286,
            36134250956749795798585127919587881956611106672985015071877198253568414405109
        );
        console2.log(x);
        console2.log(y);
    }

    function _ecdsaAdd(uint256 x, uint256 y) internal returns (uint256, uint256) {
        string[] memory inputs = new string[](3);
        inputs[0] = "test/../go/double/double";
        inputs[1] = vm.toString(x);
        inputs[2] = vm.toString(y);
        return abi.decode(vm.ffi(inputs), (uint256, uint256));
    }

    function _power(uint256 a, uint256 b, uint256 p) internal pure returns (uint256) {
        uint256 x = a;
        uint256 t = 1;
        while (b > 0) {
            if (b % 2 == 1) {
                t = mulmod(t, x, p);
                b = b - 1;
            }
            x = mulmod(x, x, p);
            b = b / 2;
        }
        return t;
    }

    function _squareRoot(uint256 a) internal returns (uint256) {
        assertEq(FCL.p % 4, 3); // p = 3 mod 4 -> therefore we can do p+1/4
        uint256 exp = (FCL.p + 1) / 4;
        uint256 x = _power(a, exp, FCL.p);
        return x;
    }

    function _convertXY(uint256 x, uint256 y, uint256 z)
        internal
        view
        returns (uint256 xPrime, uint256 yPrime, uint256 zz, uint256 zzz)
    {
        zz = mulmod(z, z, FCL.p);
        zzz = mulmod(zz, z, FCL.p);
        xPrime = mulmod(x, zz, FCL.p);
        yPrime = mulmod(y, zzz, FCL.p);
    }
}
