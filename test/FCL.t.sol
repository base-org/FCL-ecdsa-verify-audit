// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {FCL_ecdsa_utils} from "FreshCryptoLib/FCL_ecdsa_utils.sol";
import {FCL} from "../src/FCL.sol";

contract FCLTest is Test {
    function setUp() public {}

        function test_basecasesFC_nModInv() public {
           // array of base cases
           uint[] memory basecases = new uint[](8);
           uint[] memory results = new uint[](8);
           for (uint i = 0; i < 4; i++) {
               basecases[i] = i;
               results[i] = 1;
           }
           for (uint i = 0; i < 4; i++) {
               basecases[7 - i] = FCL.n - i;
               results[i + 4] = 1;
           }
           // 0 and N are not invertible
           results[0] = 0;
           results[7] = 0;

           for (uint i = 0; i < 8; i++) {
               uint inv = FCL.FCL_nModInv(basecases[i]);
               uint mul = mulmod(basecases[i], inv, FCL.n);
               assertEq(mul, results[i]);
           }
       }

       function test_basecasesFC_pModInv() public {
           // array of base cases
           uint[] memory basecases = new uint[](8);
           uint[] memory results = new uint[](8);
           for (uint i = 0; i < 4; i++) {
               basecases[i] = i;
               results[i] = 1;
           }
           for (uint i = 0; i < 4; i++) {
               basecases[7 - i] = FCL.p - i;
               results[i + 4] = 1;
           }
           // 0 and N are not invertible
           results[0] = 0;
           results[7] = 0;

           for (uint i = 0; i < 8; i++) {
               uint inv = FCL.FCL_pModInv(basecases[i]);
               uint mul = mulmod(basecases[i], inv, FCL.p);
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

    function test_DBL_Add(uint256 x_, uint256 z) public {
        vm.assume(z > 0);
        // test assumption x cannot be 0
        vm.assume(x_ > 0);
        (uint256 x, uint256 y) = _validXY(x_);
        assert(FCL.ecAff_isOnCurve(x, y));
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

    function test() public {
        (uint x, uint y) = _validXY(1);
        console.log(x);
        console.log(y);
    }

    function _validXY(uint256 x_) internal returns (uint256 x, uint256 y) {
        while (true) {
            x = x_ % FCL.p;
            uint256 yy = addmod(mulmod(mulmod(x, x, FCL.p), x, FCL.p), mulmod(x, FCL.a, FCL.p), FCL.p); // x^3+ax
            uint exp = (FCL.p - 1) / 2;
            uint jacobiSymb = _power(yy, exp, FCL.p);
            if (jacobiSymb != 1) {
                x_ = x_ + 1;
                continue;
            }
            y = _squareRoot(yy);
            break;
        }
    }

    function _power(uint a, uint b, uint p) pure internal returns (uint) {
        uint x = a;
        uint t = 1;
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

    function _squareRoot(uint a) internal returns (uint) {
        assertEq(FCL.p % 4, 3); // p = 3 mod 4 -> therefore we can do p+1/4
        uint exp = (FCL.p + 1) / 4;
        uint x = _power(a, exp, FCL.p);
        return x;
    }

    function _convertXY(uint256 x, uint256 y, uint256 z)
        internal
        view
        returns (uint256 xPrime, uint256 yPrime, uint256 zz, uint256 zzz)
    {
        zz = mulmod(z, z, FCL.p);
        zzz = mulmod(zz, z, FCL.p);
        uint256 zzInv = FCL.FCL_pModInv(zz);
        uint256 zzzInv = FCL.FCL_pModInv(zzz);
        xPrime = mulmod(x, zzInv, FCL.p);
        yPrime = mulmod(y, zzzInv, FCL.p);
    }
}
