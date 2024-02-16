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

    function test_ecAff_add(uint256 pk, uint256 pk2) public {
        vm.assume(pk > 0 && pk2 > 0);
        (uint256 x1, uint256 y1) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
        (uint256 x2, uint256 y2) = FCL_ecdsa_utils.ecdsa_derivKpub(pk2);
        (uint256 xx, uint256 yy) = FCL.ecAff_add(x1, y1, x2, y2);
        (uint256 go_x, uint256 go_y) = _goEcdsaAdd(x1, y1, x2, y2);
        assertEq(xx, go_x);
        assertEq(yy, go_y);
    }

    function test_ecZZ_AddN(uint256 pk, uint256 pk2, uint256 z) public {
        vm.assume(z > 0 && pk > 0 && pk2 > 0 && pk != pk2);
        (uint256 x1, uint256 y1) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
        (uint256 x2, uint256 y2) = FCL_ecdsa_utils.ecdsa_derivKpub(pk2);
        (uint256 x1Prime, uint256 y1Prime, uint256 zz1, uint256 zzz1) = _convertXY(x1, y1, z);
        (uint256 p0, uint256 p1, uint256 p2, uint256 p3) = FCL.ecZZ_AddN(x1Prime, y1Prime, zz1, zzz1, x2, y2);
        (uint256 xx, uint256 yy) = FCL.ecZZ_SetAff(p0, p1, p2, p3);
        (uint256 go_x, uint256 go_y) = _goEcdsaAdd(x1, y1, x2, y2);
        assertEq(xx, go_x);
        assertEq(yy, go_y);
    }

    function test_ecZZ_Dbl(uint256 pk, uint256 z) public {
        vm.assume(z > 0 && pk > 0);
        // choose (x1, y1)
        (uint256 x, uint256 y) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
        (uint256 xPrime, uint256 yPrime, uint256 zz, uint256 zzz) = _convertXY(x, y, z);
        // and double it
        (uint256 p0, uint256 p1, uint256 p2, uint256 p3) = FCL.ecZZ_Dbl(xPrime, yPrime, zz, zzz);
        (uint256 xx, uint256 yy) = FCL.ecZZ_SetAff(p0, p1, p2, p3);

        // call the affine#Add Go function with (x1, y1) and (x1, y1)
        (uint256 go_x, uint256 go_y) = _goEcdsaDouble(x, y);
        // then compare that the two are the same
        assertEq(xx, go_x);
        assertEq(yy, go_y);
    }

    function test_ecZZ_mulmuladd_S_asm() public {
        // vm.assume(z > 0 && pk > 0 && pk != pk2);
        uint256 pk = 1;
        uint256 pk2 = 2;
        uint256 z = 1;
        // choose valid (x, y), (t1, t2)
        (uint256 x, uint256 y) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
        (uint256 t1, uint256 t2) = FCL_ecdsa_utils.ecdsa_derivKpub(pk2);
        // convert (x, y) to projective: (x', y', zz, zzz)
        (uint256 xPrime, uint256 yPrime, uint256 zz, uint256 zzz) = _convertXY(x, y, z);
        // verify 205-253  =  = ecAff_add(x', y', zz, zzz, t1, t2)
        (uint256 i_x, uint256 i_y, uint256 i_t1, uint256 i_t2) = ecZZAddN(xPrime, yPrime, zz, zzz, t1, t2);
        // console2.log(i_x);
        (uint256 p0, uint256 p1, uint256 p2, uint256 p3) = FCL.ecZZ_AddN(xPrime, yPrime, zz, zzz, t1, t2);
        console2.log(p0);
        console2.log(p1);
        console2.log(p2);
        console2.log(p3);
        assertEq(p0, i_x);
    }

    function ecZZAddN(uint256 X, uint256 Y, uint256 zz, uint256 zzz, uint256 T1, uint256 T2)
        internal
        pure
        returns (uint256, uint256, uint256, uint256)
    {
        uint256 p = FCL.p;
        uint256 minus_2 = FCL.minus_2;
        console2.log(X);
        console2.log(T1);
        uint256 T3;
        uint256 T4;
        assembly {
            // Execute the loop exactly once
            for { let i := 0 } lt(i, 1) { i := add(i, 1) } {
                // If zz is zero, set values and skip to the end of the loop
                if iszero(zz) {
                    X := T1
                    Y := T2
                    zz := 1
                    zzz := 1
                    continue
                }
                // inlined EcZZ_AddN

                //T3:=sub(p, Y)
                //T3:=Y
                let y2 := addmod(mulmod(T2, zzz, p), Y, p) //R
                T2 := addmod(mulmod(T1, zz, p), sub(p, X), p) //P

                //special extremely rare case accumulator where EcAdd is replaced by EcDbl, no need to optimize this
                //todo : construct edge vector case
                if iszero(y2) {
                    if iszero(T2) {
                        T1 := mulmod(minus_2, Y, p) //U = 2*Y1, y free
                        T2 := mulmod(T1, T1, p) // V=U^2
                        T3 := mulmod(X, T2, p) // S = X1*V

                        T1 := mulmod(T1, T2, p) // W=UV
                        y2 := mulmod(addmod(X, zz, p), addmod(X, sub(p, zz), p), p) //(X-ZZ)(X+ZZ)
                        T4 := mulmod(3, y2, p) //M=3*(X-ZZ)(X+ZZ)

                        zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
                        zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free

                        X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
                        T2 := mulmod(T4, addmod(T3, sub(p, X), p), p) //M(S-X3)

                        Y := addmod(T2, mulmod(T1, Y, p), p) //Y3= M(S-X3)-W*Y1

                        continue
                    }
                }

                T4 := mulmod(T2, T2, p) //PP
                let TT1 := mulmod(T4, T2, p) //PPP, this one could be spared, but adding this register spare gas
                zz := mulmod(zz, T4, p)
                zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1
                let TT2 := mulmod(X, T4, p)
                T4 := addmod(addmod(mulmod(y2, y2, p), sub(p, TT1), p), mulmod(minus_2, TT2, p), p)
                Y := addmod(mulmod(addmod(TT2, sub(p, T4), p), y2, p), mulmod(Y, TT1, p), p)

                X := T4
            }
        }
        console2.log("end");
        console2.log(X);
        console2.log(Y);
        console2.log(T1);
        console2.log(T2);
        console2.log(T3);
        console2.log(T4);
        console2.log(zz);
        console2.log(zzz);
        console2.log("end");
        return (X, Y, zz, zzz);
    }

    //     function _inlinedAdd(uint T1, uint T2, uint X, uint Y, uint zz, uint zzz, uint p) internal returns (uint newX, uint newY, uint newZZ, uint newZZZ) {
    //     assembly {
    //         // Start of the assembly block
    //         // Save the original values of X, Y, zz, and zzz
    //         let origX := X
    //         let origY := Y
    //         let origZZ := zz
    //         let origZZZ := zzz

    //         // Load the inputs into memory
    //         let T1_ptr := add(calldataload(T1), 0x20)
    //         let T2_ptr := add(calldataload(T2), 0x20)
    //         let X_ptr := add(calldataload(X), 0x20)
    //         let Y_ptr := add(calldataload(Y), 0x20)
    //         let zz_ptr := add(calldataload(zz), 0x20)
    //         let zzz_ptr := add(calldataload(zzz), 0x20)
    //         let p_ptr := add(calldataload(p), 0x20)

    //         // Load the values from memory
    //         let T1_val := mload(T1_ptr)
    //         let T2_val := mload(T2_ptr)
    //         let X_val := mload(X_ptr)
    //         let Y_val := mload(Y_ptr)
    //         let zz_val := mload(zz_ptr)
    //         let zzz_val := mload(zzz_ptr)
    //         let p_val := mload(p_ptr)

    //         // Check if zz is zero
    //         if eq(zz_val, 0) {
    //             // Set newX, newY, newZZ, and newZZZ accordingly
    //             newX := T1_val
    //             newY := T2_val
    //             newZZ := 1
    //             newZZZ := 1
    //             // Exit the assembly block
    //             stop
    //         }

    //         // Calculate y2
    //         let y2 := addmod(mulmod(T2_val, zzz_val, p_val), Y_val, p_val)
    //         // Calculate P
    //         let P := addmod(mulmod(T1_val, zz_val, p_val), sub(p_val, X_val), p_val)

    //         // Check if y2 is zero
    //         if eq(y2, 0) {
    //             // Check if P is zero
    //             if eq(P, 0) {
    //                 // Calculate newX, newY, zz, and zzz for the special case
    //                 newX := addmod(mulmod(9, 9, p_val), mulmod(3, sub(p_val, mulmod(6, X_val, p_val)), p_val), p_val)
    //                 let M_S_X3 := addmod(mulmod(X_val, X_val, p_val), mulmod(sub(p_val, newX), newX, p_val), p_val)
    //                 let T2 := mulmod(9, M_S_X3, p_val)
    //                 newY := addmod(T2, mulmod(9, Y_val, p_val), p_val)
    //                 newZZ := mulmod(9, zz_val, p_val)
    //                 newZZZ := mulmod(81, zzz_val, p_val)
    //                 // Exit the assembly block
    //                 stop
    //             }
    //         }

    //         // Calculate T4
    //         let T4 := mulmod(P, P, p_val)
    //         // Calculate TT1
    //         let TT1 := mulmod(T4, P, p_val)
    //         // Update zz
    //         zz := mulmod(zz_val, T4, p_val)
    //         // Update zzz
    //         zzz := mulmod(zzz_val, TT1, p_val)
    //         // Calculate TT2
    //         let TT2 := mulmod(X_val, T4, p_val)
    //         // Calculate new X
    //         newX := addmod(addmod(mulmod(y2, y2, p_val), sub(p_val, TT1), p_val), mulmod(sub(p_val, mulmod(2, TT2, p_val)), TT2, p_val), p_val)
    //         // Calculate new Y
    //         newY := addmod(mulmod(addmod(TT2, sub(p_val, newX), p_val), y2, p_val), mulmod(Y_val, TT1, p_val), p_val)
    //         // End of the assembly block
    //     }
    // }

    // uint X = x;
    // uint Y = y;
    // uint T1 = t1;
    // uint T2 = t2;
    // uint256 T3;
    // uint256 T4;
    // assembly {
    //     for {} 1 {} {
    //         if iszero(0) {
    //             X := T1
    //             Y := T2
    //             zz := 1
    //             zzz := 1
    //             break
    //         }
    //         // inlined EcZZ_AddN

    //         //T3:=sub(p, Y)
    //         //T3:=Y
    //         let y2 := addmod(mulmod(T2, zzz, p), Y, p) //R
    //         T2 := addmod(mulmod(T1, zz, p), sub(p, X), p) //P

    //         //special extremely rare case accumulator where EcAdd is replaced by EcDbl, no need to optimize this
    //         //todo : construct edge vector case
    //         if iszero(y2) {
    //             if iszero(T2) {
    //                 T1 := mulmod(minus_2, Y, p) //U = 2*Y1, y free
    //                 T2 := mulmod(T1, T1, p) // V=U^2
    //                 T3 := mulmod(X, T2, p) // S = X1*V

    //                 T1 := mulmod(T1, T2, p) // W=UV
    //                 y2 := mulmod(addmod(X, zz, p), addmod(X, sub(p, zz), p), p) //(X-ZZ)(X+ZZ)
    //                 T4 := mulmod(3, y2, p) //M=3*(X-ZZ)(X+ZZ)

    //                 zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
    //                 zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free

    //                 X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
    //                 T2 := mulmod(T4, addmod(T3, sub(p, X), p), p) //M(S-X3)

    //                 Y := addmod(T2, mulmod(T1, Y, p), p) //Y3= M(S-X3)-W*Y1

    //                 break
    //             }
    //         }

    //         T4 := mulmod(T2, T2, p) //PP
    //         let TT1 := mulmod(T4, T2, p) //PPP, this one could be spared, but adding this register spare gas
    //         zz := mulmod(zz, T4, p)
    //         zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1
    //         let TT2 := mulmod(X, T4, p)
    //         T4 := addmod(addmod(mulmod(y2, y2, p), sub(p, TT1), p), mulmod(minus_2, TT2, p), p)
    //         Y := addmod(mulmod(addmod(TT2, sub(p, T4), p), y2, p), mulmod(Y, TT1, p), p)

    //         X := T4
    //         break
    //     }
    //     // x = X;
    //     // y = Y;
    //     // t1 = T1;
    //     // t2 = T2;
    // }

    // return (X, Y, T1, T2);
    // }

    // function test_powermod(uint y_) public {
    //     vm.assume(y_ > 0);
    //     uint y = y_ % FCL.p;
    //     uint yy = mulmod(y, y, FCL.p);
    //     FixedPointMathLib.powWad(int256(yy), int256((FCL.p + 1) / 2));
    //     // uint yPrime = yy ** ((FCL.p + 1) / 2) % FCL.p;

    //     // assertEq(y, yPrime);
    // }

    // function test_values(uint256 z, uint256 pk) public {
    //     vm.assume(z > 0);
    //     // choose (x1, y1)
    //     (uint256 x, uint256 y) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
    //     assertTrue(FCL.ecAff_isOnCurve(x, y));
    //     (uint256 xPrime, uint256 yPrime, uint256 zz, uint256 zzz) = _convertXY(x, y, z);
    //     // and double it
    //     (uint256 p0, uint256 p1, uint256 p2, uint256 p3) = FCL.ecZZ_Dbl(xPrime, yPrime, zz, zzz);
    //     (uint256 xx, uint256 yy) = FCL.ecZZ_SetAff(p0, p1, p2, p3);

    //     // call the affine#Add Go function with (x1, y1) and (x1, y1)
    //     (uint256 go_x, uint256 go_y) = _ecdsaAdd(x, y);
    //     // then compare that the two are the same
    //     assertEq(xx, go_x);
    //     assertEq(yy, go_y);
    // }

    // function _validXY(uint256 x_) internal returns (uint256 x, uint256 y) {
    //     while (true) {
    //         x = x_ % FCL.p;
    //         uint256 yy = addmod(mulmod(mulmod(x, x, FCL.p), x, FCL.p), mulmod(x, FCL.a, FCL.p), FCL.p); // x^3+ax
    //         uint256 exp = (FCL.p - 1) / 2;
    //         uint256 jacobiSymb = _power(yy, exp, FCL.p);
    //         if (jacobiSymb != 1) {
    //             x_ = x_ + 1;
    //             continue;
    //         }
    //         y = _squareRoot(yy);
    //         break;
    //     }
    // }

    // function test_add() public {
    //     (uint256 x, uint256 y) = _ecdsaAdd(
    //         48439561293906451759052585252797914202762949526041747995844080717082404635286,
    //         36134250956749795798585127919587881956611106672985015071877198253568414405109
    //     );
    //     console2.log(x);
    //     console2.log(y);
    // }

    function _goEcdsaDouble(uint256 x, uint256 y) internal returns (uint256, uint256) {
        return _goEcdsaAdd(x, y, x, y);
    }

    function _goEcdsaAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2) internal returns (uint256, uint256) {
        string[] memory inputs = new string[](5);
        inputs[0] = "test/../go/add/add";
        inputs[1] = vm.toString(x1);
        inputs[2] = vm.toString(y1);
        inputs[3] = vm.toString(x2);
        inputs[4] = vm.toString(y2);
        return abi.decode(vm.ffi(inputs), (uint256, uint256));
    }

    // function _power(uint256 a, uint256 b, uint256 p) internal pure returns (uint256) {
    //     uint256 x = a;
    //     uint256 t = 1;
    //     while (b > 0) {
    //         if (b % 2 == 1) {
    //             t = mulmod(t, x, p);
    //             b = b - 1;
    //         }
    //         x = mulmod(x, x, p);
    //         b = b / 2;
    //     }
    //     return t;
    // }

    // function _squareRoot(uint256 a) internal returns (uint256) {
    //     assertEq(FCL.p % 4, 3); // p = 3 mod 4 -> therefore we can do p+1/4
    //     uint256 exp = (FCL.p + 1) / 4;
    //     uint256 x = _power(a, exp, FCL.p);
    //     return x;
    // }

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
