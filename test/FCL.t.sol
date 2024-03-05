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
    
    // test 2a
    function test_ecZZ_mulmuladd_S_asm(uint256 pk, uint256 pk2, uint256 z) public {
        vm.assume(z > 0 && pk > 0 && pk2 > 0 && pk != pk2);
        // choose valid (x, y), (t1, t2)
        (uint256 x, uint256 y) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
        (uint256 t1, uint256 t2) = FCL_ecdsa_utils.ecdsa_derivKpub(pk2);
        // convert (x, y) to projective: (x', y', zz, zzz)
        (uint256 xPrime, uint256 yPrime, uint256 zz, uint256 zzz) = _convertXY(x, y, z);
        // verify 205-253  =  = ecAff_add(x', y', zz, zzz, t1, t2)
        (uint256 i_x, uint256 i_y, uint256 i_t1, uint256 i_t2) = ecZZAddN(xPrime, yPrime, zz, zzz, t1, t2);
        (uint256 p0, uint256 p1, uint256 p2, uint256 p3) = FCL.ecZZ_AddN(xPrime, yPrime, zz, zzz, t1, t2);
        assertEq(p0, i_x);
        assertEq(p1, i_y);
        assertEq(p2, i_t1);
        assertEq(p3, i_t2);
    }

    // test 2b
    function test_ecZZ_Dbl_impl1(uint256 pk, uint256 z) public {
        vm.assume(z > 0 && pk > 0);
        // mod fuzzed values to P instead of bounding to ensure no overflow
        pk = pk % FCL.p;
        z = z % FCL.p;
        // choose (x1, y1)
        (uint256 x, uint256 y) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
        (uint256 xPrime, uint256 yPrime, uint256 zz, uint256 zzz) = _convertXY(x, y, z);
        // (x1, y1) = lines 167-176(x, y)
        (uint256 X, uint256 Y) = ecZZDbl_inline1(xPrime, yPrime, zz, zzz);
        // (x2, y2) = ecZZ_Dbl(x', y', zz, zzz)
        (uint256 x2, uint256 y2, ,) = FCL.ecZZ_Dbl(xPrime, yPrime, zz, zzz);
        // Verify that:
        // x1 = x2
        // y1 = -y2
        uint256 minusY2 = FCL.p - y2;
        assertEq(X, x2);
        assertEq(Y, minusY2);
    }

    // test 2c
    function test_ecZZ_Dbl_impl2(uint256 pk, uint256 z) public {
        vm.assume(z > 0 && pk > 0);
        console.log(z);
        // choose (x1, y1)
        (uint256 x, uint256 y) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
        (uint256 xPrime, uint256 yPrime, uint256 zz, uint256 zzz) = _convertXY(x, y, z);
        // (x1, y1) = lines 217 - 231(x, y)
        (uint256 X, uint256 Y) = ecZZDbl_inline2(xPrime, yPrime, zz, zzz);
        // (x2, y2) = ecZZ_Dbl(x', y', zz, zzz)
        (uint256 p0, uint256 p1, ,) = FCL.ecZZ_Dbl(xPrime, yPrime, zz, zzz);
        // Verify that:
        // x1 = x2
        // y1 = y2
        assertEq(p0, X);
        assertEq(p1, Y);
    }

    // test 2d
    function test_ecZZ_AddN_inline(uint256 pk1, uint256 pk2, uint256 z) public {
        vm.assume(z > 0 && pk1 > 0 && pk2 > 0 && pk1 != pk2);
        (uint256 x1, uint256 y1) = FCL_ecdsa_utils.ecdsa_derivKpub(pk1);
        (uint256 x2, uint256 y2) = FCL_ecdsa_utils.ecdsa_derivKpub(pk2);
        (uint256 x1Prime, uint256 y1Prime, uint256 zz1, uint256 zzz1) = _convertXY(x1, y1, z);
        // lines243to251(x, y, zz, zzz, t1, t2) = ecZZ_AddN(x, y, zz, zzz, T1, T2)
        (uint256 p0, uint256 p1, , ) = FCL.ecZZ_AddN(x1Prime, y1Prime, zz1, zzz1, x2, y2);
        (uint256 X, uint256 Y, , ) = eczzAddn_inline(x1Prime, y1Prime, zz1, zzz1, x2, y2);
        assertEq(p0, X);
        assertEq(p1, Y);
    }

    // test 2e
    function test_ecZZ_mulmod(uint256 pk, uint256 x, uint256 z) public {
        vm.assume(pk > 0 && z > 0 && x > 0);
        (uint256 x1, uint256 y1) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
        (uint256 x1Prime, uint256 y1Prime, uint256 zz1, uint256 zzz1) = _convertXY(x1, y1, z);
        (uint256 x2, uint256 y2) = FCL.ecZZ_SetAff(x1Prime, y1Prime, zz1, zzz1);
        assertEq(x1,x2);
        assertEq(y1,y2);
        uint256 p = FCL.p;
        x = x % p;
        // uint256 zInv = FCL_pModInv(z); // 1/z
        // uint256 zzInv = mulmod(zInv, zInv, p); // 1/zz
        // x1 = mulmod(x, zzInv, p); // x/zz
        uint256 zzzInv = FCL.FCL_pModInv(zzz1); //1/zzz
        // y1 = mulmod(y, zzzInv, p); //Y/zzz
        uint256 _b = mulmod(zz1, zzzInv, p); //1/z
        uint256 zzInv_orig = mulmod(_b, _b, p); //1/zz
        // x1 = mulmod(x, zzInv_orig, p); //X/zz
        uint256 zInv = FCL.FCL_pModInv(z); // 1/z == _b
        assertEq(_b, zInv);
        uint256 zzInv = mulmod(zInv, zInv, p);
        uint256 x3 = mulmod(x1Prime, zzInv, p);
        assertEq(zzInv,zzInv_orig);
        uint256 x4 = eczzMulmod_inline(x1Prime, zz1);
        assertEq(x1,x4);
        assertEq(x3,x2);
        assertEq(x3,x4);
    }

    // test 2f
    function test_mulmuladd_S_bugcheck() public {
        (uint256 minus_gx, uint256 minus_gy) = _goEcdsaScalarMult(FCL.n-1);
        (uint256 minus_two_gx, uint256 minus_two_gy) = _goEcdsaDouble(minus_gx, minus_gy);
        (uint256 minus_four_gx, uint256 minus_four_gy) = _goEcdsaDouble(minus_two_gx, minus_two_gy);
        // Test whether we are hitting the expected case
        (uint256 testX) = eczz_mulmuladd_S_truncated_inline(minus_four_gx, minus_four_gy, 18, 4);
        assertEq(testX, 42);
        // Test that the complete method handles this case gracefully
        uint256 X = FCL.ecZZ_mulmuladd_S_asm(minus_four_gx, minus_four_gy, 18, 4);
        (uint256 t1, ) = _goEcdsaScalarMult(2);
        assertEq(t1, X);
    }

    function ecZZAddN(uint256 X, uint256 Y, uint256 zz, uint256 zzz, uint256 T1, uint256 T2)
        internal
        pure
        returns (uint256, uint256, uint256, uint256)
    {
        uint256 p = FCL.p;
        uint256 minus_2 = FCL.minus_2;
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
                
                // we added this line to get functions to match
                Y := sub(p, Y)
                //

                // T3:=sub(p, Y)
                // T3:=Y
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
                zz := mulmod(zz, T4, p) //ZZ1 
                zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1
                let TT2 := mulmod(X, T4, p)
                T4 := addmod(addmod(mulmod(y2, y2, p), sub(p, TT1), p), mulmod(minus_2, TT2, p), p)
                Y := addmod(mulmod(addmod(TT2, sub(p, T4), p), y2, p), mulmod(Y, TT1, p), p)

                X := T4
            }
        }
        return (X, Y, zz, zzz);
    }

    // from FCL.sol lines 167-176
    function ecZZDbl_inline1(uint256 X, uint256 Y, uint256 zz, uint256 zzz)
        internal
        pure
        returns (uint256, uint256) {
            uint256 p = FCL.p;
            uint256 minus_2 = FCL.minus_2;
            uint256 T1;
            uint256 T2;
            uint256 T3;
            uint256 T4;
            assembly {
                // inlined EcZZ_Dbl 
                T1 := mulmod(2, Y, p) //U = 2*Y1, y free
                T2 := mulmod(T1, T1, p) // V=U^2
                T3 := mulmod(X, T2, p) // S = X1*V
                T1 := mulmod(T1, T2, p) // W=UV
                T4 := mulmod(3, mulmod(addmod(X, sub(p, zz), p), addmod(X, zz, p), p), p) //M=3*(X1-ZZ1)*(X1+ZZ1)
                zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
                zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free

                X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
                T2 := mulmod(T4, addmod(X, sub(p, T3), p), p) //-M(S-X3)=M(X3-S)
                Y := addmod(mulmod(T1, Y, p), T2, p) //-Y3= W*Y1-M(S-X3), we replace Y by -Y to avoid a sub in ecAdd
            }
            return (X, Y);
    }

    // from FCL.sol lines 217 - 231
    function ecZZDbl_inline2(uint256 X, uint256 Y, uint256 zz, uint256 zzz)
        internal
        pure
        returns (uint256, uint256) {
            uint256 p = FCL.p;
            uint256 minus_2 = FCL.minus_2;
            uint256 T1;
            uint256 T2;
            uint256 T3;
            uint256 T4;
            // set y2 = 0 since this is only called in conditiones when iszero(y2) == True
            uint256 y2 = 0;
            assembly {
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
            }
            return (X, Y);
    }

    // from FCL.sol lines 237 - 243
    function eczzAddn_inline(uint256 X, uint256 Y, uint256 zz, uint256 zzz, uint256 T1, uint256 T2) 
        internal 
        pure 
        returns (uint256, uint256, uint256, uint256)
    {
        uint256 p = FCL.p;
        uint256 minus_2 = FCL.minus_2;

        uint256 T4;

        assembly {
            // this line is commented out in the actual implementation, but the test fails without it
            Y := sub(p, Y)

            let y2 := addmod(mulmod(T2, zzz, p), Y, p) //R
            T2 := addmod(mulmod(T1, zz, p), sub(p, X), p) //P
            T4 := mulmod(T2, T2, p) //PP
            let TT1 := mulmod(T4, T2, p) //PPP, this one could be spared, but adding this register spare gas
            zz := mulmod(zz, T4, p)
            zzz := mulmod(zzz, TT1, p) //zz3=V*ZZ1
            let TT2 := mulmod(X, T4, p)
            T4 := addmod(addmod(mulmod(y2, y2, p), sub(p, TT1), p), mulmod(minus_2, TT2, p), p)
            Y := addmod(mulmod(addmod(TT2, sub(p, T4), p), y2, p), mulmod(Y, TT1, p), p)

            X := T4
        }
        return (X, Y, zz, zzz);
    }

    // from FCL.sol lines 248 - 267
    function eczzMulmod_inline(uint256 X, uint256 zz) 
        internal
        view
        returns (uint256)
    {
        uint256 p = FCL.p;
        uint256 minus_2 = FCL.minus_2;
        assembly {
                let T := mload(0x40)
                mstore(add(T, 0x60), zz)
                //(X,Y)=ecZZ_SetAff(X,Y,zz, zzz);
                //T[0] = inverseModp_Hard(T[0], p); //1/zzz, inline modular inversion using precompile:
                // Define length of base, exponent and modulus. 0x20 == 32 bytes
                mstore(T, 0x20)
                mstore(add(T, 0x20), 0x20)
                mstore(add(T, 0x40), 0x20)
                // Define variables base, exponent and modulus
                //mstore(add(pointer, 0x60), u)
                mstore(add(T, 0x80), minus_2)
                mstore(add(T, 0xa0), p)

                // Call the precompiled contract 0x05 = ModExp
                if iszero(staticcall(not(0), 0x05, T, 0xc0, T, 0x20)) { revert(0, 0) }

                //Y:=mulmod(Y,zzz,p)//Y/zzz
                //zz :=mulmod(zz, mload(T),p) //1/z
                //zz:= mulmod(zz,zz,p) //1/zz
                X := mulmod(X, mload(T), p) //X/zz
        }
        return X;
    }

    function eczz_mulmuladd_S_truncated_inline(
        uint256 Q0,
        uint256 Q1, //affine rep for input point Q
        uint256 scalar_u,
        uint256 scalar_v
    ) internal view returns (uint256) {
        uint256 p = FCL.p;
        uint256 gx = FCL.gx;
        uint256 gy = FCL.gy;
        uint256 minus_1 = FCL.minus_1;
        uint256 minus_2 = FCL.minus_2;
        uint256 index = 255;
        uint256 zz;
        uint256 zzz;
        uint256 Y;
        uint256 X;
        uint256 inConditional;

        unchecked {
            (uint256 H0, uint256 H1) = FCL.ecAff_add(gx, FCL.gy, Q0, Q1); 
            if((H0==0)&&(H1==0))//handling Q=-G
            {
                scalar_u=addmod(scalar_u, FCL.n-scalar_v, FCL.n);
                scalar_v=0;
            }
            assembly {
                for { let T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1)) } eq(T4, 0) {
                    index := sub(index, 1)
                    T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))
                } {}
                zz := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))

                if eq(zz, 1) {
                    X := gx
                    Y := gy
                }
                if eq(zz, 2) {
                    X := Q0
                    Y := Q1
                }
                if eq(zz, 3) {
                    X := H0
                    Y := H1
                }

                index := sub(index, 1)
                zz := 1
                zzz := 1

                for {} gt(minus_1, index) { index := sub(index, 1) } {
                    // inlined EcZZ_Dbl
                    let T1 := mulmod(2, Y, p) //U = 2*Y1, y free
                    let T2 := mulmod(T1, T1, p) // V=U^2
                    let T3 := mulmod(X, T2, p) // S = X1*V
                    T1 := mulmod(T1, T2, p) // W=UV
                    let T4 := mulmod(3, mulmod(addmod(X, sub(p, zz), p), addmod(X, zz, p), p), p) //M=3*(X1-ZZ1)*(X1+ZZ1)
                    zzz := mulmod(T1, zzz, p) //zzz3=W*zzz1
                    zz := mulmod(T2, zz, p) //zz3=V*ZZ1, V free

                    X := addmod(mulmod(T4, T4, p), mulmod(minus_2, T3, p), p) //X3=M^2-2S
                    T2 := mulmod(T4, addmod(X, sub(p, T3), p), p) //-M(S-X3)=M(X3-S)
                    Y := addmod(mulmod(T1, Y, p), T2, p) //-Y3= W*Y1-M(S-X3), we replace Y by -Y to avoid a sub in ecAdd
                    {
                        //value of dibit
                        T4 := add(shl(1, and(shr(index, scalar_v), 1)), and(shr(index, scalar_u), 1))

                        if iszero(T4) {
                            Y := sub(p, Y) //restore the -Y inversion
                            continue
                        } // if T4!=0

                        if eq(T4, 1) {
                            T1 := gx
                            T2 := gy
                        }
                        if eq(T4, 2) {
                            T1 := Q0
                            T2 := Q1
                        }
                        if eq(T4, 3) {
                            T1 := H0
                            T2 := H1
                        }
                        if iszero(zz) {
                            X := T1
                            Y := T2
                            zz := 1
                            zzz := 1
                            inConditional := 42
                            break
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
                } //end loop
            }
        }
        return inConditional;
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

    function _goEcdsaScalarMult(uint256 k) internal returns (uint256, uint256) {
        string [] memory inputs = new string[](2);
        inputs[0] = "test/../go/scalar/scalar";
        inputs[1] = vm.toString(k);
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
        pure
        returns (uint256 xPrime, uint256 yPrime, uint256 zz, uint256 zzz)
    {
        zz = mulmod(z, z, FCL.p);
        zzz = mulmod(zz, z, FCL.p);
        xPrime = mulmod(x, zz, FCL.p);
        yPrime = mulmod(y, zzz, FCL.p);
    }
}
