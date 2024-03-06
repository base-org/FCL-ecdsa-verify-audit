> [!IMPORTANT]  
> This audit's scope is extremely narrow. Ensure use of this audit as a reference is appropriately scoped.

## FreshCryptoLib ecdsa_verify Audit

**This repo contains the set of tests used to audit the FCL ecdsa sepc256r1 verify method implemented by FreshCryptoLib [here](https://github.com/rdubois-crypto/FreshCryptoLib/tree/master/solidity).**

## Scope

The scope of the audit is restricted only to methods used in the context of `ecdsa_verify`:

```solidity
    function ecdsa_verify(bytes32 message, uint256 r, uint256 s, uint256 Qx, uint256 Qy)  internal view returns (bool){

        if (r == 0 || r >= FCL_Elliptic_ZZ.n || s == 0 || s >= FCL_Elliptic_ZZ.n) {
            return false;
        }
        
        if (!FCL_Elliptic_ZZ.ecAff_isOnCurve(Qx, Qy)) {
            return false;
        }

        uint256 sInv = FCL_Elliptic_ZZ.FCL_nModInv(s);

        uint256 scalar_u = mulmod(uint256(message), sInv, FCL_Elliptic_ZZ.n);
        uint256 scalar_v = mulmod(r, sInv, FCL_Elliptic_ZZ.n);
        uint256 x1;

        x1 = FCL_Elliptic_ZZ.ecZZ_mulmuladd_S_asm(Qx, Qy, scalar_u, scalar_v);

        x1= addmod(x1, n-r,n );
    
        return x1 == 0;
    }
```

As such, only the following files were in-scope for this exercise:
- [FCL_ecdsa.sol](https://github.com/rdubois-crypto/FreshCryptoLib/blob/master/solidity/src/FCL_ecdsa.sol)
- [FCL_ecdsa_utils.sol](https://github.com/rdubois-crypto/FreshCryptoLib/blob/master/solidity/src/FCL_ecdsa_utils.sol)
- [FCL_elliptic.sol](https://github.com/rdubois-crypto/FreshCryptoLib/blob/master/solidity/src/FCL_elliptic.sol)


## Methodology

The test suite was conducted in three major parts:
1. Unit tests were written for each of the helper methods employed in the `ecdsa_verify` flow. By leveraging calls against the [go/elliptic](https://pkg.go.dev/crypto/elliptic#section-sourcefiles) library, each solidity implementation was fuzz-tested for accuracy across a range of inputs. 
2. Targeted tests were written against inline assembly exceperts taken from the extensive `ecZZ_mulmuladd_S_asm` method found [here](https://github.com/rdubois-crypto/FreshCryptoLib/blob/ec7122f20900f9486a7c018d635f69738b14dfc3/solidity/src/FCL_elliptic.sol#L345C14-L345C34).
3. Our in-house cryptography team reviewed the methodology and implementation then conducted targeted edge case testing against relevant methods in the library. 


## Results

_TODO: link to report_

Through our testing, we determined there were two issues with the implementation. Both were addressed and fixed in the subject libraries. The PRs for these changes can be found [here](https://github.com/rdubois-crypto/FreshCryptoLib/pull/60) and [here](https://github.com/rdubois-crypto/FreshCryptoLib/pull/61).

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test --ffi
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
