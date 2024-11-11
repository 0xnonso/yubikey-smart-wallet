generate parameters:
```markdown
cd param_gen && cargo build
```

```markdown
# generate yubikey attestation parameters using desired slot and algorithm.
./yubikey_key_check.sh {SLOT} {ALGO}

./target/debug/param_gen verify-attestation tbsCertificate_{SLOT}_{ALGO}.der publicKey_attestation_{SLOT}_{ALGO}.der signature_attestation_{SLOT}_{ALGO}.bin tbsCertificate_intermediate.der publicKey_intermediate.der signature_intermediate.bin publicKey_root.der
```
```markdown
# generate message signature parameters using desired slot and algorithm.
./yubikey_sign_verify.sh {SLOT} {ALGO} "{DATA_IN_HEX_FORMAT}"

./target/debug/param_gen verify-signature {ALGO} public_key_{SLOT}_{ALGO}.der data.txt data.sig
```

to generate and verify proof:
```markdown
cd {circuit_folder} && nargo execute witness-name

bb prove -b ./target/{circuit_verifier}.json -w ./target/witness-name.gz -o ./target/proof        
```
