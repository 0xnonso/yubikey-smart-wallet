# yubikey-smart-wallet
initial setup to install tools and deps:
```markdown
# install yubico-piv-tools.
make build
```
generate parmeters:
```markdown
cd circuit/param_gen && cargo build
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

