# yubikey-smart-wallet
prove that you own a key pair generated from a Yubikey and generate a smart wallet account associated with it. currently, ECC P-256 (secp256r1) and RSA 2048-bit keys are supported.

initial setup to install tools and deps:
```markdown
# install yubico-piv-tools.
make build

# compile contracts.
forge build

# run contracts tests.
forge test -vv

# to compile circuits this version of noir is required.
noirup --version v0.34.0
```
