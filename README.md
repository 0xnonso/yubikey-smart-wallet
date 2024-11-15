# yubikey-smart-wallet
prove you own a key pair generated from a yubikey and generate a smart wallet account for it. currently supports ECCP256(secp256r1) and RSA2048 keys.

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
