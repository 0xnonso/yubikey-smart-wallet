#!/bin/bash

# Usage: ./script.sh <slot> <algorithm>
# Example: ./script.sh 9a RSA2048

# Check if the correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <slot> <algorithm>"
    echo "Supported algorithms: RSA2048, ECCP256"
    echo "Example: $0 9a RSA2048"
    exit 1
fi

# Assign command-line arguments to variables
SLOT="$1"
ALGORITHM="$2"
ALGO_CODE="rsa"
if [[ "$ALGORITHM" == "ECCP256" ]]; then
    ALGO_CODE="ec"
fi

# Validate the key algorithm
if [[ "$ALGORITHM" != "RSA2048" && "$ALGORITHM" != "ECCP256" ]]; then
    echo "Error: Unsupported key algorithm '$ALGORITHM'."
    echo "Supported algorithms are: RSA2048 and ECCP256."
    exit 1
fi

# Prompt the user to enter their PIN
echo -n "Enter your YubiKey PIN: "
# Read PIN without echoing input
stty -echo
read PIN
stty echo
echo

# Temporary files
CERTIFICATE=$(mktemp)
PUBLIC_KEY=$(mktemp)
PUBLIC_KEY_PEM=$(mktemp)
ATTESTATION_CERT=$(mktemp)
INTERMEDIATE_CERT=$(mktemp)
ROOT_CERT="TrustedCAcerts.pem"

# Function to clean up temporary files on exit
cleanup() {
    rm -f "$CERTIFICATE" "$PUBLIC_KEY" "$PUBLIC_KEY_PEM" "$ATTESTATION_CERT" "$INTERMEDIATE_CERT" tbs_certificate.der pubkey.pem
}
trap cleanup EXIT

# Function to extract key algorithm from public key
get_key_algorithm() {
    local pubkey_file="$1"
    local algo
    algo=$(openssl pkey -in "$pubkey_file" -pubin -text -noout 2>/dev/null | head -n 1)
    echo "$algo"
}

# Function to map OpenSSL algorithm description to specified algorithm
map_algorithm() {
    local openssl_algo="$1"
    case "$openssl_algo" in
        "Public-Key: (2048 bit)")
            echo "RSA2048"
            ;;
        "Public-Key: (256 bit)")
            echo "ECCP256"
            ;;
        *)
            echo "UNSUPPORTED"
            ;;
    esac
}

# Flag to indicate if key exists
KEY_EXISTS=false

# Attempt to read the certificate from the slot
if yubico-piv-tool --action=read-certificate --slot="$SLOT" --pin="$PIN" > "$CERTIFICATE" 2>/dev/null; then
    echo "Certificate found in slot $SLOT."
    # Extract the public key from the certificate
    openssl x509 -in "$CERTIFICATE" -pubkey -noout -out "$PUBLIC_KEY"
    KEY_EXISTS=true
else
    echo "No certificate found in slot $SLOT."
    # Attempt to generate an attestation certificate
    if yubico-piv-tool --action=attest --slot="$SLOT" --pin="$PIN" > "$CERTIFICATE" 2>/dev/null; then
        echo "Key exists in slot $SLOT (found via attestation)."
        # Extract the public key from the attestation certificate
        openssl x509 -in "$CERTIFICATE" -pubkey -noout -out "$PUBLIC_KEY"
        KEY_EXISTS=true
    else
        echo "No key found in slot $SLOT."
    fi
fi

if [ "$KEY_EXISTS" = true ]; then
    # Determine the key algorithm
    KEY_ALGO_OPENSSL=$(get_key_algorithm "$PUBLIC_KEY")
    KEY_ALGO=$(map_algorithm "$KEY_ALGO_OPENSSL")

    if [ "$KEY_ALGO" = "UNSUPPORTED" ]; then
        echo "Existing key algorithm in slot $SLOT is unsupported."
        echo "Generating a new key with algorithm $ALGORITHM."
    elif [ "$KEY_ALGO" = "$ALGORITHM" ]; then
        echo "Key algorithm in slot $SLOT matches the specified algorithm ($ALGORITHM)."
        # Save the public key
        cp "$PUBLIC_KEY" "public_key_${SLOT}_${ALGORITHM}.pem"
        echo "Public key saved to public_key_${SLOT}_${ALGORITHM}.pem."
        # Convert the public key to DER format
        if [ "$ALGORITHM" = "RSA2048" ]; then
            openssl rsa -in "public_key_${SLOT}_${ALGORITHM}.pem" -pubin -outform DER -out "public_key_${SLOT}_${ALGORITHM}.der"
        else
            openssl ec -in "public_key_${SLOT}_${ALGORITHM}.pem" -pubin -outform DER -out "public_key_${SLOT}_${ALGORITHM}.der"
        fi
        echo "Public key converted to DER format and saved to public_key_${SLOT}_${ALGORITHM}.der."
    else
        echo "Key algorithm in slot $SLOT ($KEY_ALGO) does not match the specified algorithm ($ALGORITHM)."
        echo "Generating a new key with algorithm $ALGORITHM."
    fi
else
    echo "Generating a new key in slot $SLOT with algorithm $ALGORITHM."
fi

# Generate a new key if needed
if [ "$KEY_EXISTS" != true ] || { [ "$KEY_ALGO" != "$ALGORITHM" ] && [ "$KEY_ALGO" != "UNSUPPORTED" ]; }; then
    # Generate a new key pair in the specified slot
    if ! yubico-piv-tool --action=generate --slot="$SLOT" --algorithm="$ALGORITHM" --pin="$PIN" > "$PUBLIC_KEY_PEM"; then
        echo "Failed to generate a new key in slot $SLOT."
        exit 1
    fi
    echo "New key generated in slot $SLOT."

    # Save the public key
    cp "$PUBLIC_KEY_PEM" "public_key_${SLOT}_${ALGORITHM}.pem"
    echo "Public key saved to public_key_${SLOT}_${ALGORITHM}.pem."
    # Convert the public key to DER format
    if [ "$ALGORITHM" = "RSA2048" ]; then
        openssl rsa -in "public_key_${SLOT}_${ALGORITHM}.pem" -pubin -outform DER -out "public_key_${SLOT}_${ALGORITHM}.der"
    else
        openssl ec -in "public_key_${SLOT}_${ALGORITHM}.pem" -pubin -outform DER -out "public_key_${SLOT}_${ALGORITHM}.der"
    fi
    echo "Public key converted to DER format and saved to public_key_${SLOT}_${ALGORITHM}.der."
fi

# Retrieve the root Yubico PIV CA certificate
echo "Retrieving the root Yubico PIV CA certificate."
if ! curl -s https://developers.yubico.com/PIV/Introduction/piv-attestation-ca.pem -o "$ROOT_CERT"; then
    echo "Failed to retrieve the root Yubico PIV CA certificate."
    exit 1
fi
echo "Root Yubico PIV CA certificate saved to $ROOT_CERT."

# Extract the intermediate signing certificate from slot f9
echo "Extracting intermediate signing certificate from slot f9."
if yubico-piv-tool --action=read-certificate --slot=f9 > "$INTERMEDIATE_CERT"; then
    echo "Intermediate signing certificate extracted to $INTERMEDIATE_CERT."
else
    echo "Failed to extract intermediate signing certificate from slot f9."
    exit 1
fi

# Generate an attestation certificate for the key in the specified slot
ATTESTATION_CERT_FILE="Slot${SLOT}_${ALGORITHM}Attestation.pem"
echo "Generating attestation certificate for slot $SLOT."
if yubico-piv-tool --action=attest --slot="$SLOT" --pin="$PIN" > "$ATTESTATION_CERT_FILE"; then
    echo "Attestation certificate for slot $SLOT saved to $ATTESTATION_CERT_FILE."
else
    echo "Failed to generate attestation for slot $SLOT."
    exit 1
fi

# Verify the attestation certificate
echo "Verifying the attestation certificate."
if openssl verify -CAfile "$ROOT_CERT" -untrusted "$INTERMEDIATE_CERT" "$ATTESTATION_CERT_FILE"; then
    echo "Attestation certificate verification successful."
else
    echo "Attestation certificate verification failed."
    exit 1
fi

# Extract components from the attestation certificate

echo "Extracting components from the attestation certificate."

# Extract tbsCertificate in DER format
openssl asn1parse -in "$ATTESTATION_CERT_FILE" -strparse 4 -out tbs_certificate.der -noout
# Save tbsCertificate
mv tbs_certificate.der "tbsCertificate_${SLOT}_${ALGORITHM}.der"
echo "tbsCertificate extracted to tbsCertificate_${SLOT}_${ALGORITHM}.der."

# Extract public key
openssl x509 -in "$ATTESTATION_CERT_FILE" -pubkey -noout -out pubkey.pem
# Convert public key to DER format using openssl rsa (attestation uses RSA)
openssl $ALGO_CODE -in pubkey.pem -pubin -outform DER -out "publicKey_attestation_${SLOT}_${ALGORITHM}.der"
echo "Public key extracted to publicKey_attestation_${SLOT}_${ALGORITHM}.der."

# Extract signature in binary format using specific offsets
echo "Extracting signature from the attestation certificate."
if [ "$ALGORITHM" = "RSA2048" ]; then
    # Using strparse offset 543 for attestation certificate
    openssl asn1parse -in "$ATTESTATION_CERT_FILE" -strparse 543 -out "signature_attestation_${SLOT}_${ALGORITHM}.bin" -noout
else 
    openssl asn1parse -in "$ATTESTATION_CERT_FILE" -strparse 340 -out "signature_attestation_${SLOT}_${ALGORITHM}.bin" -noout
fi
echo "Signature extracted to signature_attestation_${SLOT}_${ALGORITHM}.bin."

# Extract components from the intermediate certificate
echo "Extracting components from the intermediate certificate."

# Extract tbsCertificate in DER format
openssl asn1parse -in "$INTERMEDIATE_CERT" -strparse 4 -out tbs_certificate.der -noout
# Save tbsCertificate
mv tbs_certificate.der "tbsCertificate_intermediate.der"
echo "tbsCertificate extracted to tbsCertificate_intermediate.der."

# Extract public key
openssl x509 -in "$INTERMEDIATE_CERT" -pubkey -noout -out pubkey.pem
# Convert public key to DER format using openssl rsa (intermediate uses RSA)
openssl rsa -in pubkey.pem -pubin -outform DER -out "publicKey_intermediate.der"
echo "Public key extracted to publicKey_intermediate.der."

# Extract signature in binary format using specific offsets
echo "Extracting signature from the intermediate certificate."
# Using strparse offset 505 for intermediate certificate
openssl asn1parse -in "$INTERMEDIATE_CERT" -strparse 505 -out "signature_intermediate.bin" -noout
echo "Signature extracted to signature_intermediate.bin."

# Extract public key from the root certificate in DER format
echo "Extracting public key from the root certificate."
openssl x509 -in "$ROOT_CERT" -pubkey -noout -out pubkey.pem
# Convert public key to DER format using openssl rsa (root certificate uses RSA)
openssl rsa -in pubkey.pem -pubin -outform DER -out "publicKey_root.der"
echo "Public key extracted to publicKey_root.der."

echo "Extraction and conversion completed successfully."