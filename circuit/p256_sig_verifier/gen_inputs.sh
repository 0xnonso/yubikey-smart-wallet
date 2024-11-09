# Set the number of public inputs
NUM_PUBLIC_INPUTS=64  # Change this value to match the number of public inputs
PUBLIC_INPUT_BYTES=$((32 * NUM_PUBLIC_INPUTS))

# Extract the public inputs
HEX_PUBLIC_INPUTS=$(head -c $PUBLIC_INPUT_BYTES ./target/proof | od -An -v -t x1 | tr -d ' \n')

# Extract the proof (starting after the public inputs)
HEX_PROOF=$(tail -c +$(($PUBLIC_INPUT_BYTES + 1)) ./target/proof | od -An -v -t x1 | tr -d ' \n')

# Print the extracted public inputs and proof
echo "Public inputs:"
echo $HEX_PUBLIC_INPUTS

echo "Proof:"
echo "0x$HEX_PROOF"