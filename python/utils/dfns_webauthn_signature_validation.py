import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

# --- Helper Functions ---

def base64url_decode(input_str: str) -> bytes:
    """Decodes a base64url string to bytes, adding padding if necessary."""
    input_str = input_str.replace('-', '+').replace('_', '/')
    rem = len(input_str) % 4
    if rem > 0:
        input_str += '=' * (4 - rem)
    return base64.urlsafe_b64decode(input_str)

def load_pem_public_key(pem_key_str: str):
    """Loads a public key from a standard PEM-formatted string."""
    try:
        pem_key_bytes = pem_key_str.encode('utf-8')
        public_key = serialization.load_pem_public_key(
            pem_key_bytes,
            backend=default_backend()
        )
        return public_key
    except Exception as e:
        print(f"Error: Could not parse the PEM public key. Details: {e}")
        return None

def verify_assertion_signature(
    signature_b64: str,
    public_key_pem: str,
    client_data_b64: str,
    authenticator_data_b64: str
) -> bool:
    """
    Verifies a WebAuthn credential assertion signature using a PEM public key.
    """
    try:
        signature_bytes = base64url_decode(signature_b64)
        client_data_bytes = base64url_decode(client_data_b64)
        authenticator_data_bytes = base64url_decode(authenticator_data_b64)

        client_data_hash = hashlib.sha256(client_data_bytes).digest()
        data_to_verify = authenticator_data_bytes + client_data_hash

        public_key = load_pem_public_key(public_key_pem)
        if not public_key:
            return False

        public_key.verify(
            signature=signature_bytes,
            data=data_to_verify,
            signature_algorithm=ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"An unexpected error occurred during verification: {e}")
        return False

# --- Main Execution Logic ---

def main():
    """Main function to run the interactive tool."""
    print("Please provide the WebAuthn assertion data below.")
    
    # Prompt for all required inputs directly
    signature = input("Enter signature: ")
    public_key = input("Enter publicKey: ")
    client_data = input("Enter clientData: ")
    authenticator_data = input("Enter authenticatorData: ")

    public_key = public_key.replace('\\n', '\n')

    # Check if any of the essential arguments are empty
    if not all([signature, public_key, client_data, authenticator_data]):
        print("\n❌ Error: All four values must be provided.")
        return # Exit the function

    # Perform the verification
    is_valid = verify_assertion_signature(
        signature_b64=signature,
        public_key_pem=public_key,
        client_data_b64=client_data,
        authenticator_data_b64=authenticator_data
    )

    # Print the final result
    if is_valid:
        print("\n✅ Signature is valid")
    else:
        print("\n❌ Signature is NOT valid")

if __name__ == "__main__":
    main()
