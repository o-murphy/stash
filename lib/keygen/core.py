import ctypes
from objc_util import *
import base64
import uuid
from ctypes import c_size_t, byref, c_void_p

# --- Constants for Security.framework ---
c = ctypes.CDLL(None)
kSecAttrKeyType = c_void_p.in_dll(c, "kSecAttrKeyType")
kSecAttrKeySizeInBits = c_void_p.in_dll(c, "kSecAttrKeySizeInBits")
kSecPrivateKeyAttrs = c_void_p.in_dll(c, "kSecPrivateKeyAttrs")
kSecPublicKeyAttrs = c_void_p.in_dll(c, "kSecPublicKeyAttrs")
kCFBooleanTrue = c_void_p.in_dll(c, "kCFBooleanTrue")
kCFBooleanFalse = c_void_p.in_dll(c, "kCFBooleanFalse")
kSecAttrIsExtractable = c_void_p.in_dll(c, "kSecAttrIsExtractable")
kSecAttrApplicationTag = c_void_p.in_dll(c, "kSecAttrApplicationTag")
# kSecAttrIsPermanent = c_void_p.in_dll(c, "kCFBooleanTrue")
kSecAttrIsPermanent = c_void_p.in_dll(c, "kSecAttrIsPermanent")
kSecAttrKeyAlgorithms = ns("kSecAttrKeyAlgorithms")

# --- Key types ---
kSecAttrKeyTypeRSA = c_void_p.in_dll(c, "kSecAttrKeyTypeRSA")
kSecAttrKeyTypeEC = c_void_p.in_dll(c, "kSecAttrKeyTypeEC")

# --- Encryption Algorithms ---
RSAEncryptionPKCS1_Algorithm = ns("RSAEncryptionPKCS1")
ECIESEncryptionStandard_Algorithm = ns("ECIESEncryptionStandardVariableIVX963SHA256")

# --- Signing Algorithms ---
RSASignaturePKCS1v15SHA256 = ns("RSASignatureDigestV2_SHA256")
ECDSASignatureP256SHA256 = ns("ECDSA_P256_SHA256")

# --- Native C function declarations ---
SecKeyCreateRandomKey = c.SecKeyCreateRandomKey
SecKeyCreateRandomKey.restype = c_void_p
SecKeyCreateRandomKey.argtypes = [c_void_p, c_void_p]

SecKeyCopyExternalRepresentation = c.SecKeyCopyExternalRepresentation
SecKeyCopyExternalRepresentation.restype = c_void_p
SecKeyCopyExternalRepresentation.argtypes = [c_void_p, c_void_p]

SecKeyCopyPublicKey = c.SecKeyCopyPublicKey
SecKeyCopyPublicKey.restype = c_void_p
SecKeyCopyPublicKey.argtypes = [c_void_p]

# --- Deprecated Native C function declarations
SecKeyGeneratePair = c.SecKeyGeneratePair
SecKeyGeneratePair.restype = c_void_p
SecKeyGeneratePair.argtypes = [c_void_p, c_void_p, c_void_p]

# Encryption/Decription
SecKeyCreateEncryptedData = c.SecKeyCreateEncryptedData
SecKeyCreateEncryptedData.restype = c_void_p
SecKeyCreateEncryptedData.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]

SecKeyCreateDecryptedData = c.SecKeyCreateDecryptedData
SecKeyCreateDecryptedData.restype = c_void_p
SecKeyCreateDecryptedData.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]

# CoreFoundation helpers for data
CFDataCreate = c.CFDataCreate
CFDataCreate.restype = c_void_p
CFDataCreate.argtypes = [c_void_p, ctypes.c_void_p, c_size_t]

CFDataGetLength = c.CFDataGetLength
CFDataGetLength.restype = ctypes.c_long
CFDataGetLength.argtypes = [c_void_p]

CFDataGetBytePtr = c.CFDataGetBytePtr
CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_byte)
CFDataGetBytePtr.argtypes = [c_void_p]

CFRelease = c.CFRelease
CFRelease.restype = None
CFRelease.argtypes = [c_void_p]

# Keychain functions
SecItemCopyMatching = c.SecItemCopyMatching
SecItemCopyMatching.restype = ctypes.c_int32
SecItemCopyMatching.argtypes = [c_void_p, c_void_p]

kSecClass = c_void_p.in_dll(c, "kSecClass")
kSecClassKey = c_void_p.in_dll(c, "kSecClassKey")
kSecReturnRef = c_void_p.in_dll(c, "kSecReturnRef")

# Signature
SecKeyCreateSignature = c.SecKeyCreateSignature
SecKeyCreateSignature.restype = c_void_p
SecKeyCreateSignature.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]

SecKeyVerifySignature = c.SecKeyVerifySignature
SecKeyVerifySignature.restype = c_void_p
SecKeyVerifySignature.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]

# --- Helper functions ---
def create_cf_data(data):
    # Create a CFDataRef from Python bytes
    # FIXME: need isinstance?
    # if isinstance(data, str):
    #     data = data.encode('utf-8')
    return CFDataCreate(None, data, len(data))


def get_cf_data_bytes(cf_data_ref):
    if not cf_data_ref:
        return None
    data_ptr = CFDataGetBytePtr(cf_data_ref)
    data_len = CFDataGetLength(cf_data_ref)
    if not data_ptr or not data_len:
        return None
    return ctypes.string_at(data_ptr, data_len)

def to_pem_format(key_data, key_type="PUBLIC KEY"):
    header = f"-----BEGIN {key_type}-----\n"
    footer = f"\n-----END {key_type}-----"
    encoded_data = base64.b64encode(key_data).decode("utf-8")
    pem_string = header + "\n".join(encoded_data[i:i+64] for i in range(0, len(encoded_data), 64)) + footer
    return pem_string


def generate_key_pair(key_type, key_size_bits, algorythm, application_tag=None, exportable=False):

    # --- Public key attributes ---
    public_attrs = NSMutableDictionary.alloc().init()
    public_attrs.setObject_forKey_(kCFBooleanFalse, kSecAttrIsPermanent)

    # --- Private key attributes ---
    private_attrs = NSMutableDictionary.alloc().init()
    if application_tag:
        private_attrs.setObject_forKey_(kCFBooleanTrue, kSecAttrIsPermanent)
        private_attrs.setObject_forKey_(ns(application_tag), kSecAttrApplicationTag)
    else:
        private_attrs.setObject_forKey_(kCFBooleanFalse, kSecAttrIsPermanent)

    if exportable:
        private_attrs.setObject_forKey_(kCFBooleanTrue, kSecAttrIsExtractable)
    else:
        private_attrs.setObject_forKey_(kCFBooleanFalse, kSecAttrIsExtractable)

    # NEW: Specify the supported algorithms for the key in their respective dictionaries
    algorithm_list = NSArray.arrayWithObject_(algorythm)
    public_attrs.setObject_forKey_(algorithm_list, kSecAttrKeyAlgorithms)
    private_attrs.setObject_forKey_(algorithm_list, kSecAttrKeyAlgorithms)

    # --- Key generation attributes ---
    key_gen_attrs = NSMutableDictionary.alloc().init()
    key_gen_attrs.setObject_forKey_(key_type, kSecAttrKeyType)
    key_gen_attrs.setObject_forKey_(NSNumber.numberWithInt_(key_size_bits), kSecAttrKeySizeInBits)
    key_gen_attrs.setObject_forKey_(public_attrs, kSecPublicKeyAttrs)
    key_gen_attrs.setObject_forKey_(private_attrs, kSecPrivateKeyAttrs)

    # --- Generate key pair ---
    private_key_ptr = c_void_p(0)
    public_key_ptr = c_void_p(0)
    error_ptr = c_void_p(0)

    private_key_ptr = SecKeyCreateRandomKey(key_gen_attrs, byref(error_ptr))

    if private_key_ptr:
        private_key = ObjCInstance(private_key_ptr)
        public_key_ptr = SecKeyCopyPublicKey(private_key_ptr)
        public_key = ObjCInstance(public_key_ptr)
        return public_key, private_key
    else:
        error = ObjCInstance(error_ptr) if error_ptr else None
        print(f"Error generating key pair: {error}")
        return None, None


# Export to pem
def export_to_pem(key, key_file_path, key_type: str = "PRIVATE KEY"):
    # --- Export and save the keys to PEM format ---
    print(f"\nExporting the {key_type} data...")
    key_data_ref = SecKeyCopyExternalRepresentation(key.ptr, None)
    if key_data_ref:
        try:
            data_bytes = get_cf_data_bytes(key_data_ref)
            CFRelease(key_data_ref)
            pem_key = to_pem_format(data_bytes, key_type)
            print(f"\n{key_type} (PEM format):")
            print(pem_key)
            with open(key_file_path, "w") as f:
                f.write(pem_key)
            print(f"\n{key_type} successfully saved to '{key_file_path}'.")
        except (ValueError, TypeError) as e:
            print(f"Error exporting {key_type} data: {e}")
    else:
        print(f"Error: Could not get the external representation of the {key_type}.")


def encrypt_message(public_key, algorythm, message):
    plaintext_cf_data = create_cf_data(message)
    error_ref = c_void_p(0)

    ciphertext_ref = SecKeyCreateEncryptedData(
        public_key.ptr,
        algorythm,
        plaintext_cf_data,
        byref(error_ref),
    )

    if ciphertext_ref:
        ciphertext = get_cf_data_bytes(ciphertext_ref)
        CFRelease(ciphertext_ref)
        CFRelease(plaintext_cf_data)
        return ciphertext
    else:
        error = ObjCInstance(error_ref) if error_ref else None
        print(f"Encryption failed with error: {error}")
        if plaintext_cf_data:
            CFRelease(plaintext_cf_data)
        return None


def decrypt_message(private_key, algorythm, ciphertext):
    ciphertext_cf_data = create_cf_data(ciphertext)
    error_ref = c_void_p(0)

    plaintext_ref = SecKeyCreateDecryptedData(
        private_key.ptr,
        algorythm,
        ciphertext_cf_data,
        byref(error_ref),
    )

    if plaintext_ref:
        plaintext = get_cf_data_bytes(plaintext_ref)
        CFRelease(plaintext_ref)
        CFRelease(ciphertext_cf_data)
        return plaintext
    else:
        error = ObjCInstance(error_ref) if error_ref else None
        print(f"Decryption failed with error: {error}")
        if ciphertext_cf_data:
            CFRelease(ciphertext_cf_data)
        return None


def sign_message(private_key, algorythm, message):
    message_cf_data = create_cf_data(message)
    error_ref = c_void_p(0)

    signature_ref = SecKeyCreateSignature(
        private_key.ptr,
        algorythm,
        message_cf_data,
        byref(error_ref)
    )

    if signature_ref:
        signature = get_cf_data_bytes(signature_ref)
        CFRelease(signature_ref)
        CFRelease(message_cf_data)
        return signature
    else:
        error = ObjCInstance(error_ref) if error_ref else None
        print(f"Signing failed with error: {error}")
        if message_cf_data:
            CFRelease(message_cf_data)
        return None


def verify_signature(public_key, algorythm, message, signature):
    message_cf_data = create_cf_data(message)
    signature_cf_data = create_cf_data(signature)
    error_ref = c_void_p(0)

    is_valid = SecKeyVerifySignature(
        public_key.ptr,
        algorythm,
        message_cf_data,
        signature_cf_data,
        byref(error_ref)
    )

    CFRelease(message_cf_data)
    CFRelease(signature_cf_data)

    if is_valid:
        return True
    else:
        error = ObjCInstance(error_ref) if error_ref else None
        print(f"Signature verification failed with error: {error}")
        return False


def _test_encryption(key_size, key_type, key_type_prefix, algorythm):
    exportable = True
    key_tag = f"com.example.mykey.{uuid.uuid4()}"
    private_key_file_path = "private_key.pem"
    public_key_file_path = "public_key.pem"

    pub_key, priv_key = generate_key_pair(
        key_type,
        key_size,
        algorythm,
        application_tag=key_tag,
        exportable=exportable,
    )

    if pub_key and priv_key and exportable:
        print(f"{key_type_prefix} key pair generated successfully!")
        export_to_pem(priv_key, private_key_file_path, f"{key_type_prefix} PRIVATE KEY")
        export_to_pem(pub_key, public_key_file_path)

        # --- Demonstration of Encryption/Decryption ---
        print("\n--- Demonstrating Encryption/Decryption with Modern APIs ---")
        message = b"Hello, Pythonista! This is a secret message."

        # Encrypt the message using the public key
        ciphertext = encrypt_message(pub_key, algorythm, message)
        if ciphertext:
            print(f"Original message: {message.decode()}")
            print(f"Ciphertext (base64): {base64.b64encode(ciphertext).decode()}")

            # Decrypt the message using the private key
            plaintext = decrypt_message(priv_key, algorythm, ciphertext)
            if plaintext:
                print(f"Decrypted message: {plaintext.decode()}")

        CFRelease(pub_key.ptr)
        CFRelease(priv_key.ptr)
    else:
        print(f"Error: Failed to generate the {key_type_prefix} key pair.")

def _test_sign(key_size, key_type, key_type_prefix, algorythm):
    exportable = True
    key_tag = f"com.example.mykey.{uuid.uuid4()}"
    private_key_file_path = "private_key.pem"
    public_key_file_path = "public_key.pem"

    pub_key, priv_key = generate_key_pair(key_type, key_size, algorythm, application_tag=key_tag, exportable=exportable)

    if pub_key and priv_key and exportable:
        print(f"{key_type_prefix} key pair generated successfully!")
        export_to_pem(priv_key, private_key_file_path, f"{key_type_prefix} PRIVATE KEY")
        export_to_pem(pub_key, public_key_file_path)

        # --- Demonstrating Signing and Verification ---
        print(
            f"\n--- Demonstrating Signing and Verification with {key_type_prefix} Keys ---"
        )
        message = b"Hello, Pythonista! This is a secret message."

        signature = sign_message(priv_key, algorythm, message)

        if signature:
            print(
                f"Message signed successfully. Signature (base64): {base64.b64encode(signature).decode()}"
            )

            is_valid = verify_signature(pub_key, algorythm, message, signature)

            if is_valid:
                print("Signature verification successful!")
            else:
                print("Signature verification failed!")

        else:
            print("Signing failed!")

        CFRelease(pub_key.ptr)
        CFRelease(priv_key.ptr)
    else:
        print(f"Error: Failed to generate the {key_type_prefix} key pair.")

def _test_rsa():
    key_size = 2048
    key_type = kSecAttrKeyTypeRSA
    key_type_prefix = "RSA"
    enc_algorythm = RSAEncryptionPKCS1_Algorithm
    sign_algorythm = RSASignaturePKCS1v15SHA256
    key_tag = f"com.example.mykey.{uuid.uuid4()}"
    print(f"Attempting to generate an exportable {key_size}-bit {key_type_prefix} key pair with tag: {key_tag}")
    _test_encryption(key_size, key_type, key_type_prefix, enc_algorythm)
    _test_sign(key_size, key_type, key_type_prefix, sign_algorythm)

def _test_ecdsa():
    key_size = 256
    key_type = kSecAttrKeyTypeEC
    key_type_prefix = "EC"
    enc_algorythm = ECIESEncryptionStandard_Algorithm
    sign_algorythm = ECDSASignatureP256SHA256
    key_tag = f"com.example.mykey.{uuid.uuid4()}"
    print(f"Attempting to generate an exportable {key_size}-bit {key_type_prefix} key pair with tag: {key_tag}")
    _test_encryption(key_size, key_type, key_type_prefix, enc_algorythm)
    _test_sign(key_size, key_type, key_type_prefix, sign_algorythm)

# --- Main execution block ---
if __name__ == "__main__":
    _test_rsa()
    _test_ecdsa()
