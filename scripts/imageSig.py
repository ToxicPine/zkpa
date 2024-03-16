import blake3
import secp256k1
from PIL import Image
from ecdsa import ellipticcurve
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from bn254.constants import *
from bn254 import big
from bn254 import curve
from bn254.ecp import *
from bn254.ecp import generator as generator
from bn254.ecp import ECp as ECp
import hashlib
import os
import io

ecdh_scalar = "3f9e36da67670ab97e60c2d6138e7049b79e64ef"
random_nonce = "14e50ec35ddee0bd40134da8023249c715231924cc3cfd3cdd950715ebb9d5"
# consortium private key is 0x10203040506
consortiumPubKeyX = "022a76889006b3268357bc86a0737304d518aa2d6556b495442f092bb1a6c132"
consortiumPubKeyY = "076d4453fe98427afe1ee6153c17917ccae7050fbcd87cde21088b4bd6f56b11"
decryptPk_x = "255679baf28978b9b98db6c36283b709233c7acedc7db13e0b475a1710be1352"
decryptPk_y = "243837430f4955e3de9539fbda12361313ff558eaef45ef4f41c6aa5a974b807"

def gen_unencrypted_camera_id(random_nonce, camera_pubkey_y, camera_pubkey_x):
    camera_id = bytearray(64)
    random_nonce_bytes = bytes.fromhex(random_nonce)
    camera_pubkey_x_bytes = bytes.fromhex(camera_pubkey_x)
    camera_pubkey_y_bytes = bytes.fromhex(camera_pubkey_y)
    
    for i in range(31):
        camera_id[i] = random_nonce_bytes[i]
    
    camera_id[31] = camera_pubkey_y_bytes[0]

    for i in range(32):
        camera_id[i+32] = camera_pubkey_x_bytes[i]
    
    return camera_id

def gen_camera_id(random_nonce, camera_pubkey_y, camera_pubkey_x, ecdh_scalar, keeper_pk_x, keeper_pk_y):
    camera_id = gen_unencrypted_camera_id(random_nonce, camera_pubkey_y, camera_pubkey_x)
    
    # Pre-Calculated, Since Values Are Hardcoded And Python Doesn't Like BabyJubJub. See tests in Noir to validate.
    ecdh_key = bytes([1, 235, 39, 113, 46, 171, 235, 252, 178, 0, 51, 33, 198, 103, 237, 184])
    
    # Initialize AES cipher for encryption
    backend = default_backend()
    cipher = Cipher(algorithms.AES(ecdh_key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    
    # Encrypt camera_id in 16-byte blocks using slicing
    encrypted_camera_id = bytearray(len(camera_id))
    for i in range(0, len(camera_id), 16):
        encrypted_camera_id[i:i+16] = encryptor.update(camera_id[i:i+16])
    
    return encrypted_camera_id

def return_byte_array_str(hex_string):
    byte_array = bytes.fromhex(hex_string)
    formatted_bytes: str = "[" + ', '.join(f'0x{byte:02X}' for byte in byte_array) + "]"
    return formatted_bytes

def extract_png_data(file_path):
    with Image.open(file_path) as img:
        rgb_img = img.convert('RGB')
        
        bytes_io = io.BytesIO()
        rgb_img.save(bytes_io, format='PPM')
        raw_data = bytes_io.getvalue()
        
    return raw_data

def hash_data(data):
    return blake3.blake3(data).digest()

def sign_data(private_key_bytes, data_hash):
    priv_key = secp256k1.PrivateKey(private_key_bytes)
    signature = priv_key.ecdsa_sign(data_hash, raw=True)
    serialized_sig = priv_key.ecdsa_serialize_compact(signature)
    return serialized_sig, priv_key.pubkey.serialize(compressed=True)

def getPubkey(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    priv_key = secp256k1.PrivateKey(private_key_bytes)
    pub_key = priv_key.pubkey.serialize(compressed=False)
    x, y = pub_key.hex()[2:66], pub_key.hex()[66:130]
    return x, y

def main():
    image_data = extract_png_data('ETHLondon.png')
    hashed_data = hash_data(image_data)
    
    private_key_hex = 'ec28f3b5e71d85971df7edbf06ae04f2ec28f3b5e71d85971df7edbf06ae04f2'
    private_key_bytes = bytes.fromhex(private_key_hex)
    serialized_sig, compressed_pub_key = sign_data(private_key_bytes, hashed_data)
    camera_pubkey_x, camera_pubkey_y = getPubkey(private_key_hex)

    authorityPrivKey = 'ec28f06ae04f2ec6ae04f228f3b5e71d85971df7edbf0f3b5e71d85971df7edb'
    authority_private_key_bytes = bytes.fromhex(authorityPrivKey)
    authority_camera_certificate, useless = sign_data(authority_private_key_bytes, hash_data(compressed_pub_key))
    authority_camera_certificate = authority_camera_certificate.hex()
    trustedX, trustedY = getPubkey(authorityPrivKey)
    
    print("randomNonce =", return_byte_array_str(random_nonce))
    print("ecdhScalar =", f"'0x{ecdh_scalar}'")
    print("cameraPubKeyX =", return_byte_array_str(compressed_pub_key.hex()[2:66]))
    print("cameraPubKeyFullY =", return_byte_array_str(camera_pubkey_y))
    print("cameraAttestationSignature =", return_byte_array_str(serialized_sig.hex()))
    print("consortiumPubKey = [", ', '.join([f"'0x{consortiumPubKeyX}'", f"'0x{consortiumPubKeyY}'"]), "]")
    print("assertedDecryptPk = [", ', '.join([f"'0x{decryptPk_x}'", f"'0x{decryptPk_y}'"]), "]")
    print("certAuthorityPubkeyX =", return_byte_array_str(trustedX))
    print("certAuthorityPubkeyY =", return_byte_array_str(trustedY))
    print("certAuthoritySignature =", return_byte_array_str(authority_camera_certificate))
    print("imageHash =", return_byte_array_str(hash_data(image_data).hex()))
    print("assertedCameraIdentifier =", return_byte_array_str(gen_camera_id(random_nonce, compressed_pub_key.hex()[:2], compressed_pub_key.hex()[2:66], ecdh_scalar, consortiumPubKeyX, consortiumPubKeyY).hex()))

if __name__ == '__main__':
    main()
