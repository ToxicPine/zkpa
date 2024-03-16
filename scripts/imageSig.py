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

def BabyJubJub_ECDH(scalar, keeper_pk_x, keeper_pk_y):
    scalar = int.from_bytes(bytes.fromhex(scalar)) % curve.r

    keeper_point = ECp()
    keeper_point.setxy(
        int.from_bytes(keeper_pk_x), 
        int.from_bytes(keeper_pk_y)
    )
    
    ecdh_point = scalar * keeper_point
    ecdh_key, lsb_y = ecdh_point.getxs()

    return ecdh_key

def getJubJubPubkey(scalar):
    G = generator()
    scalar = big.from_bytes(bytes.fromhex(scalar)) % curve.r

    Y = scalar * G
    pk = Y.toBytes(False)
    y = pk[1:33]
    x = pk[33:68]
    return x, y

ecdh_scalar = "3f9e36da67670ab97e60c2d6138e7049b79e64ef"
random_nonce = "14e50ec35ddee0bd40134da8023249c715231924cc3cfd3cdd950715ebb9d5"

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
    
    ecdh_key = BabyJubJub_ECDH(ecdh_scalar, keeper_pk_x, keeper_pk_y)
    ecdh_key_bytes = ecdh_key.to_bytes(32, 'little')
    ecdh_key_16 = ecdh_key_bytes[16:32]
    
    # Initialize AES cipher for encryption
    backend = default_backend()
    cipher = Cipher(algorithms.AES(ecdh_key_16), modes.ECB(), backend=backend)
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
    #camera_pubkey_x, camera_pubkey_y = getPubkey(private_key_hex)

    keeperPrivKey = 'ec28f06ae04f2ec28f3b5e71d85971df7edbf06ae04f2f3b5e71d85971df7edb'
    keeperX, keeperY = getJubJubPubkey(keeperPrivKey)

    authorityPrivKey = 'ec28f06ae04f2ec6ae04f228f3b5e71d85971df7edbf0f3b5e71d85971df7edb'
    authority_private_key_bytes = bytes.fromhex(authorityPrivKey)
    authority_camera_certificate, useless = sign_data(authority_private_key_bytes, hash_data(compressed_pub_key))
    authority_camera_certificate = authority_camera_certificate.hex()
    trustedX, trustedY = getPubkey(authorityPrivKey)
    
    print("randomNonce =", return_byte_array_str(random_nonce))
    print("ecdhScalar =", return_byte_array_str(ecdh_scalar))
    print("cameraPubKeyX =", return_byte_array_str(compressed_pub_key.hex()[2:66]))
    print("cameraPubKeyY =", f"0x{compressed_pub_key.hex()[:2]}")
    print("cameraAttestationSignature =", return_byte_array_str(serialized_sig.hex()))
    print("keeperKey = [", ', '.join([return_byte_array_str(keeperX.hex()), return_byte_array_str(keeperY.hex())]), "]")
    print("certAuthorityPubkeyX =", return_byte_array_str(trustedX))
    print("certAuthorityPubkeyY =", return_byte_array_str(trustedY))
    print("certAuthoritySignature =", return_byte_array_str(authority_camera_certificate))
    print("imageHash =", return_byte_array_str(hash_data(image_data).hex()))
    print("assertedCameraIdentifier =", return_byte_array_str(gen_camera_id(random_nonce, compressed_pub_key.hex()[:2], compressed_pub_key.hex()[2:66], ecdh_scalar, keeperX, keeperY).hex()))

if __name__ == '__main__':
    main()
