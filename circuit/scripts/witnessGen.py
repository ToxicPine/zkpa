import blake3
import secp256k1
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import io
import os
import json
from random import randbytes

def bytes_from_hex(hex_string):
    return bytes.fromhex(hex_string)

def extract_and_convert_image_to_ppm(image_path):
    with Image.open(image_path) as img:
        img_rgb = img.convert('RGB')
        bytes_io = io.BytesIO()
        img_rgb.save(bytes_io, format='PPM')
        return bytes_io.getvalue()

def hash_data(data):
    return blake3.blake3(data).digest()

def sign_data(private_key_hex, data):
    private_key = secp256k1.PrivateKey(bytes_from_hex(private_key_hex))
    signature = private_key.ecdsa_sign(hash_data(data), raw=True)
    serialized_signature = private_key.ecdsa_serialize_compact(signature)
    return serialized_signature, private_key.pubkey.serialize(compressed=True)

def get_public_key_hex(private_key_hex):
    private_key = secp256k1.PrivateKey(bytes_from_hex(private_key_hex))
    public_key = private_key.pubkey.serialize(compressed=False)
    return public_key.hex()[2:66], public_key.hex()[66:130]

def encrypt_data(data, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(data)

def generate_camera_id(nonce, pub_key_compressed, ecdh_key_hex):
    ecdh_key = bytes_from_hex(ecdh_key_hex)

    camera_id = nonce[:31] + pub_key_compressed[0:32]
    encrypted_camera_id = encrypt_data(camera_id, ecdh_key)
    return encrypted_camera_id

def main(image_path, private_key_hex, authority_private_key_hex, consortium_pubkey, nonce_hex, ecdh_scalar_hex):
    image_data = extract_and_convert_image_to_ppm(image_path)
    hashed_image_data = hash_data(image_data)
    
    signature, pub_key_compressed = sign_data(private_key_hex, hashed_image_data)
    camera_pubkey_x, camera_pubkey_y = get_public_key_hex(private_key_hex)
    
    authority_signature, _ = sign_data(authority_private_key_hex, pub_key_compressed)
    trusted_x, trusted_y = get_public_key_hex(authority_private_key_hex)

    #prover_key = babyjubjub_generate_pubkey(ecdh_scalar_hex)
    prover_key = [0x0121, 0xa16a]
    #ecdh_key_hex = babyjubjub_ecdh(ecdh_scalar_hex, consortium_pubkey)

    # Pre-Calculated, Since Values Are Hardcoded And Python Doesn't Like BabyJubJub. See tests in Noir to validate.
    ecdh_key_hex = bytes([1, 235, 39, 113, 46, 171, 235, 252, 178, 0, 51, 33, 198, 103, 237, 184]).hex()
    asserted_camera_identifier = generate_camera_id(nonce_hex, pub_key_compressed, ecdh_key_hex)
    asserted_camera_identifier = randbytes(64)

    witness_data = {
        "random_nonce": [x for x in nonce_hex],
        "ecdh_scalar": ecdh_scalar,
        "camera_pubkey_x": [x for x in bytes_from_hex(camera_pubkey_x)], 
        "camera_pubkey_y": [x for x in bytes_from_hex(camera_pubkey_y)],
        "camera_attestation": [x for x in signature],
        "consortium_pubkey": [consortium_pubkey[0], consortium_pubkey[1]],
        "identifier_deckey": [prover_key[0], prover_key[1]],
        "authority_pubkey_x": [x for x in bytes_from_hex(trusted_x)],
        "authority_pubkey_y": [x for x in bytes_from_hex(trusted_y)],
        "authority_attestation": [x for x in authority_signature],
        "image_hash": [x for x in hashed_image_data],
        "camera_identifier": [x for x in asserted_camera_identifier]
    }

    print(json.dumps(witness_data))

if __name__ == '__main__':
    image_path = '/Users/zihan/Desktop/hackathon-london/zkpa-frontend/circuit/scripts/ETHLondon.png'
    private_key_hex = 'ec28f3b5e71d85971df7edbf06ae04f2ec28f3b5e71d85971df7edbf06ae04f2'
    authority_private_key_hex = 'ec28f06ae04f2ec6ae04f228f3b5e71d85971df7edbf0f3b5e71d85971df7edb'
    consortium_pubkey = ["022a76889006b3268357bc86a0737304d518aa2d6556b495442f092bb1a6c132", "076d4453fe98427afe1ee6153c17917ccae7050fbcd87cde21088b4bd6f56b11"]    # Generated on BabyJubJub from Private Key 0x10203040506
    nonce_hex = randbytes(31)
    ecdh_scalar = "3f9e36da67670ab97e60c2d6138e7049b79e64ef"
    main(image_path, private_key_hex, authority_private_key_hex, consortium_pubkey, nonce_hex, ecdh_scalar)
