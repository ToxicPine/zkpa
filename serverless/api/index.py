from flask import Flask, jsonify, request
from PIL import Image
import io
import blake3
import secp256k1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import json
from random import randbytes

app = Flask(__name__)

def bytes_from_hex(hex_string):
    return bytes.fromhex(hex_string)

def extract_and_convert_image_to_ppm(image_data):
    img = Image.open(io.BytesIO(image_data))
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

def generate_camera_id(nonce_hex, pub_key_compressed, ecdh_key_hex):
    nonce = bytes_from_hex(nonce_hex)
    ecdh_key = bytes_from_hex(ecdh_key_hex)

    camera_id = nonce[:31] + pub_key_compressed[0:32]
    encrypted_camera_id = encrypt_data(camera_id, ecdh_key)
    return encrypted_camera_id

def return_byte_array_str(hex_string):
    byte_array = bytes.fromhex(hex_string)
    formatted_bytes: str = "[" + ', '.join(f'0x{byte:02X}' for byte in byte_array) + "]"
    return formatted_bytes

@app.route('/get_witness', methods=['POST'])
def get_witness():
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400

    nonce_hex = randbytes(31)
    ecdh_scalar = "3f9e36da67670ab97e60c2d6138e7049b79e64ef"
    consortium_pubkey = ["022a76889006b3268357bc86a0737304d518aa2d6556b495442f092bb1a6c132", "076d4453fe98427afe1ee6153c17917ccae7050fbcd87cde21088b4bd6f56b11"]
    private_key_hex = 'ec28f3b5e71d85971df7edbf06ae04f2ec28f3b5e71d85971df7edbf06ae04f2'
    authority_private_key_hex = 'ec28f06ae04f2ec6ae04f228f3b5e71d85971df7edbf0f3b5e71d85971df7edb'

    image_file = request.files['image']
    image_origin = image_file.read()
    image_data = extract_and_convert_image_to_ppm(image_origin)
    hashed_image_data = hash_data(image_data)
    
    signature, pub_key_compressed = sign_data(private_key_hex, hashed_image_data)
    camera_pubkey_x, camera_pubkey_y = get_public_key_hex(private_key_hex)
    
    authority_signature, _ = sign_data(authority_private_key_hex, pub_key_compressed)
    trusted_x, trusted_y = get_public_key_hex(authority_private_key_hex)

    prover_key = [0x0121, 0xa16a]
    asserted_camera_identifier = randbytes(64)

    witness_data = {
        "random_nonce": [x for x in nonce_hex],
        "ecdh_scalar": int(ecdh_scalar,16),
        "camera_pubkey_x": [x for x in bytes_from_hex(camera_pubkey_x)], 
        "camera_pubkey_y": [x for x in bytes_from_hex(camera_pubkey_y)],
        "camera_attestation": [x for x in signature],
        "consortium_pubkey": [int(consortium_pubkey[0],16), int(consortium_pubkey[1],16)],
        "identifier_deckey": [prover_key[0], prover_key[1]],
        "authority_pubkey_x": [x for x in bytes_from_hex(trusted_x)],
        "authority_pubkey_y": [x for x in bytes_from_hex(trusted_y)],
        "authority_attestation": [x for x in authority_signature],
        "image_hash": [x for x in hashed_image_data],
        "camera_identifier": [x for x in asserted_camera_identifier]
    }

    return witness_data

@app.route('/hash_image', methods=['POST'])
def hash_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400

    image_file = request.files['image']
    image_data = image_file.read()
    hashed_data = hash_data(image_data)
    hashed_hex = hashed_data.hex()
    byte_array_str = return_byte_array_str(hashed_hex)

    return jsonify({
        'hash_hex': hashed_hex,
        'hash_byte_array': byte_array_str
    })

if __name__ == '__main__':
    app.run(debug=True)