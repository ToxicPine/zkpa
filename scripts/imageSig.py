import blake3
import secp256k1
from PIL import Image
from ecdsa import ellipticcurve
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tinyec.ec as ec
import os
import io

EC_CURVE_REGISTRY = {
    "babyJubJub": {
        "p": 21888242871839275222246405745257275088548364400416034343698204186575808495617,
        "a": 168698,
        "b": 1,
        "g": (
            7,
            4258727773875940690362607550498304598101071202821725296872974770776423442226
        ),
        "n": 21888242871839275222246405745257275088614511777268538073601725287587578984328,
        "h": 8
    }
}

def get_curve(name):
    curve_params = {}
    for k, v in EC_CURVE_REGISTRY.items():
        if name.lower() == k.lower():
            curve_params = v
    if curve_params == {}:
        raise ValueError("Unknown elliptic curve name")
    try:
        sub_group = ec.SubGroup(curve_params["p"], curve_params["g"], curve_params["n"], curve_params["h"])
        curve = ec.Curve(curve_params["a"], curve_params["b"], sub_group, name)
    except KeyError:
        raise RuntimeError("Missing parameters for curve %s" % name)
    return curve

babyJubJub = get_curve("babyJubJub")

def BabyJubJub_ECDH(scalar, keeper_pk_x, keeper_pk_y):
    scalar = int.from_bytes(bytes.fromhex(scalar))

    keeper_point = ec.Point(babyJubJub, keeper_pk_x, keeper_pk_y)
    ecdh_point = scalar * keeper_point
    ecdh_key = ecdh_point.x

    return ecdh_key

def getJubJubPubkey(scalar):
    G = babyJubJub.g

    scalar = int.from_bytes(bytes.fromhex(scalar))
    pk = scalar * G

    return pk.x, pk.y

ecdh_scalar = "6915a13c1d33d5d315eea68a82737305fea27d6f78cf0917f3130ba8c118fa0f40eefca31cce1335802a2ed223d0d2d651f78780885fd7284612dea3d761c4df1d8b8ab9c53998a20cfa14f1fd6a4269ee194eb85ae92146b4f6434666bd7f8ab62cf7e265ba3b57f84558ba0e81913009f1008b77b7233608d1f41e49bd2084da27c9e8f8367f4e5bf9682f07a64779cb5a090dc61006f7c49247032370c52de7692aa431b4ba862d2bc29dabc8795b6957f41ff3bcf4c5b5b8e67a7dd17a79824155ffe04b61b6c5bc864bd9ebcbc3bdfaf3d369bab324fb1dccab19105eedea4953cdf41eaaf915c241b3966b9b8788cbc748006a4b321666342589c2"
random_nonce = "14e50ec35ddee0bd40134da8023249c715231924cc3cfd3cdd950715ebb9d588"

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
    
    ecdh_key = BabyJubJub_ECDH(random_nonce, keeper_pk_x, keeper_pk_y)
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
    formatted_bytes: str = [f'0x{byte:02X}' for byte in byte_array]
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
    signature = priv_key.ecdsa_sign_recoverable(data_hash, raw=True)
    serialized_sig = priv_key.ecdsa_recoverable_serialize(signature)
    return serialized_sig, priv_key.pubkey.serialize(compressed=True)

def getPubkey(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    priv_key = secp256k1.PrivateKey(private_key_bytes)
    compressed_pub_key = priv_key.pubkey.serialize(compressed=False)
    y, x = compressed_pub_key.hex()[2:66], compressed_pub_key.hex()[66:130]
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
    authority_camera_certificate = sign_data(authority_private_key_bytes, hash_data(compressed_pub_key))[0][0].hex()
    trustedX, trustedY = getPubkey(authorityPrivKey)
    
    print("Random Nonce:", random_nonce)
    print("ECDH Scalar:", ecdh_scalar)
    print("Camera Public Key, Y:", f"0x{compressed_pub_key.hex()[:2]}")
    print("Camera Public Key, X:", return_byte_array_str(compressed_pub_key.hex()[2:66]))
    print("Camera Signature:", return_byte_array_str(serialized_sig[0].hex()))
    print("Keeper Public Key, X:", keeperX)
    print("Keeper Public Key, Y:", keeperY)
    print("Trusted Authority Public Key, X:", return_byte_array_str(trustedX))
    print("Trusted Authority Public Key, Y:", return_byte_array_str(trustedY))
    print("Trusted Authority Camera Signature:", return_byte_array_str(authority_camera_certificate))
    print("Image Hash:", return_byte_array_str(hash_data(image_data).hex()))

    print(gen_unencrypted_camera_id(random_nonce, compressed_pub_key.hex()[:2], compressed_pub_key.hex()[2:66]).hex())
    print(gen_camera_id(random_nonce, compressed_pub_key.hex()[:2], compressed_pub_key.hex()[2:66], ecdh_scalar, keeperX, keeperY).hex())

if __name__ == '__main__':
    main()
