import blake3
import secp256k1
from PIL import Image
import io

ecdh_scalar = "6915a13c1d33d5d315eea68a82737305fea27d6f78cf0917f3130ba8c118fa0f40eefca31cce1335802a2ed223d0d2d651f78780885fd7284612dea3d761c4df1d8b8ab9c53998a20cfa14f1fd6a4269ee194eb85ae92146b4f6434666bd7f8ab62cf7e265ba3b57f84558ba0e81913009f1008b77b7233608d1f41e49bd2084da27c9e8f8367f4e5bf9682f07a64779cb5a090dc61006f7c49247032370c52de7692aa431b4ba862d2bc29dabc8795b6957f41ff3bcf4c5b5b8e67a7dd17a79824155ffe04b61b6c5bc864bd9ebcbc3bdfaf3d369bab324fb1dccab19105eedea4953cdf41eaaf915c241b3966b9b8788cbc748006a4b321666342589c2"
random_nonce = "14e50ec35ddee0bd40134da8023249c715231924cc3cfd3cdd950715ebb9d588"

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
    keeperX, keeperY = getPubkey(keeperPrivKey)

    authorityPrivKey = 'ec28f06ae04f2ec6ae04f228f3b5e71d85971df7edbf0f3b5e71d85971df7edb'
    authority_private_key_bytes = bytes.fromhex(authorityPrivKey)
    authority_camera_certificate = sign_data(authority_private_key_bytes, hash_data(compressed_pub_key))[0][0].hex()
    trustedX, trustedY = getPubkey(authorityPrivKey)
    
    print("Random Nonce:", random_nonce)
    print("ECDH Scalar:", ecdh_scalar)
    print("Camera Public Key, Y:", compressed_pub_key.hex()[:2])
    print("Camera Public Key, X:", compressed_pub_key.hex()[2:66])
    print("Camera Signature:", serialized_sig[0].hex())
    print("Keeper Public Key, X:", keeperX)
    print("Keeper Public Key, Y:", keeperY)
    print("Trusted Authority Public Key, X:", trustedX)
    print("Trusted Authority Public Key, Y:", trustedY)
    print("Trusted Authority Camera Signature:", authority_camera_certificate)
    print("Image Hash:", hash_data(image_data).hex())

if __name__ == '__main__':
    main()
