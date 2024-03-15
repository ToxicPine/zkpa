import blake3
import secp256k1
from PIL import Image
import io

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

def main():
    image_data = extract_png_data('ETHLondon.png')
    hashed_data = hash_data(image_data)
    
    # Replace with your actual private key bytes
    private_key_hex = 'ec28f3b5e71d85971df7edbf06ae04f2ec28f3b5e71d85971df7edbf06ae04f2'
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    serialized_sig, compressed_pub_key = sign_data(private_key_bytes, hashed_data)
    r, s = serialized_sig[0][:32], serialized_sig[0][32:64]
    
    print("Signature:", serialized_sig[0].hex())
    print("Public Key, Y:", compressed_pub_key.hex()[:2])
    print("Public Key, X:", compressed_pub_key.hex()[2:66])

if __name__ == '__main__':
    main()
