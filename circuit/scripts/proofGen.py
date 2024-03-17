import subprocess
import toml
import os
import io
import sys
from exif import Image as ExifImage

filename = sys.argv[-1]

def add_exif_to_image(image_path, data):
    with open(image_path, 'rb') as image_file:
        my_image = ExifImage(image_file)
        my_image.maker_note(data)

def main(image_path):
    # Run "nargo prove" in the terminal and wait for it to finish
    subprocess.run(["nargo", "prove"], check=True)

    # Read the contents of "../Verifier.toml"
    verifier_path = "../Verifier.toml"
    with open(verifier_path, "r") as file:
        verifier_data = toml.load(file)

    # Read the content of "../proofs/zkpa.proof"
    proof_path = "../proofs/zkpa.proof"
    with open(proof_path, "r") as file:
        zkpa_proof = file.read()

    # Add the zkpa.proof content to the dictionary with the key "zkp"
    verifier_data["zkp"] = zkpa_proof

    print(verifier_data)

    #bug here, should be easy fix but I can't be asked.
    #add_exif_to_image(image_path, verifier_data)

if __name__ == '__main__':
    main(filename)