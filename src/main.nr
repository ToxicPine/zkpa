use dep::std::ec::tecurve::affine::{Curve, Point};
use dep::std::ec::tecurve::affine::Point as G;
use dep::std::ecdsa_secp256k1::verify_signature as ecdsa_verify;
use dep::aes::aes_128_enc as aes_128_enc;

fn babyjub_derive_pubkey(priv_key: Field) -> Point {
    let bjj = Curve::new(
        168700,
        168696,
        G::new(
            995203441582195749578291179787384436505546430278305826713579947235728471134,
            5472060717959818805561601436314318772137091100104008585924551046643952123905
        )
    );

    let base_pt = Point::new(
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    );

    bjj.mul(priv_key, base_pt)
}

fn babyjub_scalarmul(priv_key: Field, base_pt: Point) -> Point {
    let bjj = Curve::new(
        168700,
        168696,
        G::new(
            995203441582195749578291179787384436505546430278305826713579947235728471134,
            5472060717959818805561601436314318772137091100104008585924551046643952123905
        )
    );

    bjj.mul(priv_key, base_pt)
}

// The Camera ID (64 bytes), which will be encrypted, consists of:
// - A Random Nonce (31 bytes)
// - The Unique Compressed Pubkey Of The Camera Signer (33 bytes)
//   - The Y-coord is compressed, we delcare whether it is positive (1 byte)
//   - The X-coord is given (32 bytes)
fn gen_unencrypted_camera_id(
    randomNonce: u32, // This Is Used To Randomise The Cypertext
    cameraPubKeyY: u8, // Y-Coord of Public Key Of Camera Signer, Positive or Negative
    cameraPubKeyX: u32 // X-Coord of Public Key of Camera Signer
) -> [u8; 64] {
    let mut cameraId: [u8; 64] = [0; 64];

    // Append The Nonce To cameraId
    for i in 0..31 {
        cameraId[i] = ((randomNonce >> (i * 8)) & 0xFF) as u8;
    }

    // Append The Camera Pubkey Y To cameraId.
    cameraId[32] = cameraPubKeyY;

    // Append The Camera Pubkey X to cameraID.
    for i in 0..32 {
        cameraId[i+33] = ((cameraPubKeyX >> (i * 8)) & 0xFF) as u8;
    }

    cameraId
}

// Generates the Camera ID in the 64 byte encrypted form.
fn gen_camera_id(
    randomNonce: u32, // This Is Used To Randomise The Cypertext
    cameraPubKeyY: u8, // Y-Coord of Public Key Of Camera Signer, Positive or Negative
    cameraPubKeyX: u32, // X-Coord of Public Key of Camera Signer
    ecdh_scalar: Field, // ECDH Scalar for Symmetric Key Encryption
    keeperKey: Point // Key of the Blacklist Keeper
) -> [u8; 64] {
    // Get encrypted camera ID 
    let cameraId: [u8; 64] = gen_unencrypted_camera_id(randomNonce, cameraPubKeyY, cameraPubKeyX);
    let mut cameraId_bytes: [[u8; 16]; 4] = [[0; 16]; 4];
    for i in 0..(cameraId_bytes.len() - 1) {
        for n in 0..15 {
            cameraId_bytes[i][n] = cameraId[((i*8) + n)];
        }
    }

    // Calculate ECDH Shared Key
    let ecdh_key = babyjub_scalarmul(ecdh_scalar, keeperKey).x as u64;
    let mut ecdh_key_bytes: [u8; 16] = [0; 16];
    for i in 0..15 {
        // Make ecdh_key into a 16 byte key.
        ecdh_key_bytes[i] = ((ecdh_key >> (i * 8)) & 0xFF) as u8;
    }

    // Encrypt Camera ID to Keeper.
    let mut encryptedCameraId_bytes: [[u8; 16]; 4] = [[0; 16]; 4];
    for i in 0..(encryptedCameraId_bytes.len() - 1) {
        // Encrypt 
        encryptedCameraId_bytes[i] = aes_128_enc(cameraId_bytes[i], ecdh_key_bytes);
    }

    // Convert Formats
    let mut encryptedCameraId: [u8; 64] = [0; 64];
    for i in 0..(encryptedCameraId_bytes.len() - 1) {
        for n in 0..15 {
            encryptedCameraId[((i * 8) + n)] = encryptedCameraId_bytes[i][n];
        }
    }

    encryptedCameraId
}

fn main(
    randomNonce: u32,
    cameraPubKeyY: u8,
    cameraPubKeyX: u32,
    ecdh_scalar: Field,
    keeperKey: pub Point,
    certAuthorityPubkeyX: pub [u8; 32],
    certAuthorityPubkeyY: pub [u8; 32],
    certAuthoritySignature: [u8; 64],
    cameraAttestationSignature: [u8; 64],
    imageHash: pub [u8; 32],
    assertedCameraIdentifier: pub [u8; 64]
) {
    // Get Camera Identifier
    let cameraIdentifier = gen_camera_id(
        randomNonce,
        cameraPubKeyY,
        cameraPubKeyX,
        ecdh_scalar,
        keeperKey
    );

    // Get the Camera Pubkey in its Compressed Form.
    let mut cameraPubKey_compressed: [u8; 32] = [0; 32];
    cameraPubKey_compressed[0] = cameraPubKeyY;
    for i in 0..32 {
        cameraPubKey_compressed[i+1] = ((cameraPubKeyX >> (i * 8)) & 0xFF) as u8;
    }

    // Get the Hash of the Camera Pubkey.
    let camPubkeyHash = dep::std::hash::blake3(cameraPubKey_compressed);

    // Check Camera Attestation
    let camera_is_certified: bool = ecdsa_verify(
        certAuthorityPubkeyX,
        certAuthorityPubkeyY,
        certAuthoritySignature,
        camPubkeyHash
    );

    // Get Camera Pubkey As Uncompressed Bytes
    let mut cameraPubkeyX_bytes: [u8; 32] = [0; 32];
    let mut cameraPubkeyY_bytes: [u8; 32] = [0; 32];

    for i in 0..31 {
        cameraPubkeyX_bytes[i] = ((cameraPubKeyX >> (i * 8)) & 0xFF) as u8;
    }
    // GET THE Y-COORD BASED ON POSITIVE OR NEGATIVE AS BYTES

    // Check Image Attestation
    let image_is_attested: bool = ecdsa_verify(
        cameraPubkeyX_bytes,
        cameraPubkeyY_bytes,
        cameraAttestationSignature,
        imageHash
    );

    // Check that the image is attested by the camera, that the camera which is doing the attestation is certified, and that the correct identifier has been passed.
    assert(image_is_attested);
    assert(camera_is_certified);
    assert(cameraIdentifier == assertedCameraIdentifier);
}

#[test]
fn test_main() {
    main(1, 2);
    // Uncomment to make test fail
    // main(1, 1);
}
