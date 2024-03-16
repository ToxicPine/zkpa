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
    randomNonce: [u8; 31], // This Is Used To Randomise The Cypertext
    cameraPubKeyY: u8, // Y-Coord of Public Key Of Camera Signer, Positive or Negative
    cameraPubKeyX: [u8; 32] // X-Coord of Public Key of Camera Signer
) -> [u8; 64] {
    let mut cameraId: [u8; 64] = [0; 64];

    // Append The Nonce To cameraId
    for i in 0..30 {
        cameraId[i] = randomNonce[i];
    }

    // Append The Camera Pubkey Y To cameraId.
    cameraId[31] = cameraPubKeyY;

    // Append The Camera Pubkey X to cameraID.
    for i in 0..31 {
        cameraId[i+32] = cameraPubKeyX[i];
    }

    cameraId
}

// Provides the Camera ID in the 64 byte encrypted form, using ECDH and AES-128.
fn gen_camera_id(
    randomNonce: [u8; 31], // This Is Used To Randomise The Cypertext
    cameraPubKeyY: u8, // Y-Coord of Public Key Of Camera Signer, Positive or Negative
    cameraPubKeyX: [u8; 32], // X-Coord of Public Key of Camera Signer
    ecdh_scalar: Field, // ECDH Scalar for Symmetric Key Encryption
    keeperKey: Point // Key of the Blacklist Keeper
) -> [u8; 64] {
    // Get Encrypted Camera ID 
    let cameraId: [u8; 64] = gen_unencrypted_camera_id(randomNonce, cameraPubKeyY, cameraPubKeyX);
    let mut cameraId_chunk: [[u8; 16]; 4] = [[0; 16]; 4];
    for i in 0..(cameraId_chunk.len() - 1) {
        for n in 0..15 {
            cameraId_chunk[i][n] = cameraId[((i*8) + n)];
        }
    }

    // Calculate ECDH Shared Key.
    let ecdh_key = babyjub_scalarmul(ecdh_scalar, keeperKey).x as u32;
    let mut ecdh_key_bytes: [u8; 16] = [0; 16];
    for i in 0..15 {
        // Make ecdh_key Into a 16 Byte Key.
        ecdh_key_bytes[i] = ((ecdh_key >> (i * 8)) & 0xFF) as u8;
    }

    // Encrypt Camera ID to Keeper.
    let mut encryptedCameraId_bytes: [[u8; 16]; 4] = [[0; 16]; 4];
    for i in 0..(encryptedCameraId_bytes.len() - 1) {
        // Encrypt Using The Key.
        encryptedCameraId_bytes[i] = aes_128_enc(cameraId_chunk[i], ecdh_key_bytes);
    }

    // Convert Formats.
    let mut encryptedCameraId: [u8; 64] = [0; 64];
    for i in 0..(encryptedCameraId_bytes.len() - 1) {
        for n in 0..15 {
            encryptedCameraId[((i * 8) + n)] = encryptedCameraId_bytes[i][n];
        }
    }

    encryptedCameraId
}

fn main(
    randomNonce: [u8; 31],
    ecdh_scalar: Field,
    cameraPubKeyX: pub [u8; 32],
    cameraPubKeyY: u8,
    cameraAttestationSignature: [u8; 64],
    keeperKey: [Field; 2],
    certAuthorityPubkeyX: pub [u8; 32],
    certAuthorityPubkeyY: pub [u8; 32],
    certAuthoritySignature: [u8; 64],
    imageHash: pub [u8; 32],
    assertedCameraIdentifier: pub [u8; 64]
) {
    // Represent Keeper Key as Point.
    let keeperKeyPoint = Point::new(keeperKey[0], keeperKey[1]);

    // Get Camera Identifier.
    let cameraIdentifier = gen_camera_id(
        randomNonce,
        cameraPubKeyY,
        cameraPubKeyX,
        ecdh_scalar,
        keeperKeyPoint
    );

    // Get the Camera Pubkey in its Compressed Form.
    let mut cameraPubKey_compressed: [u8; 32] = [0; 32];
    cameraPubKey_compressed[0] = cameraPubKeyY;
    for i in 0..31 {
        cameraPubKey_compressed[i+1] = cameraPubKeyX[i];
    }

    // Get the Hash of the Camera Pubkey.
    let camPubKeyHash = dep::std::hash::blake3(cameraPubKey_compressed);

    // Check Camera Attestation.
    let camera_is_certified: bool = ecdsa_verify(
        certAuthorityPubkeyX,
        certAuthorityPubkeyY,
        certAuthoritySignature,
        camPubKeyHash
    );

    // Get Camera Pubkey As Uncompressed Bytes.
    let mut cameraPubKeyFullY: [u8; 32] = [0; 32];
    // GET THE Y-COORD BASED ON POSITIVE OR NEGATIVE AS BYTES

    // Check Image Attestation.
    let image_is_attested: bool = ecdsa_verify(
        cameraPubKeyX,
        cameraPubKeyFullY,
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
    main(
        [
        0x14, 0xE5, 0x0E, 0xC3, 0x5D, 0xDE, 0xE0, 0xBD, 0x40, 0x13, 0x4D, 0xA8, 0x02, 0x32, 0x49, 0xC7, 0x15, 0x23, 0x19, 0x24, 0xCC, 0x3C, 0xFD, 0x3C, 0xDD, 0x95, 0x07, 0x15, 0xEB, 0xB9, 0xD5
    ],
        0xc842695f09580de84f50f0d096fd0ad87efd99411b4aec91441342,
        [
        0xAC, 0x63, 0x8F, 0x14, 0x18, 0x1F, 0x3A, 0xD3, 0x36, 0xA2, 0xC4, 0x97, 0x9E, 0xEF, 0x36, 0x38, 0x9C, 0x56, 0xF3, 0x10, 0x1F, 0x5B, 0xEA, 0x57, 0xF9, 0xF7, 0x9F, 0x8A, 0xB5, 0xE2, 0x77, 0x6D
    ],
        0x02,
        [
        0xCD, 0x72, 0x03, 0x3F, 0x5A, 0x5C, 0x7C, 0x74, 0xFC, 0xF1, 0x8C, 0xB7, 0x0F, 0x79, 0xAC, 0x8D, 0xC4, 0xFE, 0xD3, 0x0D, 0x70, 0xDD, 0x42, 0xBF, 0x27, 0x9E, 0x33, 0x15, 0xAF, 0xDC, 0x8B, 0x3E, 0x56, 0x09, 0xE9, 0x79, 0x92, 0xF5, 0xAC, 0x64, 0x6D, 0x7D, 0x37, 0xE4, 0x8A, 0xF5, 0xAF, 0x11, 0x94, 0x11, 0x15, 0xF9, 0x89, 0x72, 0x57, 0x1F, 0xBC, 0x53, 0x6B, 0xD9, 0x41, 0xE0, 0x3D, 0xD1
    ],
        [
        0x10204572b572d1a6eb4490eb2b8bb7e6b18b80699b92400c869b1dd647fba39b, 0x1a92a01a86086f6d57b35bf56e7202d4e1c98870f76244008765c43969a5ba7c
    ],
        [
        0x76, 0xB0, 0x00, 0xC3, 0x35, 0xC1, 0x65, 0x35, 0xB1, 0x6D, 0xAE, 0x53, 0xF9, 0x91, 0xB7, 0xEB, 0x52, 0x58, 0x09, 0xF8, 0x69, 0xCA, 0x35, 0x1E, 0xBA, 0x76, 0x06, 0xF6, 0xDC, 0x97, 0xDE, 0x91
    ],
        [
        0xA3, 0x8C, 0x57, 0xDB, 0xA6, 0x2C, 0x3C, 0x67, 0x32, 0xDA, 0x00, 0xFE, 0x33, 0x6F, 0x4B, 0x28, 0xC0, 0x79, 0x7A, 0x39, 0xB7, 0xCE, 0x73, 0x7A, 0x1A, 0xE6, 0xC6, 0x90, 0x60, 0xDF, 0xEE, 0xE4
    ],
        [
        0xE3, 0x45, 0x45, 0xBD, 0xFC, 0x98, 0x3C, 0xB4, 0xC7, 0xD8, 0x9F, 0x20, 0x9B, 0xB8, 0x6A, 0xC6, 0x8D, 0x75, 0x72, 0x71, 0x77, 0x2B, 0x2E, 0x55, 0x10, 0xC8, 0x22, 0x81, 0x8B, 0x94, 0x57, 0x1E, 0x4C, 0xED, 0xBD, 0xAF, 0x5B, 0x01, 0x35, 0x0B, 0x0F, 0xD1, 0xB6, 0xF4, 0x31, 0xA9, 0x9B, 0x95, 0xD2, 0xAF, 0xF7, 0x02, 0xDE, 0x77, 0xC1, 0x76, 0x11, 0x1B, 0x05, 0x3D, 0xD6, 0xC2, 0x5B, 0x0A
    ],
        [
        0xE3, 0xFB, 0xB0, 0xAD, 0x39, 0x90, 0xB6, 0x3C, 0xDB, 0xAB, 0xB4, 0x9B, 0x0A, 0xE6, 0xEB, 0x95, 0x97, 0x01, 0xCF, 0x0D, 0x8B, 0x36, 0x44, 0x8E, 0xF0, 0x28, 0x41, 0x5B, 0x67, 0x1B, 0xF1, 0x10
    ],
        [
        0xF9, 0x99, 0x6B, 0x8D, 0x53, 0x08, 0x45, 0x8A, 0x1B, 0x20, 0x0D, 0x20, 0x1D, 0x78, 0x01, 0x62, 0x44, 0xE4, 0x75, 0xD4, 0xAE, 0x06, 0x92, 0x3D, 0xDA, 0xE7, 0xCB, 0x14, 0xAD, 0x6F, 0xFA, 0x2A, 0x29, 0x16, 0x7D, 0x60, 0x99, 0x2A, 0xAE, 0x53, 0x94, 0xE5, 0x46, 0xC1, 0x32, 0x39, 0x96, 0xA3, 0x05, 0xCD, 0x19, 0x1B, 0xAB, 0x64, 0x4F, 0x36, 0x66, 0x8E, 0x97, 0x2B, 0x12, 0xC1, 0xCF, 0xD9
    ]
    )
}
