use dep::std::ecdsa_secp256k1::verify_signature as ecdsa_verify;
use dep::aes::aes_128_enc as aes_128_enc;
use dep::std::ec::tecurve::affine::{Curve, Point};
use dep::std::ec::tecurve::affine::Point as G;

fn bjj_pub_key(priv_key: Field) -> Point {
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

fn bjj_scalar_mul(scalar: Field, base_pt: Point) -> Point {
    let bjj = Curve::new(
        168700,
        168696,
        G::new(
            995203441582195749578291179787384436505546430278305826713579947235728471134,
            5472060717959818805561601436314318772137091100104008585924551046643952123905
        )
    );

    bjj.mul(scalar, base_pt)
}

fn bjj_ecdh(scalar: Field, base_pt: Point) -> [u8; 16] {
    let point: Point = bjj_scalar_mul(scalar, base_pt);
    let x_array = point.x.to_be_bytes(32);
    let mut x_16: [u8; 16] = [0; 16];
    for i in 0..16 {
        x_16[i] = x_array[i];
    }

    x_16
}

fn construct_point(x: Field, y: Field) -> Point {
    Point::new(x, y)
}

fn gen_unencrypted_camera_id(
    randomNonce: [u8; 31], // This Is Used To Randomise The Cypertext
    cameraPubKeyY: u8, // Y-Coord of Public Key Of Camera Signer, Positive or Negative
    cameraPubKeyX: [u8; 32] // X-Coord of Public Key of Camera Signer
) -> [u8; 64] {
    let mut cameraId: [u8; 64] = [0; 64];

    // Append The Nonce To cameraId
    for i in 0..31 {
        cameraId[i] = randomNonce[i];
    }

    // Append The Camera Pubkey Y To cameraId.
    cameraId[31] = cameraPubKeyY;

    // Append The Camera Pubkey X to cameraID.
    for i in 0..32 {
        cameraId[i+32] = cameraPubKeyX[i];
    }

    cameraId
}

// Provides the Camera ID in the 64 byte encrypted form, using ECDH and AES-128.
fn gen_camera_id(
    randomNonce: [u8; 31], // This Is Used To Randomise The Cypertext
    cameraPubKeySignY: u8, // Sign of Y-Coord of Public Key Of Camera Signer, Positive or Negative
    cameraPubKeyX: [u8; 32], // X-Coord of Public Key of Camera Signer
    ecdhScalar: Field, // ECDH Scalar for Symmetric Key Encryption
    consortiumPubKey: Point // Key of the Blacklist Keeper
) -> [u8; 64] {
    // Get Camera ID as Chunks.
    let cameraId: [u8; 64] = gen_unencrypted_camera_id(randomNonce, cameraPubKeySignY, cameraPubKeyX);
    let mut cameraId_chunk: [[u8; 16]; 4] = [[0; 16]; 4];
    for i in 0..cameraId_chunk.len() {
        for n in 0..16 {
            cameraId_chunk[i][n] = cameraId[((i * 16) + n)];
        }
    }

    // Calculate ECDH Shared Key, Use First 16 Bytes Of X-Coord As Key.
    let ecdh_key = bjj_ecdh(ecdhScalar, consortiumPubKey);

    // Encrypt Camera ID to Keeper.
    let mut encryptedCameraId_bytes: [[u8; 16]; 4] = [[0; 16]; 4];
    for i in 0..encryptedCameraId_bytes.len() {
        // Encrypt Using The Key.
        encryptedCameraId_bytes[i] = aes_128_enc(cameraId_chunk[i], ecdh_key);
    }

    // Convert Formats.
    let mut encryptedCameraId: [u8; 64] = [0; 64];
    for i in 0..encryptedCameraId_bytes.len() {
        for n in 0..16 {
            encryptedCameraId[((i * 16) + n)] = encryptedCameraId_bytes[i][n];
        }
    }

    encryptedCameraId
}

fn get_compressed_y(bytes: [u8; 32]) -> u8 {
    // Get Least Significant Bit To Determine Oddness.
    let is_neg = bytes[0] & 1;

    // Set 0x02 if Even, 0x03 if Odd.
    if (is_neg as bool) == false {
        0x02
    } else {
        0x03
    }
}

fn main(
    randomNonce: [u8; 31],
    ecdhScalar: Field,
    cameraPubKeyX: [u8; 32],
    cameraPubKeyFullY: [u8; 32],
    cameraAttestationSignature: [u8; 64],
    consortiumPubKey: pub [Field; 2],
    assertedDecryptPk: pub [Field; 2],
    certAuthorityPubkeyX: pub [u8; 32],
    certAuthorityPubkeyY: pub [u8; 32],
    certAuthoritySignature: [u8; 64],
    imageHash: pub [u8; 32],
    assertedCameraIdentifier: pub [u8; 64]
) {
    // Check Whether The Pubkey Is Positive or Negative.
    let mut cameraPubKeySignY: u8 = get_compressed_y(cameraPubKeyFullY);

    // Represent Keeper Key as Point.
    let consortiumPubKey_Point = construct_point(consortiumPubKey[0], consortiumPubKey[1]);

    // Calculate ECDH Counterpart So Consortium Can Decrypt The CameraID.
    let decryptPk_Point = bjj_pub_key(ecdhScalar);
    let decryptPk: [Field; 2] = [decryptPk_Point.x, decryptPk_Point.y];

    // Get Camera Identifier.
    let cameraIdentifier = gen_camera_id(
        randomNonce,
        cameraPubKeySignY,
        cameraPubKeyX,
        ecdhScalar,
        consortiumPubKey_Point
    );

    // Get the Camera Pubkey in its Compressed Form.
    let mut cameraPubKey_compressed: [u8; 33] = [0; 33];
    cameraPubKey_compressed[0] = cameraPubKeySignY;
    for i in 0..32 {
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
    assert(decryptPk == assertedDecryptPk);
}

#[test]
fn test_camera_id_generation() {
    let camera_id = gen_unencrypted_camera_id(
        [
        0x14, 0xE5, 0x0E, 0xC3, 0x5D, 0xDE, 0xE0, 0xBD, 0x40, 0x13, 0x4D, 0xA8, 0x02, 0x32, 0x49, 0xC7, 0x15, 0x23, 0x19, 0x24, 0xCC, 0x3C, 0xFD, 0x3C, 0xDD, 0x95, 0x07, 0x15, 0xEB, 0xB9, 0xD5
    ],
        0x02,
        [
        0xAC, 0x63, 0x8F, 0x14, 0x18, 0x1F, 0x3A, 0xD3, 0x36, 0xA2, 0xC4, 0x97, 0x9E, 0xEF, 0x36, 0x38, 0x9C, 0x56, 0xF3, 0x10, 0x1F, 0x5B, 0xEA, 0x57, 0xF9, 0xF7, 0x9F, 0x8A, 0xB5, 0xE2, 0x77, 0x6D
    ]
    );
    println(camera_id);

    let mut cameraId_chunk: [[u8; 16]; 4] = [[0; 16]; 4];
    for i in 0..4 {
        for n in 0..16 {
            cameraId_chunk[i][n] = camera_id[((i * 16) + n)];
        }
    }
    println(cameraId_chunk)
}

#[test]
fn test_key_agreement() {
    let ecdhScalar: Field = 0x12341234;
    let consortiumPubKey = bjj_pub_key(0x10203040506);
    let mut ecdh_key = bjj_ecdh(ecdhScalar, consortiumPubKey);
    println("Agreed Key On Prover Side:");
    println(ecdh_key);

    let decryptPk = bjj_pub_key(ecdhScalar);
    ecdh_key = bjj_ecdh(0x10203040506, decryptPk);
    println("Agreed Key On Verifier Side:");
    println(ecdh_key);
}

#[test]
fn test_camera_id_encryption() {
    let randomNonce: [u8; 31] = [0xaa; 31];
    let ecdhScalar: Field = 0x12341234;
    let cameraPubKeySignY: u8 = 0x02;
    let cameraPubKeyX: [u8; 32] = [0xFF; 32];
    let consortiumPubKey = bjj_pub_key(0x10203040506);

    let encryptedCameraId = gen_camera_id(
        randomNonce,
        cameraPubKeySignY,
        cameraPubKeyX,
        ecdhScalar,
        consortiumPubKey
    );

    // Calculate The Decryption Key.
    let mut encryptionKey = bjj_ecdh(ecdhScalar, consortiumPubKey);

    println("Check if you can decrypt the following with AES-128 ECB,");
    println(encryptedCameraId);
    println("Here's your decryption key:");
    println(encryptionKey);
}

#[test]
fn test_ec_verification() {
    let certAuthorityPubkeyX = [
        0xA3, 0x8C, 0x57, 0xDB, 0xA6, 0x2C, 0x3C, 0x67, 0x32, 0xDA, 0x00, 0xFE, 0x33, 0x6F, 0x4B, 0x28, 0xC0, 0x79, 0x7A, 0x39, 0xB7, 0xCE, 0x73, 0x7A, 0x1A, 0xE6, 0xC6, 0x90, 0x60, 0xDF, 0xEE, 0xE4
    ];
    let certAuthorityPubkeyY = [
        0x76, 0xB0, 0x00, 0xC3, 0x35, 0xC1, 0x65, 0x35, 0xB1, 0x6D, 0xAE, 0x53, 0xF9, 0x91, 0xB7, 0xEB, 0x52, 0x58, 0x09, 0xF8, 0x69, 0xCA, 0x35, 0x1E, 0xBA, 0x76, 0x06, 0xF6, 0xDC, 0x97, 0xDE, 0x91
    ];
    let certAuthoritySignature = [
        0xE3, 0x45, 0x45, 0xBD, 0xFC, 0x98, 0x3C, 0xB4, 0xC7, 0xD8, 0x9F, 0x20, 0x9B, 0xB8, 0x6A, 0xC6, 0x8D, 0x75, 0x72, 0x71, 0x77, 0x2B, 0x2E, 0x55, 0x10, 0xC8, 0x22, 0x81, 0x8B, 0x94, 0x57, 0x1E, 0x4C, 0xED, 0xBD, 0xAF, 0x5B, 0x01, 0x35, 0x0B, 0x0F, 0xD1, 0xB6, 0xF4, 0x31, 0xA9, 0x9B, 0x95, 0xD2, 0xAF, 0xF7, 0x02, 0xDE, 0x77, 0xC1, 0x76, 0x11, 0x1B, 0x05, 0x3D, 0xD6, 0xC2, 0x5B, 0x0A
    ];

    let cameraPubKeyX = [
        0xAC, 0x63, 0x8F, 0x14, 0x18, 0x1F, 0x3A, 0xD3, 0x36, 0xA2, 0xC4, 0x97, 0x9E, 0xEF, 0x36, 0x38, 0x9C, 0x56, 0xF3, 0x10, 0x1F, 0x5B, 0xEA, 0x57, 0xF9, 0xF7, 0x9F, 0x8A, 0xB5, 0xE2, 0x77, 0x6D
    ];
    let cameraPubKeyY = 0x02;

    let mut cameraPubKey_compressed: [u8; 33] = [0; 33];
    cameraPubKey_compressed[0] = cameraPubKeyY;
    for i in 0..32 {
        cameraPubKey_compressed[i+1] = cameraPubKeyX[i];
    }

    println("Compressed PubKey:");
    println(cameraPubKey_compressed);

    // Get the Hash of the Camera Pubkey.
    let camPubKeyHash = dep::std::hash::blake3(cameraPubKey_compressed);

    println("Hash of Compressed PubKey:");
    println(camPubKeyHash);

    let camera_is_certified: bool = ecdsa_verify(
        certAuthorityPubkeyX,
        certAuthorityPubkeyY,
        certAuthoritySignature,
        camPubKeyHash
    );

    if camera_is_certified == true {
        println("Verification Works.")
    } else {
        println("Verification Doesn't Work.")
    }
}
