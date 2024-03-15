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

// Provides the Camera ID in the 64 byte encrypted form, using ECDH and AES-128.
fn gen_camera_id(
    randomNonce: u32, // This Is Used To Randomise The Cypertext
    cameraPubKeyY: u8, // Y-Coord of Public Key Of Camera Signer, Positive or Negative
    cameraPubKeyX: u32, // X-Coord of Public Key of Camera Signer
    ecdh_scalar: Field, // ECDH Scalar for Symmetric Key Encryption
    keeperKey: Point // Key of the Blacklist Keeper
) -> [u8; 64] {
    // Get Encrypted Camera ID 
    let cameraId: [u8; 64] = gen_unencrypted_camera_id(randomNonce, cameraPubKeyY, cameraPubKeyX);
    let mut cameraId_bytes: [[u8; 16]; 4] = [[0; 16]; 4];
    for i in 0..(cameraId_bytes.len() - 1) {
        for n in 0..15 {
            cameraId_bytes[i][n] = cameraId[((i*8) + n)];
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
        encryptedCameraId_bytes[i] = aes_128_enc(cameraId_bytes[i], ecdh_key_bytes);
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
    randomNonce: u32,
    ecdh_scalar: Field,
    cameraPubKeyY: u8,
    cameraPubKeyX: u32,
    cameraAttestationSignature: [u8; 64],
    keeperKey: pub Point,
    certAuthorityPubkeyX: pub [u8; 32],
    certAuthorityPubkeyY: pub [u8; 32],
    certAuthoritySignature: [u8; 64],
    imageHash: pub [u8; 32],
    assertedCameraIdentifier: pub [u8; 64]
) {
    // Get Camera Identifier.
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
    let camPubKeyHash = dep::std::hash::blake3(cameraPubKey_compressed);

    // Check Camera Attestation.
    let camera_is_certified: bool = ecdsa_verify(
        certAuthorityPubkeyX,
        certAuthorityPubkeyY,
        certAuthoritySignature,
        camPubKeyHash
    );

    // Get Camera Pubkey As Uncompressed Bytes.
    let mut cameraPubKeyX_bytes: [u8; 32] = [0; 32];
    let mut cameraPubKeyY_bytes: [u8; 32] = [0; 32];

    for i in 0..31 {
        cameraPubKeyX_bytes[i] = ((cameraPubKeyX >> (i * 8)) & 0xFF) as u8;
    }
    // GET THE Y-COORD BASED ON POSITIVE OR NEGATIVE AS BYTES

    // Check Image Attestation.
    let image_is_attested: bool = ecdsa_verify(
        cameraPubKeyX_bytes,
        cameraPubKeyY_bytes,
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
        0x14e50ec35ddee0bd40134da8023249c715231924cc3cfd3cdd950715ebb9d588,
        0x02,
        0xac638f14181f3ad336a2c4979eef36389c56f3101f5bea57f9f79f8ab5e2776d,
        0x6915a13c1d33d5d315eea68a82737305fea27d6f78cf0917f3130ba8c118fa0f40eefca31cce1335802a2ed223d0d2d651f78780885fd7284612dea3d761c4df1d8b8ab9c53998a20cfa14f1fd6a4269ee194eb85ae92146b4f6434666bd7f8ab62cf7e265ba3b57f84558ba0e81913009f1008b77b7233608d1f41e49bd2084da27c9e8f8367f4e5bf9682f07a64779cb5a090dc61006f7c49247032370c52de7692aa431b4ba862d2bc29dabc8795b6957f41ff3bcf4c5b5b8e67a7dd17a79824155ffe04b61b6c5bc864bd9ebcbc3bdfaf3d369bab324fb1dccab19105eedea4953cdf41eaaf915c241b3966b9b8788cbc748006a4b321666342589c2,
        Point::(
            "b57636fde92e6fce78bce928c39cca0d1683806097bda75d4d595b9531f36621",
            "9e2b9d17b39f05efb7d53ad34d91db03745253265647327df9a00896b67a0b61"
        ),
        0xa38c57dba62c3c6732da00fe336f4b28c0797a39b7ce737a1ae6c69060dfeee4,
        0xa38c57dba62c3c6732da00fe336f4b28c0797a39b7ce737a1ae6c69060dfeee4,
        "",
        0xcd72033f5a5c7c74fcf18cb70f79ac8dc4fed30d70dd42bf279e3315afdc8b3e5609e97992f5ac646d7d37e48af5af11941115f98972571fbc536bd941e03dd1,
        0xcd72033f5a5c7c74fcf18cb70f79ac8dc4fed30d70dd42bf279e3315afdc8b3e5609e97992f5ac646d7d37e48af5af11941115f98972571fbc536bd941e03dd1,
        ""
    );
    // Uncomment to make test fail
    // main(1, 1);
}
