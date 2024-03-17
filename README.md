# ZKPA - Zero Knowledge Provenance Authenticity

<div align="center">

This project is for 2024 ETH Golabal London Hackathon.

</div>

<table>
  <tr>
    <td>
      <img src="./src/assets/banner.png" width="400" height="200">
    </td>
  </tr>
  <tr>
    <td bgcolor="#3240CB">
      <img src="https://storage.googleapis.com/ethglobal-api-production/events%2Fgyosr%2Flogo%2F1699999130188_ethlondon-blue.svg" width="400" height="200">
    </td>
  </tr>
</table>

### Overview

ZKPA allows manufacturers to add a signature to cameras, enabling users and third parties to verify the origin and authenticity of photos. This system incorporates several core functions and technologies to ensure the integrity and authenticity of digital photos.

### Core Functions

#### 1. Camera Signature Creation by Manufacturers

Manufacturers add a signature to the camera to enable photo identification and tracking. This ensures that users and third parties can verify the camera's origin and the quality of the photos taken.

#### 2. User Photo Capture

The camera, being trusted, allows users to capture photos.

#### 3. Photo Hash Generation

Upon photo upload, the camera uses a hashing function to generate a unique hash value for the photo, ensuring its integrity and uniqueness.

#### 4. Signature Generation

The camera generates a signature for the photo, proving its genuineness.

#### 5. Zero-Knowledge Proof Generation

A Zero-Knowledge proof is generated to prove the photo's authenticity without revealing the actual signature. This ensures privacy and security in verifying photo authenticity.

#### 6. Verification and Storage

Users can store the Zero-Knowledge proof along with the photo hash on a blockchain, enabling secure and verifiable photo authenticity.

#### 7. Querying and Authenticity Verification

Other users can verify the authenticity of a photo by querying its hash. The application retrieves the corresponding Zero-Knowledge proof and photo hash, verifying the photo's authenticity without revealing its content.

### Technologies

- **Zero-Knowledge Proof (ZKP) Libraries**: Used for creating and verifying signatures without disclosing sensitive information.
- **Elliptic Curve Cryptography (ECC)**: Employed for securely generating and verifying Zero-Knowledge signatures.
- **Image Processing Libraries (IPL)**: Utilized for extracting data from photos, which is then used to generate ZK signatures.

### Implementation Example

Manufacturers like Sony leverage ECC to generate Zero-Knowledge signatures, ensuring the authenticity of photos captured with their cameras. The cameras use IPL to extract data from photos, which ECC then uses to create ZK signatures, providing proof of authenticity.
