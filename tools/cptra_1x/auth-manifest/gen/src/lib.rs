/*++

Licensed under the Apache-2.0 license.

Modified by ASPEED Technology Inc., 2026-04-16: Make the auth manifest tool more flexible to support different signature combinations

File Name:

   generator.rs

Abstract:

    Caliptra Image generator

--*/
mod generator;

pub use generator::AuthManifestGenerator;

use caliptra_auth_man_types::*;
use caliptra_image_types::*;

/// Image Generator Vendor Configuration
#[derive(Default, Clone)]
pub struct AuthManifestGeneratorKeyConfig {
    pub pub_keys: AuthManifestPubKeys,

    pub priv_keys: Option<AuthManifestPrivKeys>,
}

/// Authorization Manifest Generator Configuration
#[derive(Default, Clone)]
pub struct AuthManifestGeneratorConfig {
    pub version: u32,

    pub flags: AuthManifestFlags,

    pub vendor_fw_key_info: AuthManifestGeneratorKeyConfig,

    pub vendor_man_key_info: AuthManifestGeneratorKeyConfig,

    pub owner_fw_key_info: Option<AuthManifestGeneratorKeyConfig>,

    pub owner_man_key_info: Option<AuthManifestGeneratorKeyConfig>,

    pub image_metadata_list: Vec<AuthManifestImageMetadata>,
}

#[derive(Default, Clone)]
pub struct AuthManifestECCKeyPair {
    pub ecc_pub_key: ImageEccPubKey,
    pub ecc_priv_key: ImageEccPrivKey,
}

#[derive(Default, Clone)]
pub struct AuthManifestLmsKeyPair {
    pub lms_pub_key: ImageLmsPublicKey,
    pub lms_priv_key: ImageLmsPrivKey,
}

#[derive(Default, Clone)]
pub struct AuthManifestGeneratorEccKeyConfig {
    pub fw_ecc_key_pair: AuthManifestECCKeyPair,
    pub man_ecc_key_pair: AuthManifestECCKeyPair,
}

#[derive(Default, Clone)]
pub struct AuthManifestGeneratorLmsKeyConfig {
    pub fw_lms_key_pair: AuthManifestLmsKeyPair,
    pub man_lms_key_pair: AuthManifestLmsKeyPair,
}

#[derive(Default, Clone)]
pub struct AspeedAuthManifestGeneratorConfig {
    pub version: u32,
    pub flags: AuthManifestFlags,
    pub vendor_ecc_key_config: Option<AuthManifestGeneratorEccKeyConfig>,
    pub vendor_lms_key_config: Option<AuthManifestGeneratorLmsKeyConfig>,
    pub owner_ecc_key_config: Option<AuthManifestGeneratorEccKeyConfig>,
    pub owner_lms_key_config: Option<AuthManifestGeneratorLmsKeyConfig>,
    pub image_metadata_list: Vec<AuthManifestImageMetadata>,
}
