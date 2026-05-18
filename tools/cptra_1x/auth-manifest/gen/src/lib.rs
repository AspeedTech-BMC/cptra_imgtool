/*++

Licensed under the Apache-2.0 license.

Modified by ASPEED Technology Inc., 2026-04-16: Make the auth manifest tool more flexible to support different signature combinations
Modified by ASPEED Technology Inc., 2026-04-16: Support sign helper config input
Modified by ASPEED Technology Inc., 2026-05-18: Rename the Rust dependency crate import for compatibility with two versions of the auth manifest
                                                generation tool, and remove unused dependencies: caliptra-drivers and caliptra-image-elf.

File Name:

   generator.rs

Abstract:

    Caliptra Image generator

--*/
mod generator;

use caliptra_auth_man_types_1x::*;
use caliptra_image_types_1x::*;
pub use generator::AuthManifestGenerator;
use serde_derive::{Deserialize, Serialize};

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
pub struct AuthManifestGeneratorEccKeyOptionalConfig {
    pub man_ecc_pub_key: Option<ImageEccPubKey>,
    pub man_ecc_priv_key: Option<ImageEccPrivKey>,
}

#[derive(Default, Clone)]
pub struct AuthManifestGeneratorLmsKeyConfig {
    pub fw_lms_key_pair: AuthManifestLmsKeyPair,
    pub man_lms_key_pair: AuthManifestLmsKeyPair,
}

#[derive(Default, Clone)]
pub struct AuthManifestGeneratorLmsKeyOptionalConfig {
    pub man_lms_pub_key: Option<ImageLmsPublicKey>,
    pub man_lms_priv_key: Option<ImageLmsPrivKey>,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct AspeedAuthManifestSignHelper {
    pub owner_ecc_fw_key_sign_helper: Option<String>,
    pub owner_ecc_man_key_sign_helper: Option<String>,
    pub owner_lms_fw_key_sign_helper: Option<String>,
    pub owner_lms_man_key_sign_helper: Option<String>,
    pub by_file: Option<bool>,
}

#[derive(Default, Clone)]
pub struct AspeedAuthManifestGeneratorConfig {
    pub version: u32,
    pub flags: AuthManifestFlags,
    pub vendor_ecc_key_config: Option<AuthManifestGeneratorEccKeyConfig>,
    pub vendor_lms_key_config: Option<AuthManifestGeneratorLmsKeyConfig>,
    pub owner_ecc_key_config: Option<AuthManifestGeneratorEccKeyConfig>,
    pub owner_lms_key_config: Option<AuthManifestGeneratorLmsKeyConfig>,
    pub owner_ecc_key_optional_config: AuthManifestGeneratorEccKeyOptionalConfig,
    pub owner_lms_key_optional_config: AuthManifestGeneratorLmsKeyOptionalConfig,
    pub image_metadata_list: Vec<AuthManifestImageMetadata>,
    pub sign_helper: AspeedAuthManifestSignHelper,
}
