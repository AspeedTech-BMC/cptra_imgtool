/*++

Licensed under the Apache-2.0 license.

Modified by ASPEED Technology Inc., 2026-04-16: Support generate anti-rollback signature
Modified by ASPEED Technology Inc., 2026-04-16: Make the auth manifest tool more flexible to support different signature combinations

File Name:

   generator.rs

Abstract:

    Caliptra Authorization Manifest generator

--*/

use caliptra_image_gen::ImageGeneratorCrypto;
use zerocopy::IntoBytes;

use crate::*;
use core::mem::size_of;

/// Authorization Manifest generator
pub struct AuthManifestGenerator<Crypto: ImageGeneratorCrypto> {
    crypto: Crypto,
}

impl<Crypto: ImageGeneratorCrypto> AuthManifestGenerator<Crypto> {
    /// Create an instance `AuthManifestGenerator`
    pub fn new(crypto: Crypto) -> Self {
        Self { crypto }
    }

    pub fn generate(
        &self,
        config: &AuthManifestGeneratorConfig,
    ) -> anyhow::Result<AuthorizationManifest> {
        let mut auth_manifest = AuthorizationManifest::default();

        if config.image_metadata_list.len() > AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT {
            eprintln!(
                "Unsupported image metadata count, only {} entries supported.",
                AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT
            );
            return Err(anyhow::anyhow!("Error converting image metadata list"));
        }

        // Generate the Image Metadata List.
        let slice = config.image_metadata_list.as_slice();
        auth_manifest.image_metadata_col.image_metadata_list[..slice.len()].copy_from_slice(slice);

        auth_manifest.image_metadata_col.entry_count = config.image_metadata_list.len() as u32;

        // Generate the preamble.
        auth_manifest.preamble.marker = AUTH_MANIFEST_MARKER;
        auth_manifest.preamble.size = size_of::<AuthManifestPreamble>() as u32;
        auth_manifest.preamble.version = config.version;
        auth_manifest.preamble.flags = config.flags.bits();

        // Sign the vendor manifest public keys.
        auth_manifest.preamble.vendor_pub_keys = config.vendor_man_key_info.pub_keys;

        let range = AuthManifestPreamble::vendor_signed_data_range();

        let data = auth_manifest
            .preamble
            .as_bytes()
            .get(range.start as usize..)
            .ok_or_else(|| anyhow::anyhow!("Failed to get vendor signed data range start"))?
            .get(..range.len())
            .ok_or(anyhow::anyhow!(
                "Failed to get vendor signed data range length"
            ))?;

        let digest = self.crypto.sha384_digest(data)?;

        if let Some(priv_keys) = config.vendor_fw_key_info.priv_keys {
            let sig = self.crypto.ecdsa384_sign(
                &digest,
                &priv_keys.ecc_priv_key,
                &config.vendor_fw_key_info.pub_keys.ecc_pub_key,
            )?;
            auth_manifest.preamble.vendor_pub_keys_signatures.ecc_sig = sig;

            let lms_sig = self.crypto.lms_sign(&digest, &priv_keys.lms_priv_key)?;
            auth_manifest.preamble.vendor_pub_keys_signatures.lms_sig = lms_sig;
        }

        // Sign the owner manifest public keys.
        if let (Some(owner_fw_config), Some(owner_man_config)) =
            (&config.owner_fw_key_info, &config.owner_man_key_info)
        {
            auth_manifest.preamble.owner_pub_keys = owner_man_config.pub_keys;

            let digest = self
                .crypto
                .sha384_digest(auth_manifest.preamble.owner_pub_keys.as_bytes())?;

            if let Some(owner_fw_priv_keys) = owner_fw_config.priv_keys {
                let sig = self.crypto.ecdsa384_sign(
                    &digest,
                    &owner_fw_priv_keys.ecc_priv_key,
                    &owner_fw_config.pub_keys.ecc_pub_key,
                )?;
                auth_manifest.preamble.owner_pub_keys_signatures.ecc_sig = sig;
                let lms_sig = self
                    .crypto
                    .lms_sign(&digest, &owner_fw_priv_keys.lms_priv_key)?;
                auth_manifest.preamble.owner_pub_keys_signatures.lms_sig = lms_sig;
            }
        }

        // Hash the IMC.
        let digest = self
            .crypto
            .sha384_digest(auth_manifest.image_metadata_col.as_bytes())?;

        // Sign the IMC with the vendor manifest public keys if indicated in the flags.
        if config
            .flags
            .contains(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED)
        {
            if let Some(vendor_man_priv_keys) = config.vendor_man_key_info.priv_keys {
                let sig = self.crypto.ecdsa384_sign(
                    &digest,
                    &vendor_man_priv_keys.ecc_priv_key,
                    &config.vendor_man_key_info.pub_keys.ecc_pub_key,
                )?;
                auth_manifest
                    .preamble
                    .vendor_image_metdata_signatures
                    .ecc_sig = sig;

                let lms_sig = self
                    .crypto
                    .lms_sign(&digest, &vendor_man_priv_keys.lms_priv_key)?;
                auth_manifest
                    .preamble
                    .vendor_image_metdata_signatures
                    .lms_sig = lms_sig;
            }
        }

        // Sign the IMC with the owner manifest public keys.
        if let Some(owner_man_config) = &config.owner_man_key_info {
            if let Some(owner_man_priv_keys) = &owner_man_config.priv_keys {
                let sig = self.crypto.ecdsa384_sign(
                    &digest,
                    &owner_man_priv_keys.ecc_priv_key,
                    &owner_man_config.pub_keys.ecc_pub_key,
                )?;
                auth_manifest
                    .preamble
                    .owner_image_metdata_signatures
                    .ecc_sig = sig;

                let lms_sig = self
                    .crypto
                    .lms_sign(&digest, &owner_man_priv_keys.lms_priv_key)?;
                auth_manifest
                    .preamble
                    .owner_image_metdata_signatures
                    .lms_sig = lms_sig;
            }
        }

        Ok(auth_manifest)
    }

    pub fn aspeed_generate(
        &self,
        config: &AspeedAuthManifestGeneratorConfig,
    ) -> anyhow::Result<AuthorizationManifest> {
        let mut auth_manifest = AuthorizationManifest::default();

        if config.image_metadata_list.len() > AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT {
            eprintln!(
                "Unsupported image metadata count, only {} entries supported.",
                AUTH_MANIFEST_IMAGE_METADATA_MAX_COUNT
            );
            return Err(anyhow::anyhow!("Error converting image metadata list"));
        }

        // Generate the Image Metadata List.
        let slice = config.image_metadata_list.as_slice();
        auth_manifest.image_metadata_col.image_metadata_list[..slice.len()].copy_from_slice(slice);

        auth_manifest.image_metadata_col.entry_count = config.image_metadata_list.len() as u32;

        // Generate the preamble.
        auth_manifest.preamble.marker = AUTH_MANIFEST_MARKER;
        auth_manifest.preamble.size = size_of::<AuthManifestPreamble>() as u32;
        auth_manifest.preamble.version = config.version;
        auth_manifest.preamble.flags = config.flags.bits();

        // Sign the vendor manifest public keys.
        if let Some(vendor_ecc_config) = &config.vendor_ecc_key_config {
            auth_manifest.preamble.vendor_pub_keys.ecc_pub_key =
                vendor_ecc_config.man_ecc_key_pair.ecc_pub_key;
        }
        if let Some(vendor_lms_config) = &config.vendor_lms_key_config {
            auth_manifest.preamble.vendor_pub_keys.lms_pub_key =
                vendor_lms_config.man_lms_key_pair.lms_pub_key;
        }

        let range = AuthManifestPreamble::vendor_signed_data_range();

        let data = auth_manifest
            .preamble
            .as_bytes()
            .get(range.start as usize..)
            .ok_or_else(|| anyhow::anyhow!("Failed to get vendor signed data range start"))?
            .get(..range.len())
            .ok_or(anyhow::anyhow!(
                "Failed to get vendor signed data range length"
            ))?;

        let digest = self.crypto.sha384_digest(data)?;

        if let Some(vendor_ecc_config) = &config.vendor_ecc_key_config {
            let sig = self.crypto.ecdsa384_sign(
                &digest,
                &vendor_ecc_config.fw_ecc_key_pair.ecc_priv_key,
                &vendor_ecc_config.fw_ecc_key_pair.ecc_pub_key,
            )?;
            auth_manifest.preamble.vendor_pub_keys_signatures.ecc_sig = sig;
        }

        if let Some(vendor_lms_config) = &config.vendor_lms_key_config {
            let lms_sig = self
                .crypto
                .lms_sign(&digest, &vendor_lms_config.fw_lms_key_pair.lms_priv_key)?;
            auth_manifest.preamble.vendor_pub_keys_signatures.lms_sig = lms_sig;
        }

        // Sign the owner manifest public keys.
        if let Some(owner_ecc_config) = &config.owner_ecc_key_config {
            auth_manifest.preamble.owner_pub_keys.ecc_pub_key =
                owner_ecc_config.man_ecc_key_pair.ecc_pub_key;
        }
        if let Some(owner_lms_config) = &config.owner_lms_key_config {
            auth_manifest.preamble.owner_pub_keys.lms_pub_key =
                owner_lms_config.man_lms_key_pair.lms_pub_key;
        }

        let digest = self
            .crypto
            .sha384_digest(auth_manifest.preamble.owner_pub_keys.as_bytes())?;

        if let Some(owner_ecc_config) = &config.owner_ecc_key_config {
            let sig = self.crypto.ecdsa384_sign(
                &digest,
                &owner_ecc_config.fw_ecc_key_pair.ecc_priv_key,
                &owner_ecc_config.fw_ecc_key_pair.ecc_pub_key,
            )?;
            auth_manifest.preamble.owner_pub_keys_signatures.ecc_sig = sig;
        }

        if let Some(owner_lms_config) = &config.owner_lms_key_config {
            let lms_sig = self
                .crypto
                .lms_sign(&digest, &owner_lms_config.fw_lms_key_pair.lms_priv_key)?;
            auth_manifest.preamble.owner_pub_keys_signatures.lms_sig = lms_sig;
        }

        // Hash the IMC.
        let digest = self
            .crypto
            .sha384_digest(auth_manifest.image_metadata_col.as_bytes())?;

        // Sign the IMC with the vendor manifest public keys if indicated in the flags.
        if config
            .flags
            .contains(AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED)
        {
            if let Some(vendor_ecc_config) = &config.vendor_ecc_key_config {
                let sig = self.crypto.ecdsa384_sign(
                    &digest,
                    &vendor_ecc_config.man_ecc_key_pair.ecc_priv_key,
                    &vendor_ecc_config.man_ecc_key_pair.ecc_pub_key,
                )?;
                auth_manifest
                    .preamble
                    .vendor_image_metdata_signatures
                    .ecc_sig = sig;
            }

            if let Some(vendor_lms_config) = &config.vendor_lms_key_config {
                let lms_sig = self
                    .crypto
                    .lms_sign(&digest, &vendor_lms_config.man_lms_key_pair.lms_priv_key)?;
                auth_manifest
                    .preamble
                    .vendor_image_metdata_signatures
                    .lms_sig = lms_sig;
            }
        }

        // Sign the IMC with the owner manifest public keys.
        if let Some(owner_ecc_config) = &config.owner_ecc_key_config {
            let sig = self.crypto.ecdsa384_sign(
                &digest,
                &owner_ecc_config.man_ecc_key_pair.ecc_priv_key,
                &owner_ecc_config.man_ecc_key_pair.ecc_pub_key,
            )?;
            auth_manifest
                .preamble
                .owner_image_metdata_signatures
                .ecc_sig = sig;
        }

        if let Some(owner_lms_config) = &config.owner_lms_key_config {
            let lms_sig = self
                .crypto
                .lms_sign(&digest, &owner_lms_config.man_lms_key_pair.lms_priv_key)?;
            auth_manifest
                .preamble
                .owner_image_metdata_signatures
                .lms_sig = lms_sig;
        }

        Ok(auth_manifest)
    }

    pub fn generate_sig_svn(
        &self,
        svn: u32,
        config: &AspeedAuthManifestGeneratorConfig,
    ) -> anyhow::Result<AuthManifestSignatures> {
        let mut sig: AuthManifestSignatures = AuthManifestSignatures::default();
        let mut aspeed_manifest = AspeedAuthorizationManifest::default();

        aspeed_manifest.version = config.version;
        aspeed_manifest.sec_version = svn;
        aspeed_manifest.flags = config.flags.bits();

        if let Some(owner_ecc_config) = &config.owner_ecc_key_config {
            aspeed_manifest.owner_pub_keys.ecc_pub_key =
                owner_ecc_config.man_ecc_key_pair.ecc_pub_key;
        }

        if let Some(owner_lms_config) = &config.owner_lms_key_config {
            aspeed_manifest.owner_pub_keys.lms_pub_key =
                owner_lms_config.man_lms_key_pair.lms_pub_key;
        }

        let digest = self.crypto.sha384_digest(aspeed_manifest.as_bytes())?;

        if let Some(owner_ecc_config) = &config.owner_ecc_key_config {
            let ecc_sig = self.crypto.ecdsa384_sign(
                &digest,
                &owner_ecc_config.fw_ecc_key_pair.ecc_priv_key,
                &owner_ecc_config.fw_ecc_key_pair.ecc_pub_key,
            )?;
            sig.ecc_sig = ecc_sig;
        }

        if let Some(owner_lms_config) = &config.owner_lms_key_config {
            let lms_sig = self
                .crypto
                .lms_sign(&digest, &owner_lms_config.fw_lms_key_pair.lms_priv_key)?;
            sig.lms_sig = lms_sig;
        }

        Ok(sig)
    }
}
