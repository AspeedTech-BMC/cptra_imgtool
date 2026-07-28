/*++

Licensed under the Apache-2.0 license.

Modified by ASPEED Technology Inc., 2026-04-16: Support generate anti-rollback signature
Modified by ASPEED Technology Inc., 2026-04-16: Make the auth manifest tool more flexible to support different signature combinations
Modified by ASPEED Technology Inc., 2026-04-16: Support sign helper config input
Modified by ASPEED Technology Inc., 2026-05-18: Rename the Rust dependency crate import for compatibility with two versions of the auth manifest
                                                generation tool, and remove unused dependencies: caliptra-drivers and caliptra-image-elf.
Modified by ASPEED Technology Inc., 2026-07-28: Select LMS authentication tree paths by matching the configured public key.

File Name:

   generator.rs

Abstract:

    Caliptra Authorization Manifest generator

--*/

use caliptra_image_gen_1x::ImageGeneratorCrypto;
use zerocopy::IntoBytes;

use crate::*;
use anyhow::Result;
use core::mem::size_of;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

/// Authorization Manifest generator
pub struct AuthManifestGenerator<Crypto: ImageGeneratorCrypto> {
    crypto: Crypto,
}

pub struct SignaturePair {
    pub ecdsa: Option<ImageEccSignature>,
    pub lms: Option<ImageLmsSignature>,
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

            let lms_sig = crate::lms_dual_mode::sign_lms_matching_public_key(
                &self.crypto,
                &digest,
                &priv_keys.lms_priv_key,
                &config.vendor_fw_key_info.pub_keys.lms_pub_key,
            )?;
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
                let lms_sig = crate::lms_dual_mode::sign_lms_matching_public_key(
                    &self.crypto,
                    &digest,
                    &owner_fw_priv_keys.lms_priv_key,
                    &owner_fw_config.pub_keys.lms_pub_key,
                )?;
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

                let lms_sig = crate::lms_dual_mode::sign_lms_matching_public_key(
                    &self.crypto,
                    &digest,
                    &vendor_man_priv_keys.lms_priv_key,
                    &config.vendor_man_key_info.pub_keys.lms_pub_key,
                )?;
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

                let lms_sig = crate::lms_dual_mode::sign_lms_matching_public_key(
                    &self.crypto,
                    &digest,
                    &owner_man_priv_keys.lms_priv_key,
                    &owner_man_config.pub_keys.lms_pub_key,
                )?;
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
            let lms_sig = crate::lms_dual_mode::sign_lms_matching_public_key(
                &self.crypto,
                &digest,
                &vendor_lms_config.fw_lms_key_pair.lms_priv_key,
                &vendor_lms_config.fw_lms_key_pair.lms_pub_key,
            )?;
            auth_manifest.preamble.vendor_pub_keys_signatures.lms_sig = lms_sig;
        }

        // Sign the owner manifest public keys.
        // check ecc sign helper
        let owner_ecc_fw_key_sign_helper_cmd = &config
            .sign_helper
            .owner_ecc_fw_key_sign_helper
            .clone()
            .unwrap_or_default();
        let owner_ecc_man_key_sign_helper_cmd = &config
            .sign_helper
            .owner_ecc_man_key_sign_helper
            .clone()
            .unwrap_or_default();
        // check lms sign helper
        let owner_lms_fw_key_sign_helper_cmd = &config
            .sign_helper
            .owner_lms_fw_key_sign_helper
            .clone()
            .unwrap_or_default();
        let owner_lms_man_key_sign_helper_cmd = &config
            .sign_helper
            .owner_lms_man_key_sign_helper
            .clone()
            .unwrap_or_default();

        // set owner pub keys
        if let Some(owner_ecc_config) = &config.owner_ecc_key_config {
            auth_manifest.preamble.owner_pub_keys.ecc_pub_key =
                owner_ecc_config.man_ecc_key_pair.ecc_pub_key;
        } else if !owner_ecc_fw_key_sign_helper_cmd.is_empty() {
            auth_manifest.preamble.owner_pub_keys.ecc_pub_key = config
                .owner_ecc_key_optional_config
                .man_ecc_pub_key
                .clone()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Owner Manifest ECC public key must be provided in the optional config when using signing helper"
                    )
                })?;
        }

        if let Some(owner_lms_config) = &config.owner_lms_key_config {
            auth_manifest.preamble.owner_pub_keys.lms_pub_key =
                owner_lms_config.man_lms_key_pair.lms_pub_key;
        } else if !owner_lms_fw_key_sign_helper_cmd.is_empty() {
            auth_manifest.preamble.owner_pub_keys.lms_pub_key = config
                .owner_lms_key_optional_config
                .man_lms_pub_key
                .clone()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Owner Manifest LMS public key must be provided in the optional config when using signing helper"
                    )
                })?;
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
        } else if !owner_ecc_fw_key_sign_helper_cmd.is_empty() {
            let sig_pair = Self::sign_with_helper(
                &digest,
                owner_ecc_fw_key_sign_helper_cmd,
                config.sign_helper.by_file,
                true,
            )?;
            let sig = sig_pair
                .ecdsa
                .ok_or_else(|| anyhow::anyhow!("Expected ECC signature, but got None"))?;

            auth_manifest.preamble.owner_pub_keys_signatures.ecc_sig = sig;
        }

        if let Some(owner_lms_config) = &config.owner_lms_key_config {
            let lms_sig = crate::lms_dual_mode::sign_lms_matching_public_key(
                &self.crypto,
                &digest,
                &owner_lms_config.fw_lms_key_pair.lms_priv_key,
                &owner_lms_config.fw_lms_key_pair.lms_pub_key,
            )?;
            auth_manifest.preamble.owner_pub_keys_signatures.lms_sig = lms_sig;
        } else if !owner_lms_fw_key_sign_helper_cmd.is_empty() {
            let sig_pair = Self::sign_with_helper(
                &digest,
                owner_lms_fw_key_sign_helper_cmd,
                config.sign_helper.by_file,
                false,
            )?;
            let sig = sig_pair
                .lms
                .ok_or_else(|| anyhow::anyhow!("Expected LMS signature, but got None"))?;

            auth_manifest.preamble.owner_pub_keys_signatures.lms_sig = sig;
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
                let lms_sig = crate::lms_dual_mode::sign_lms_matching_public_key(
                    &self.crypto,
                    &digest,
                    &vendor_lms_config.man_lms_key_pair.lms_priv_key,
                    &vendor_lms_config.man_lms_key_pair.lms_pub_key,
                )?;
                auth_manifest
                    .preamble
                    .vendor_image_metdata_signatures
                    .lms_sig = lms_sig;
            }
        }

        // Sign the IMC with the owner manifest public keys.
        let ecc_sig = if let Some(owner_ecc_config) = &config.owner_ecc_key_config {
            self.crypto.ecdsa384_sign(
                &digest,
                &owner_ecc_config.man_ecc_key_pair.ecc_priv_key,
                &owner_ecc_config.man_ecc_key_pair.ecc_pub_key,
            )?
        } else if let (Some(man_ecc_priv_key), Some(man_ecc_pub_key)) = (
            &config.owner_ecc_key_optional_config.man_ecc_priv_key,
            &config.owner_ecc_key_optional_config.man_ecc_pub_key,
        ) {
            self.crypto
                .ecdsa384_sign(&digest, man_ecc_priv_key, man_ecc_pub_key)?
        } else if !owner_ecc_man_key_sign_helper_cmd.is_empty() {
            let sig_pair = Self::sign_with_helper(
                &digest,
                owner_ecc_man_key_sign_helper_cmd,
                config.sign_helper.by_file,
                true,
            )?;
            sig_pair
                .ecdsa
                .ok_or_else(|| anyhow::anyhow!("Expected ECC signature, but got None"))?
        } else {
            ImageEccSignature::default()
        };

        auth_manifest
            .preamble
            .owner_image_metdata_signatures
            .ecc_sig = ecc_sig;

        let lms_sig = if let Some(owner_lms_config) = &config.owner_lms_key_config {
            crate::lms_dual_mode::sign_lms_matching_public_key(
                &self.crypto,
                &digest,
                &owner_lms_config.man_lms_key_pair.lms_priv_key,
                &owner_lms_config.man_lms_key_pair.lms_pub_key,
            )?
        } else if !owner_lms_man_key_sign_helper_cmd.is_empty() {
            let sig_pair = Self::sign_with_helper(
                &digest,
                owner_lms_man_key_sign_helper_cmd,
                config.sign_helper.by_file,
                false,
            )?;
            sig_pair
                .lms
                .ok_or_else(|| anyhow::anyhow!("Expected LMS signature, but got None"))?
        } else {
            ImageLmsSignature::default()
        };

        auth_manifest
            .preamble
            .owner_image_metdata_signatures
            .lms_sig = lms_sig;

        Ok(auth_manifest)
    }

    pub fn generate_sig_svn(
        &self,
        svn: u32,
        config: &AspeedAuthManifestGeneratorConfig,
    ) -> anyhow::Result<AuthManifestSignatures> {
        let mut sig: AuthManifestSignatures = AuthManifestSignatures::default();
        let mut aspeed_manifest = AspeedAuthorizationManifest::default();

        // check ecc sign helper
        let owner_ecc_fw_key_sign_helper_cmd = &config
            .sign_helper
            .owner_ecc_fw_key_sign_helper
            .clone()
            .unwrap_or_default();
        // check lms sign helper
        let owner_lms_fw_key_sign_helper_cmd = &config
            .sign_helper
            .owner_lms_fw_key_sign_helper
            .clone()
            .unwrap_or_default();

        aspeed_manifest.version = config.version;
        aspeed_manifest.sec_version = svn;
        aspeed_manifest.flags = config.flags.bits();

        if let Some(owner_ecc_config) = &config.owner_ecc_key_config {
            aspeed_manifest.owner_pub_keys.ecc_pub_key =
                owner_ecc_config.man_ecc_key_pair.ecc_pub_key;
        } else if !owner_ecc_fw_key_sign_helper_cmd.is_empty() {
            aspeed_manifest.owner_pub_keys.ecc_pub_key = config
                .owner_ecc_key_optional_config
                .man_ecc_pub_key
                .clone()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Owner Manifest ECC public key must be provided in the optional config when using signing helper"
                    )
                })?;
        }

        if let Some(owner_lms_config) = &config.owner_lms_key_config {
            aspeed_manifest.owner_pub_keys.lms_pub_key =
                owner_lms_config.man_lms_key_pair.lms_pub_key;
        } else if !owner_lms_fw_key_sign_helper_cmd.is_empty() {
            aspeed_manifest.owner_pub_keys.lms_pub_key = config
                .owner_lms_key_optional_config
                .man_lms_pub_key
                .clone()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Owner Manifest LMS public key must be provided in the optional config when using signing helper"
                    )
                })?;
        }

        let digest = self.crypto.sha384_digest(aspeed_manifest.as_bytes())?;

        if let Some(owner_ecc_config) = &config.owner_ecc_key_config {
            let ecc_sig = self.crypto.ecdsa384_sign(
                &digest,
                &owner_ecc_config.fw_ecc_key_pair.ecc_priv_key,
                &owner_ecc_config.fw_ecc_key_pair.ecc_pub_key,
            )?;
            sig.ecc_sig = ecc_sig;
        } else if !owner_ecc_fw_key_sign_helper_cmd.is_empty() {
            let sig_pair = Self::sign_with_helper(
                &digest,
                owner_ecc_fw_key_sign_helper_cmd,
                config.sign_helper.by_file,
                true,
            )?;
            let ecc_sig = sig_pair
                .ecdsa
                .ok_or_else(|| anyhow::anyhow!("Expected ECC signature, but got None"))?;
            sig.ecc_sig = ecc_sig;
        }

        if let Some(owner_lms_config) = &config.owner_lms_key_config {
            let lms_sig = crate::lms_dual_mode::sign_lms_matching_public_key(
                &self.crypto,
                &digest,
                &owner_lms_config.fw_lms_key_pair.lms_priv_key,
                &owner_lms_config.fw_lms_key_pair.lms_pub_key,
            )?;
            sig.lms_sig = lms_sig;
        } else if !owner_lms_fw_key_sign_helper_cmd.is_empty() {
            let sig_pair = Self::sign_with_helper(
                &digest,
                owner_lms_fw_key_sign_helper_cmd,
                config.sign_helper.by_file,
                false,
            )?;
            let lms_sig = sig_pair
                .lms
                .ok_or_else(|| anyhow::anyhow!("Expected LMS signature, but got None"))?;
            sig.lms_sig = lms_sig;
        }

        Ok(sig)
    }

    /// Performs an ECDSA-P384 signature operation using an external signing helper (e.g., a Python script).
    ///
    /// # Parameters
    /// - `digest`: The SHA-384 digest to sign, represented as `[u32; 12]` in big-endian order.
    /// - `helper_cmd`: The command string used to invoke the external signing helper.
    /// - `by_file`: If `true`, the digest and signature are exchanged via temporary files;  
    ///              if `false`, they are passed via STDIN/STDOUT.
    /// - `is_ecdsa384`: `true` for ECC (P-384), `false` for LMS.
    ///
    /// # Returns
    /// An [`ImageEccSignature`] containing the `r` and `s` components of the ECDSA signature.
    ///
    /// # Errors
    /// This function returns an error if:
    /// - The external helper process fails to launch or exits with a non-zero status.
    /// - The helper’s output cannot be parsed or decoded into a valid signature.
    pub fn sign_with_helper(
        digest: &ImageDigest,
        helper_cmd: &str,
        by_file: Option<bool>,
        is_ecdsa384: bool,
    ) -> Result<SignaturePair> {
        // Split helper command string into program and arguments
        let parts: Vec<&str> = helper_cmd.split_whitespace().collect();
        let helper = parts[0];
        let helper_args = &parts[1..];

        // Convert the digest (u32 array) into a 48-byte big-endian byte sequence
        let mut digest_bytes = Vec::with_capacity(48);
        for word in digest {
            digest_bytes.extend_from_slice(&word.to_be_bytes());
        }

        // =======================================================
        // Mode 1: File-based communication (by_file = true)
        // =======================================================
        if let Some(true) = by_file {
            // Write the digest to a temporary file
            let mut tmp_in = NamedTempFile::new()?;
            tmp_in.write_all(&digest_bytes)?;
            tmp_in.flush()?;
            let tmp_path = tmp_in.path().to_path_buf();

            // Launch the helper with the file path as argument
            let mut cmd = Command::new(helper);
            cmd.args(helper_args)
                .arg("--input")
                .arg(tmp_path.clone())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit()); // Show helper log output

            let status = cmd.status()?;
            if !status.success() {
                anyhow::bail!("Signing helper (file mode) failed");
            }

            // Read the signature result from the same file
            let mut sig_bytes = Vec::new();
            File::open(tmp_path)?.read_to_end(&mut sig_bytes)?;

            if is_ecdsa384 {
                let (r_bytes, s_bytes) = Self::parse_ecdsa_der(&sig_bytes)?;
                let r = Self::bytes_to_u32_array(&r_bytes)?;
                let s = Self::bytes_to_u32_array(&s_bytes)?;
                return Ok(SignaturePair {
                    ecdsa: Some(ImageEccSignature { r, s }),
                    lms: None,
                });
            } else {
                // LMS path: interpret as raw struct bytes
                if sig_bytes.len() != std::mem::size_of::<ImageLmsSignature>() {
                    anyhow::bail!(
                        "Invalid LMS signature length: expected {}, got {}",
                        std::mem::size_of::<ImageLmsSignature>(),
                        sig_bytes.len()
                    );
                }

                let sig = unsafe { *(sig_bytes.as_ptr() as *const ImageLmsSignature) };

                return Ok(SignaturePair {
                    ecdsa: None,
                    lms: Some(sig),
                });
            }
        }

        // =======================================================
        // Mode 2: STDIN/STDOUT communication (by_file = false)
        // =======================================================
        let mut cmd = Command::new(helper);
        cmd.args(helper_args);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().expect("Failed to start signing helper");

        // Write the digest (hex) to the helper's STDIN
        {
            let stdin = child.stdin.as_mut().expect("Failed to open stdin");
            writeln!(stdin, "{}", hex::encode(&digest_bytes))?;
        }

        // Wait for the helper to finish and capture its output
        let output = child.wait_with_output()?;
        if !output.status.success() {
            anyhow::bail!(
                "Signing helper failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        if is_ecdsa384 {
            // ECC case
            let signature_hex = String::from_utf8(output.stdout)?.trim().to_string();
            let signature_bytes = hex::decode(signature_hex)?;
            let (r_bytes, s_bytes) = Self::parse_ecdsa_der(&signature_bytes)?;
            let r = Self::bytes_to_u32_array(&r_bytes)?;
            let s = Self::bytes_to_u32_array(&s_bytes)?;
            Ok(SignaturePair {
                ecdsa: Some(ImageEccSignature { r, s }),
                lms: None,
            })
        } else {
            // LMS case: helper returns hex string of raw struct
            let sig_hex = String::from_utf8(output.stdout)?.trim().to_string();
            let sig_bytes = hex::decode(sig_hex)?;

            if sig_bytes.len() != std::mem::size_of::<ImageLmsSignature>() {
                anyhow::bail!(
                    "Invalid LMS signature length: expected {}, got {}",
                    std::mem::size_of::<ImageLmsSignature>(),
                    sig_bytes.len()
                );
            }

            let sig = unsafe { *(sig_bytes.as_ptr() as *const ImageLmsSignature) };

            Ok(SignaturePair {
                ecdsa: None,
                lms: Some(sig),
            })
        }
    }

    /// Converts a 48-byte big-endian byte slice into a `[u32; 12]` array.
    ///
    /// If the input is shorter than 48 bytes, it is left-padded with zeros.
    /// Each group of 4 bytes is interpreted as a big-endian `u32` word.
    ///
    /// # Errors
    /// Returns an error if the input is longer than 48 bytes.
    fn bytes_to_u32_array(bytes: &[u8]) -> Result<ImageScalar> {
        if bytes.len() > 48 {
            anyhow::bail!("Invalid scalar length > 48");
        }

        // Left-pad to 48 bytes if necessary
        let mut full = [0u8; 48];
        full[48 - bytes.len()..].copy_from_slice(bytes);

        // Convert each 4-byte chunk into a big-endian u32 word
        let mut arr = [0u32; ECC384_SCALAR_WORD_SIZE];
        for (i, chunk) in full.chunks(4).enumerate() {
            arr[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        Ok(arr)
    }

    /// Parse a DER-encoded ECDSA signature and return the (r, s) components.
    fn parse_ecdsa_der(sig: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        use simple_asn1::{from_der, ASN1Block};

        let asn1 = from_der(sig)?;
        if let Some(ASN1Block::Sequence(_, items)) = asn1.get(0) {
            if items.len() == 2 {
                if let (ASN1Block::Integer(_, r), ASN1Block::Integer(_, s)) = (&items[0], &items[1])
                {
                    let r_bytes = Self::int_to_bytes(r);
                    let s_bytes = Self::int_to_bytes(s);
                    return Ok((r_bytes, s_bytes));
                }
            }
        }
        anyhow::bail!("Invalid ECDSA DER format")
    }

    /// Convert an ASN.1 INTEGER value to a raw unsigned byte array.
    ///
    /// Removes any leading zero bytes that are only present to maintain
    /// positive integer representation in ASN.1 encoding.
    fn int_to_bytes(n: &num_bigint::BigInt) -> Vec<u8> {
        let mut bytes = n.to_bytes_be().1;
        // Remove unnecessary leading zero bytes
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        bytes
    }
}
