use crate::error::Error;
use crate::ltv::{append_dss_dictionary, build_adbe_revocation_attribute};
use crate::signature_options::SignatureOptions;
use crate::{ByteRange, PDFSigningDocument, UserSignatureInfo};
use bcder::Mode::Der;
use bcder::{encode::Values, Captured, OctetString};
use cryptographic_message_syntax::{Bytes, Oid, SignedDataBuilder};
use lopdf::ObjectId;
use sha2::{Digest, Sha256};
use std::io::Write;
use x509_certificate::rfc5652::AttributeValue;

impl PDFSigningDocument {
    fn compute_cert_hash(cert: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&cert);
        hasher.finalize().to_vec()
    }

    fn build_signing_certificate_v2_attribute_value(cert_hash: Vec<u8>) -> Captured {
        let certificate_hash_octet_string = OctetString::new(Bytes::from(cert_hash));

        let ess_cert_id_v2 = bcder::encode::sequence(certificate_hash_octet_string.encode());

        let signing_certificate_v2 = bcder::encode::sequence(ess_cert_id_v2);

        let signing_certificate_attr_value = bcder::encode::sequence(signing_certificate_v2);

        signing_certificate_attr_value.to_captured(Der)
    }

    /// Digitally signs the document using a cryptographically secure algorithm.
    /// Note that using this function will prevent you from changing anything else about the document.
    /// Changing the document in any other way will invalidate the cryptographic check.
    pub(crate) fn digitally_sign_document(
        &self,
        user_info: &UserSignatureInfo,
        signature_options: &SignatureOptions,
    ) -> Result<Vec<u8>, Error> {
        // TODO: Code should be enabled in the future, do not remove.
        // Decompose `pdf_document` into it parts.
        // let acro_forms = self.acro_form.clone();
        // Add data to file before signing
        // Get first signature
        // let first_signature_id = if let Some(Some(first_signature)) =
        //     acro_forms.as_ref().map(|forms| forms.first().cloned())
        // {
        //     first_signature.get_object_id()
        // } else {
        //     None
        // };
        // // first_signature_id
        // if let Some(first_signature_id) = first_signature_id {
        //     pdf_signing_document.add_digital_signature_data(first_signature_id)?;
        // } else {
        //     return Err(InternalError::new(
        //         "Could not find first signature in PDF, can not sign document.",
        //         ApiErrorKind::ServerError,
        //         InternalErrorCodes::Default,
        //     ));
        // }

        // Convert pdf document to binary data.
        let mut pdf_file_data: Vec<u8> = Vec::new();
        self.write_document(&mut pdf_file_data)?;

        let (byte_range, pdf_file_data) =
            Self::set_next_byte_range(pdf_file_data, signature_options);

        let first_part = &pdf_file_data[byte_range.get_range(0)];
        let second_part = &pdf_file_data[byte_range.get_range(1)];

        // Used for debugging
        // log::trace!(
        //     "End of first part: {}",
        //     String::from_utf8_lossy(&first_part[(byte_range.0[1] - 15)..])
        // );
        // log::trace!(
        //     "Start of second part: {}...{}",
        //     String::from_utf8_lossy(&second_part[0..10]),
        //     String::from_utf8_lossy(&second_part[(second_part.len() - 5)..])
        // );

        let user_certificate_chain = user_info.user_certificate_chain.clone();
        let user_certificate = user_certificate_chain[0].clone();
        // 1.2.840.113549.1.9.16.2.47
        let signing_certificate_v2_oid = Oid(Bytes::copy_from_slice(&[
            42, 134, 72, 134, 247, 13, 1, 9, 16, 2, 47,
        ]));
        let cert_hash = Self::compute_cert_hash(user_certificate.encode_der().unwrap());
        let signing_certificate_v2_value =
            Self::build_signing_certificate_v2_attribute_value(cert_hash);

        // Add signing_certificate_v2 attribute to the signer
        let mut signer = user_info.user_signing_keys.clone();
        signer = signer.signed_attribute(
            signing_certificate_v2_oid,
            vec![AttributeValue::new(signing_certificate_v2_value)],
        );

        // Add adbe-revocationInfoArchival signed attribute
        let adbe_revocation_data = build_adbe_revocation_attribute(
            &user_certificate_chain,
            signature_options.signed_attribute_include_crl,
            signature_options.signed_attribute_include_ocsp,
        );
        if let Some((oid, values)) = adbe_revocation_data {
            signer = signer.signed_attribute(oid, values);
        }

        // Timestamp
        if let Some(tsa_url) = &signature_options.timestamp_url {
            signer = signer.time_stamp_url(tsa_url).unwrap()
        }

        // create new vec without the content part
        let mut vec = Vec::with_capacity(byte_range.get_capacity_inclusive());
        vec.extend_from_slice(first_part);
        vec.extend_from_slice(second_part);

        // Calculate file hash and sign it using the users key
        let mut builder = SignedDataBuilder::default()
            .content_external(vec)
            .content_type(Oid(Bytes::copy_from_slice(
                cryptographic_message_syntax::asn1::rfc5652::OID_ID_DATA.as_ref(),
            )))
            .signer(signer.clone());
        for i in 0..user_certificate_chain.len() {
            builder = builder.certificate(user_certificate_chain[i].clone());
        }

        let signature = builder.build_der().unwrap();

        #[cfg(feature = "debug")]
        {
            let mut file = std::fs::File::create("./signature.der").unwrap();
            file.write_all(&signature).unwrap();
        }

        // Write signature to file
        let mut pdf_file_data = Self::set_content(pdf_file_data, signature, signature_options);

        if signature_options.include_dss {
            pdf_file_data = append_dss_dictionary(pdf_file_data, user_certificate_chain)?;
        }

        Ok(pdf_file_data)
    }

    // TODO: Not used, see start of `digitally_sign_document()`
    #[allow(dead_code)]
    pub(crate) fn add_digital_signature_data(
        &mut self,
        first_signature_id: ObjectId,
    ) -> Result<(), Error> {
        use lopdf::Object::*;
        // Get root ID
        let root_obj_id = self
            .raw_document
            .get_prev_documents()
            .trailer
            .get(b"Root")?
            .as_reference()?;
        // Clone object
        self.raw_document
            .opt_clone_object_to_new_document(root_obj_id)?;
        // Get Root in new document
        let root = self
            .raw_document
            .new_document
            .get_object_mut(root_obj_id)?
            .as_dict_mut()?;
        log::debug!("Root: {:?}", root);

        if root.has(b"Perms") {
            log::info!("Document already has `Perms` field.");
            let perms = root.get_mut(b"Perms")?.as_dict_mut()?;
            log::debug!("Perms: {:?}", perms);
            // Add `DocMDP` reference to existing dict
            perms.set("DocMDP", Reference(first_signature_id));
        } else {
            // Add `Perms` field with `DocMDP` reference
            root.set(
                "Perms",
                lopdf::Dictionary::from_iter(vec![("DocMDP", Reference(first_signature_id))]),
            );
        }

        Ok(())
    }

    // Find and set the `Content` field in the signature
    fn set_content(
        mut pdf_file_data: Vec<u8>,
        content: Vec<u8>,
        signature_options: &SignatureOptions,
    ) -> Vec<u8> {
        // Determine the byte ranged
        // Find the `Content` part of the file
        let pattern_prefix = b"/Contents<";
        let pattern_content = vec![48u8; signature_options.signature_size]; // 48 = 0x30 = `0`

        if content.len() > pattern_content.len() {
            panic!(
                "Length of content is to long. Available: {}, Needed: {}",
                pattern_content.len(),
                content.len()
            );
        }
        let mut pattern = pattern_prefix.to_vec();
        pattern.extend_from_slice(&pattern_content[..=50]); // Just add the first part, rest will be okay

        // Find the pattern in the PDF file binary
        let found_at = Self::find_binary_pattern(&pdf_file_data, &pattern);

        match found_at {
            Some(found_at) => {
                // Construct new Contents and insert it into file
                let new_contents_vec = format!(
                    "/Contents<{}",
                    content
                        .iter()
                        .map(|num| format!("{:02x}", num))
                        .collect::<Vec<String>>()
                        .join("")
                )
                .as_bytes()
                .to_vec();

                pdf_file_data.splice(
                    found_at..(found_at + new_contents_vec.len()),
                    new_contents_vec,
                );

                pdf_file_data
            }
            None => {
                // Pattern was not found, add debug info
                #[cfg(debug_assertions)]
                {
                    let crashed_file = "./pdf_missing_pattern.pdf";
                    let mut file = std::fs::File::create(crashed_file).unwrap();
                    file.write_all(&pdf_file_data).unwrap();
                    log::error!(
                        "Pattern not found `{}`. Saved file to: `{}`.",
                        String::from_utf8_lossy(&pattern),
                        crashed_file
                    );
                }
                panic!(
                    "Pattern not found `{}`. PDF Signing bug in the code.",
                    String::from_utf8_lossy(&pattern),
                );
            }
        }
    }

    /// Set the next found byte `ByteRange` that still has the default values.
    fn set_next_byte_range(
        mut pdf_file_data: Vec<u8>,
        signature_options: &SignatureOptions,
    ) -> (ByteRange, Vec<u8>) {
        // Determine the byte ranged
        // Find the `Content` part of the file
        let pattern_prefix = b"/ByteRange[0 10000 20000 10000]/Contents<";
        let pattern_content = vec![48u8; signature_options.signature_size]; // 48 = 0x30 = `0`
        let mut pattern = pattern_prefix.to_vec();
        pattern.extend_from_slice(&pattern_content[..=50]); // Just add the first part, rest will be okay

        // Search for `ByteRange` tag with default values
        let found_at = Self::find_binary_pattern(&pdf_file_data, &pattern).unwrap();

        // Calculate `ByteRange`
        let fixed_byte_range_width = 25;
        let pattern_prefix_len = b"/ByteRange[]/Contents<".len() + fixed_byte_range_width;
        let content_len =
            pattern_content.len() + b"0 10000 20000 10000".len() - fixed_byte_range_width;
        let content_offset = found_at + pattern_prefix_len - 1;
        let byte_range = ByteRange(vec![
            0,
            content_offset,
            content_offset + content_len + 2,
            pdf_file_data.len() - 2 - (content_offset + content_len),
        ]);

        // Code for debugging
        // dbg!(&byte_range
        //     .0
        //     .iter()
        //     .map(|x| format!("0x{:02x}", x))
        //     .collect::<Vec<String>>());

        // Change binary file

        // The `Contents` field after the `ByteRange` always need to have an even number of `0`s
        // because otherwise it will have invalid byte pattern.

        // Construct new ByteRange and insert it into file
        // Note: Notice the `0`s after `Contents<` this is to make sure that if the `ByteRange`
        // is shorter than the pattern that any other chars are overwritten.
        // Have at least "0 10000 20000 10000".len() + "{}".len() `0`s. (and even number)
        let mut new_byte_range_string = format!(
            "/ByteRange[{}]/Contents<0000000000000000000000",
            byte_range.to_list(fixed_byte_range_width).unwrap()
        );

        // The `Contents<...>` always need to be an even number of chars
        if pattern_prefix.len() % 2 != new_byte_range_string.len() % 2 {
            log::trace!("Added space to `ByteRange`");
            // Add space to make equal
            new_byte_range_string = format!(
                "/ByteRange[{} ]/Contents<0000000000000000000000",
                byte_range.to_list(fixed_byte_range_width).unwrap()
            );
        }
        let new_byte_range_string = new_byte_range_string.as_bytes().to_vec();

        pdf_file_data.splice(
            found_at..(found_at + new_byte_range_string.len()),
            new_byte_range_string,
        );

        (byte_range, pdf_file_data)
    }

    /// Finds the first instance matching the pattern.
    ///
    /// Note: This function can not deal well with repeating patterns inside the pattern.
    /// But this should not matter in our cases.
    ///
    /// Result is `byte_offset_where_pattern_starts`
    ///
    fn find_binary_pattern(bytes: &[u8], pattern: &[u8]) -> Option<usize> {
        if bytes.is_empty() || pattern.is_empty() {
            return None;
        }

        let first_pat_byte = pattern.first().expect("At least 1 byte expected.");
        let mut next_pat_byte = first_pat_byte;
        let mut pattern_index = 0;
        let mut start_index = 0;

        for (index, byte) in bytes.iter().enumerate() {
            if next_pat_byte == byte {
                // Save `start_index` for later
                if pattern_index == 0 {
                    start_index = index;
                }
                // Go to next byte of pattern
                pattern_index += 1;
                next_pat_byte = match pattern.get(pattern_index) {
                    Some(byte) => byte,
                    None => return Some(start_index),
                };
            } else {
                // If pattern breaks or does not match
                pattern_index = 0;
                next_pat_byte = first_pat_byte;
            }
        }

        None
    }
}
