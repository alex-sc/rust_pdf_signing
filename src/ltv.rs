use bcder::encode::Values;
use bcder::Mode::Der;
use bcder::{encode::PrimitiveContent, Captured, Integer, OctetString, Oid, Tag};
use cryptographic_message_syntax::Bytes;
use rasn::ber::encode;
use rasn::types::ObjectIdentifier;
use rasn_ocsp::{CertId, Request, TbsRequest};
use reqwest::blocking::Client;
use std::borrow::Cow;
use x509_certificate::rfc5652::AttributeValue;
use x509_certificate::CapturedX509Certificate;
use x509_parser::extensions::ParsedExtension::AuthorityInfoAccess;
use x509_parser::num_bigint::{BigInt, Sign};
use x509_parser::prelude::*;

pub(crate) fn get_ocsp_crl_url(
    captured_cert: CapturedX509Certificate,
) -> (Option<String>, Option<String>) {
    let binding = captured_cert.encode_der().unwrap();
    let x509_certificate = X509Certificate::from_der(&*binding);
    let cert = x509_certificate.unwrap().1;
    let mut crl_url = None;
    let mut ocsp_url = None;
    for extension in cert.extensions() {
        let parsed = extension.parsed_extension();
        if let AuthorityInfoAccess(aia) = parsed {
            for access_desc in &aia.accessdescs {
                if "1.3.6.1.5.5.7.48.1".eq(&access_desc.access_method.to_string()) {
                    if let GeneralName::URI(ocsp) = &access_desc.access_location {
                        ocsp_url = Some(ocsp.to_string());
                    }
                } else if "1.3.6.1.5.5.7.48.2".eq(&access_desc.access_method.to_string()) {
                    if let GeneralName::URI(crl) = &access_desc.access_location {
                        crl_url = Some(crl.to_string());
                    }
                }
            }
        }
    }

    return (ocsp_url, crl_url);
}

pub(crate) fn fetch_ocsp_response(
    captured_cert: CapturedX509Certificate,
    ocsp_url: String,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let binding = captured_cert.encode_der().unwrap();
    let cert = X509Certificate::from_der(&*binding).unwrap().1;

    let ocsp_req = create_ocsp_request(&cert)?;

    let client = Client::new();
    let response = client
        .post(&ocsp_url)
        .header("Content-Type", "application/ocsp-request")
        .body(ocsp_req)
        .send()?;

    if response.status().is_success() {
        let ocsp_resp = response.bytes()?;
        //print!("{:?}", ocsp_resp);
        return Ok(Some(ocsp_resp.to_vec()));
    } else {
        eprintln!("OCSP request failed with status: {}", response.status());
        return Ok(None);
    }
}

pub(crate) fn create_ocsp_request(
    cert: &X509Certificate,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let sha1_oid = ObjectIdentifier::new_unchecked(Cow::from(vec![1, 3, 14, 3, 2, 26]));

    let sha1 = rasn_pkix::AlgorithmIdentifier {
        algorithm: sha1_oid,
        parameters: None,
    };

    let request = Request {
        req_cert: CertId {
            hash_algorithm: sha1,
            // TODO
            issuer_name_hash: Default::default(),
            // TODO
            issuer_key_hash: Default::default(),
            serial_number: BigInt::from_bytes_le(Sign::Plus, cert.raw_serial()),
        },
        single_request_extensions: None,
    };

    let tbs_request = TbsRequest {
        version: Default::default(),
        requestor_name: None,
        request_list: vec![request],
        request_extensions: None,
    };

    let ocsp_req = rasn_ocsp::OcspRequest {
        tbs_request,
        optional_signature: None,
    };

    Ok(encode(&ocsp_req).unwrap())
}

pub(crate) fn encode_revocation_info_archival<'a>(
    crl: Option<Vec<u8>>,
    ocsp: Option<Vec<u8>>,
) -> Option<Captured> {
    let mut revocation_vector = Vec::new();

    if crl.is_some() {
        // crl [0] EXPLICIT SEQUENCE of CRLs, OPTIONAL
    }

    if ocsp.is_some() {
        let ocsp_encoded = OctetString::new(Bytes::from(ocsp.unwrap()));
        // 1.3.6.1.5.5.7.48.1.1 - id_pkix_ocsp_basic
        let adbe_revocation_oid = Oid(Bytes::copy_from_slice(&[43, 6, 1, 5, 5, 7, 48, 1, 1]));
        let basic_ocsp_response =
            bcder::encode::sequence((adbe_revocation_oid.encode(), ocsp_encoded.encode()));

        let tagged_basic_ocsp_response =
            bcder::encode::sequence_as(Tag::CTX_0, basic_ocsp_response);
        let tagged_seq = Integer::from(0u8)
            .encode_as(Tag::ENUMERATED)
            .to_captured(Der);
        let ocsp_response = bcder::encode::sequence((tagged_seq, tagged_basic_ocsp_response));

        let ocsp_responses = bcder::encode::sequence(ocsp_response);

        let ocsp_tagged = bcder::encode::sequence_as(Tag::CTX_1, ocsp_responses);

        // ocsp [1] EXPLICIT SEQUENCE of OCSP Responses, OPTIONAL
        revocation_vector.push(ocsp_tagged);
    }

    Some(bcder::encode::sequence(revocation_vector).to_captured(Der))
}

pub(crate) fn build_adbe_revocation_attribute(
    user_certificate_chain: &Vec<CapturedX509Certificate>,
) -> Option<(Oid, Vec<AttributeValue>)> {
    let user_certificate = user_certificate_chain[0].clone();

    let (ocsp_url, crl_url) = get_ocsp_crl_url(user_certificate.clone());
    let mut crl_data = None;
    let mut ocsp_data = None;
    if let Some(ocsp) = ocsp_url {
        ocsp_data = fetch_ocsp_response(user_certificate, ocsp).unwrap();
    }
    if let Some(crl) = crl_url {
        // TOOD:
    }
    let encoded_revocation_info = encode_revocation_info_archival(crl_data, ocsp_data);
    if encoded_revocation_info.is_some() {
        let adbe_revocation_oid = Oid(Bytes::copy_from_slice(&[
            42, 134, 72, 134, 247, 47, 1, 1, 8,
        ]));

        return Some((
            adbe_revocation_oid,
            vec![AttributeValue::new(encoded_revocation_info.unwrap())],
        ));
    }

    return None;
}
