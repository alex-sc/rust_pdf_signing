use cryptographic_message_syntax::SignerBuilder;
use pdf_signing::{PDFSigningDocument, SignatureOptions, UserSignatureInfo};
use std::{fs::File, io::Write};
use x509_certificate::{CapturedX509Certificate, InMemorySigningKeyPair};
use pdf_signing::signature_options::SignatureFormat::PADES;

fn main() {
    let pdf_file_name = "test-small-1sig.pdf";
    let pdf_data = std::fs::read(format!("./examples/assets/{}", pdf_file_name)).unwrap();

    // Use Cert/Private key to sign data
    let cert = std::fs::read_to_string("./examples/assets/keystore-local-chain.pem").unwrap();
    let x509_certs = CapturedX509Certificate::from_pem_multiple(cert).unwrap();
    let x509_cert = &x509_certs[0];
    let private_key_data =
        std::fs::read_to_string("./examples/assets/keystore-local-key.pem").unwrap();
    let private_key = InMemorySigningKeyPair::from_pkcs8_pem(&private_key_data).unwrap();
    let signer = SignerBuilder::new(&private_key, x509_cert.clone());

    let users_signature_info = vec![UserSignatureInfo {
        user_id: "272".to_owned(),
        user_name: "Charlie".to_owned(),
        user_email: "charlie@test.com".to_owned(),
        user_signature: std::fs::read("./examples/assets/sig1.png").unwrap(),
        user_signing_keys: signer.clone(),
        user_certificate_chain: x509_certs.clone(),
    }];

    let mut signature_parameters: SignatureOptions = Default::default();
    signature_parameters.format = PADES;
    signature_parameters.signed_attribute_include_ocsp = false;
    signature_parameters.signed_attribute_include_crl = false;

    let mut pdf_signing_document =
        PDFSigningDocument::read_from(&*pdf_data, pdf_file_name.to_owned()).unwrap();
    let pdf_file_data = pdf_signing_document
        .sign_document(users_signature_info, &signature_parameters)
        .unwrap();

    let mut pdf_file = File::create("./examples/result.pdf").unwrap();
    pdf_file.write_all(&pdf_file_data).unwrap();
}
