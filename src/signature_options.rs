#[derive(Clone)]
pub enum SignatureFormat {
    PKCS7,
    PADES,
}

#[derive(Clone)]
pub struct SignatureOptions {
    pub format: SignatureFormat,
    pub timestamp_url: Option<String>,

    // Pkcs7-specific
    pub signed_attribute_include_crl: bool,
    pub signed_attribute_include_ocsp: bool,
}

impl Default for SignatureOptions {
    fn default() -> SignatureOptions {
        SignatureOptions {
            format: SignatureFormat::PKCS7,
            timestamp_url: Some("http://timestamp.digicert.com".parse().unwrap()),

            signed_attribute_include_crl: true,
            signed_attribute_include_ocsp: false,
        }
    }
}
