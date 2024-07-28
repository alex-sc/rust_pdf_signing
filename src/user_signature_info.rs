use cryptographic_message_syntax::SignerBuilder;
use serde::{Deserialize, Serialize};
use x509_certificate::CapturedX509Certificate;

/// The info provided to PDF service when a document needs to be signed.
#[derive(Clone)]
pub struct UserSignatureInfo<'a> {
    pub user_id: String,
    pub user_name: String,
    pub user_email: String,
    pub user_signature: Vec<u8>,
    pub user_signing_keys: SignerBuilder<'a>,
    pub user_certificate_chain: Vec<CapturedX509Certificate>,
}

/// The info inside the PDF form signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserFormSignatureInfo {
    pub user_id: String,
}
