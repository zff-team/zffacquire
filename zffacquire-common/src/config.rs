use crate::{
    CompressionAlgorithm, EncryptionAlgorithm, HashType, KDFScheme, PBEScheme,
};

#[derive(Debug, Clone)]
pub struct AcquireConfig {
    pub compression_algorithm: CompressionAlgorithm,
    pub compression_level: u8,
    pub compression_threshold: f32,
    pub encrypt: bool,
    pub kdf_scheme: KDFScheme,
    pub pbe_scheme: PBEScheme,
    pub encryption_algorithm: EncryptionAlgorithm,
    pub hash_algorithms: Vec<HashType>,
    pub sign_data: bool,
    pub sign_key: Option<String>,
    pub case_number: Option<String>,
    pub evidence_number: Option<String>,
    pub examiner_name: Option<String>,
    pub notes: Option<String>,
    pub custom_descriptions: Vec<(String, String)>,
    pub segment_size: Option<String>,
    pub chunk_size: String,
    pub chunkmap_size: String,
    pub description_notes: Option<String>,
    pub uncompress_input: bool,
}

impl Default for AcquireConfig {
    fn default() -> Self {
        Self {
            compression_algorithm: CompressionAlgorithm::Zstd,
            compression_level: 3,
            compression_threshold: 1.05,
            encrypt: false,
            kdf_scheme: KDFScheme::Argon2id,
            pbe_scheme: PBEScheme::AES256CBC,
            encryption_algorithm: EncryptionAlgorithm::AES256GCM,
            hash_algorithms: vec![HashType::Blake3],
            sign_data: false,
            sign_key: None,
            case_number: None,
            evidence_number: None,
            examiner_name: None,
            notes: None,
            custom_descriptions: Vec::new(),
            segment_size: None,
            chunk_size: "32KB".to_string(),
            chunkmap_size: "32KB".to_string(),
            description_notes: None,
            uncompress_input: false,
        }
    }
}
