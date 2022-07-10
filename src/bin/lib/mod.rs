// - modules
pub mod constants;

// - internal
use crate::HRS_PARSER_BASE;
use super::{EncryptionHeader, CompressionHeader, ObjectType, EncryptionAlgorithm, KDFScheme, PBEScheme, DescriptionHeader};

// - external
use serde::ser::{Serialize, Serializer, SerializeStruct};

fn string_to_str(s: String) -> &'static str {
  Box::leak(s.into_boxed_str())
}

pub(crate) struct OutputInfo {
    pub chunk_size: u64,
    pub segment_size: String,
    pub unique_segment_identifier: i64,
    pub encryption_header: Option<EncryptionHeader>,
    pub compression_header: Option<CompressionHeader>,
    pub signature_private_key: Option<String>,
    pub signature_public_key: Option<String>,
    pub object_type: ObjectType,
    pub extended: bool,
    pub description_header: Option<DescriptionHeader>
}

impl OutputInfo {
    pub fn new() -> OutputInfo {
        Self {
            chunk_size: 0,
            segment_size: String::from(""),
            unique_segment_identifier: 0,
            encryption_header: None,
            compression_header: None,
            signature_private_key: None,
            signature_public_key: None,
            object_type: ObjectType::Physical,
            extended: false,
            description_header: None,
        }
    }
}

impl Serialize for OutputInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("acquisition", 6)?;
        state.serialize_field("chunk_size", &self.chunk_size)?;
        state.serialize_field("segment_size", &self.segment_size)?;
        state.serialize_field("unique_segment_identifier", &self.unique_segment_identifier)?;
        
        if let Some(compression_header) = self.compression_header.clone() {
            let sch = SerializeCompressionHeader(compression_header);
            state.serialize_field("compression_information", &sch)?;
        }

        if let Some(encryption_header) = self.encryption_header.clone() {
            let seh = SerializeEncryptionHeader(encryption_header);
            state.serialize_field("encryption_information", &seh)?;
        }

        state.serialize_field("object_type", &self.object_type.to_string())?;
        state.serialize_field("existing_zff_container_extended", &self.extended)?;

        if let Some(description_header) = self.description_header.clone() {
            if !description_header.identifier_map().is_empty() {
                let sdh = SerializeDescriptionHeader(description_header);
                state.serialize_field("object_description_information", &sdh)?;
            }            
        }

        if let Some(signature_private_key) = &self.signature_private_key {
            state.serialize_field("auto-generated_signature_private_key", &signature_private_key)?;
        }

        if let Some(signature_public_key) = &self.signature_public_key {
            state.serialize_field("signature_public_key", &signature_public_key)?;
        }

        state.end()
    }
}

pub struct SerializeDescriptionHeader(DescriptionHeader);

impl Serialize for SerializeDescriptionHeader {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("description_header", 1)?;

        for (key, value) in self.0.identifier_map() {
            let key = string_to_str(key.to_string());
            let key = match key {
                "ev" => "evidence-number",
                "ex" => "examiner-name",
                "cn" => "case-number",
                "no" => "notes",
                _ => key
            };
            state.serialize_field(key, value)?;
        }

        state.end()
    }
}

pub struct SerializeEncryptionHeader(EncryptionHeader);

impl Serialize for SerializeEncryptionHeader {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("encryption_header", 3)?;
        let algorithm = match&self.0.algorithm() {
            EncryptionAlgorithm::AES128GCMSIV => "AES128GCMSIV",
            EncryptionAlgorithm::AES256GCMSIV => "AES256GCMSIV",
            _ => "unknown algorithm"
        };
        state.serialize_field("algorithm", &algorithm)?;

        let mut pbe_variant = match self.0.pbe_header().kdf_scheme() {
            KDFScheme::PBKDF2SHA256 => String::from("PBKDF2SHA256-"),
            KDFScheme::Scrypt => String::from("Scrypt-"),
            _ => String::from("unknown kdf scheme /"),
        };
        match self.0.pbe_header().encryption_scheme() {
            PBEScheme::AES128CBC => pbe_variant.push_str("AES128CBC"),
            PBEScheme::AES256CBC => pbe_variant.push_str("AES256CBC"),
            _ => pbe_variant.push_str("unknown pbe encryption scheme"),
        };
        state.serialize_field("pbe_scheme", &pbe_variant)?;

        state.end()
    }
}

pub struct SerializeCompressionHeader(CompressionHeader);

impl Serialize for SerializeCompressionHeader {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("compression_header", 3)?;
        state.serialize_field("algorithm", &self.0.algorithm().to_string())?;
        state.serialize_field("level", &self.0.level())?;
        state.serialize_field("threshold", &self.0.threshold())?;

        state.end()
    }
}


pub(crate) fn hrs_parser<V: Into<String>>(value: V) -> Option<u64> {
    let mut value = value.into();
    if let Ok(val) = value.parse() { return Some(val) };
    let mut last_char = value.pop()?;
    if last_char == 'b' || last_char == 'B' {
        last_char = value.pop()?;
    }
    if last_char == 'k' || last_char == 'K' {
        match value.parse::<u64>() {
            Ok(val) => return Some(val*(HRS_PARSER_BASE.checked_pow(1)?)),
            Err(_) => return None
        }
    }
    if last_char == 'm' || last_char == 'M' {
        match value.parse::<u64>() {
            Ok(val) => return Some(val*(HRS_PARSER_BASE.checked_pow(2)?)),
            Err(_) => return None,
        }
    }
    if last_char == 'g' || last_char == 'G' {
        match value.parse::<u64>() {
            Ok(val) => return Some(val*(HRS_PARSER_BASE.checked_pow(3)?)),
            Err(_) => return None,
        }
    }
    if last_char == 't' || last_char == 'T' {
        match value.parse::<u64>() {
            Ok(val) => return Some(val*(HRS_PARSER_BASE.checked_pow(4)?)),
            Err(_) => return None,
        }
    }
    if last_char == 'p' || last_char == 'P' {
        match value.parse::<u64>() {
            Ok(val) => return Some(val*(HRS_PARSER_BASE.checked_pow(5)?)),
            Err(_) => return None,
        }
    }
    None
}
