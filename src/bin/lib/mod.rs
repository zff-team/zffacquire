//STD
use std::process::exit;
use std::error::Error;

// - modules
pub mod constants;
pub mod traits;

// - internal
use constants::*;
use super::{EncryptionHeader, CompressionHeader, ObjectType, EncryptionAlgorithm, KDFScheme, PBEScheme, DescriptionHeader};

// - external
use serde::ser::{Serialize, Serializer, SerializeStruct};
use log::{LevelFilter, error, debug, info};

fn string_to_str(s: String) -> &'static str {
  Box::leak(s.into_boxed_str())
}

pub(crate) struct OutputInfo {
    pub chunk_size: String,
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
            chunk_size: String::from(""),
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

/*
impl Serialize for OutputInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(SER_INFORMATION, 6)?;
        state.serialize_field(SER_CHUNK_SIZE, &self.chunk_size)?;
        state.serialize_field(SER_SEGMENT_SIZE, &self.segment_size)?;
        state.serialize_field(SER_UNIQUE_SEGMENT_IDENTIFIER, &self.unique_segment_identifier)?;
        
        if let Some(compression_header) = self.compression_header.clone() {
            let sch = SerializeCompressionHeader(compression_header);
            state.serialize_field(SER_COMPRESSION_INFORMATION, &sch)?;
        }

        if let Some(encryption_header) = self.encryption_header.clone() {
            let seh = SerializeEncryptionHeader(encryption_header);
            state.serialize_field(SER_ENCRYPTION_INFORMATION, &seh)?;
        }

        state.serialize_field(SER_OBJECT_TYPE, &self.object_type.to_string())?;
        state.serialize_field(SER_EXISTING_CONTAINER_EXTENDED, &self.extended)?;

        if let Some(description_header) = self.description_header.clone() {
            if !description_header.identifier_map().is_empty() {
                let sdh = SerializeDescriptionHeader(description_header);
                state.serialize_field(SER_OBJECT_DESCRIPTION_INFORMATION, &sdh)?;
            }            
        }

        if let Some(signature_private_key) = &self.signature_private_key {
            state.serialize_field(SER_PRIVATE_KEY, &signature_private_key)?;
        }

        if let Some(signature_public_key) = &self.signature_public_key {
            state.serialize_field(SER_PUBLIC_KEY, &signature_public_key)?;
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
        let mut state = serializer.serialize_struct(SER_INFORMATION, 1)?;

        for (key, value) in self.0.identifier_map() {
            let key = string_to_str(key.to_string());
            let key = match key {
                "ev" => SER_EVIDENCE_NUMBER,
                "ex" => SER_EXAMINER_NAME,
                "cn" => SER_CASE_NUMBER,
                "no" => SER_NOTES,
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
        let mut state = serializer.serialize_struct(SER_INFORMATION, 3)?;
        let algorithm = match&self.0.algorithm() {
            EncryptionAlgorithm::AES128GCMSIV => SER_AES128GCMSIV,
            EncryptionAlgorithm::AES256GCMSIV => SER_AES256GCMSIV,
            _ => "unknown algorithm"
        };
        state.serialize_field("algorithm", &algorithm)?;

        let mut pbe_variant = match self.0.pbe_header().kdf_scheme() {
            KDFScheme::PBKDF2SHA256 => String::from(SER_KDF_SCHEME_PBKDF2_),
            KDFScheme::Scrypt => String::from(SER_KDF_SCHEME_SCRYPT_),
            _ => String::from(SER_KDF_SCHEME_UNKNOWN_),
        };
        match self.0.pbe_header().encryption_scheme() {
            PBEScheme::AES128CBC => pbe_variant.push_str(SER_PBESCHEME_AES128CBC),
            PBEScheme::AES256CBC => pbe_variant.push_str(SER_PBESCHEME_AES256CBC),
            _ => pbe_variant.push_str(SER_PBESCHEME_UNKNOWN),
        };
        state.serialize_field(SER_PBESCHEME, &pbe_variant)?;

        state.end()
    }
}

pub struct SerializeCompressionHeader(CompressionHeader);

impl Serialize for SerializeCompressionHeader {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(SER_INFORMATION, 3)?;
        state.serialize_field(SER_ALGORITHM, &self.0.algorithm().to_string())?;
        state.serialize_field(SER_LEVEL, &self.0.level())?;
        state.serialize_field(SER_THRESHOLD, &self.0.threshold())?;

        state.end()
    }
}

*/
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

/// Parse a single key-value pair
pub(crate) fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find(':')
        .ok_or_else(|| format!("invalid KEY:value -> no `:` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}