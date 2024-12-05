use pcsc::Error as PcscError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PcscCodecError {
    #[error("PC/SC error")]
    Pcsc(#[source] PcscError),
    #[error("Not enough bytes")]
    TooShort,
    #[error("Byte length exceeded")]
    TooLong,
    #[error("Not a PC/SC storage card command")]
    WrongClass,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyType {
    Unknown(u8),
    MifareA,
    MifareB,
}

impl From<u8> for KeyType {
    fn from(value: u8) -> Self {
        match value {
            0x60 => KeyType::MifareA,
            0x61 => KeyType::MifareB,
            o => KeyType::Unknown(o),
        }
    }
}

impl From<KeyType> for u8 {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::Unknown(o) => o,
            KeyType::MifareA => 0x60,
            KeyType::MifareB => 0x61,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PcscInstruction {
    GetData {
        le: u8,
    },
    LoadKeys {
        data: Vec<u8>,
    },
    GeneralAuthenticate {
        address: u16,
        key_type: KeyType,
        key_id: u8,
    },
    Verify {
        data: Vec<u8>,
    },
    ReadBinary {
        le: u8,
    },
    UpdateBinary {
        data: Vec<u8>,
    },
}

#[derive(Debug, PartialEq)]
pub struct PcscCommand {
    ins: PcscInstruction,
    p1: u8,
    p2: u8,
}

impl PcscCommand {
    pub const MIN_LENGTH: usize = 5; // class + ins + p1 + p2 + le/lc
    pub const MAX_LENGTH: usize = 5 + u8::MAX as usize;

    pub fn new(ins: PcscInstruction, p1: u8, p2: u8) -> Self {
        Self { ins, p1, p2 }
    }

    pub fn ins_code(&self) -> u8 {
        match self.ins {
            PcscInstruction::GetData { .. } => 0xCA,
            PcscInstruction::LoadKeys { .. } => 0x82,
            PcscInstruction::GeneralAuthenticate { .. } => 0x86,
            PcscInstruction::Verify { .. } => 0x20,
            PcscInstruction::ReadBinary { .. } => 0xB0,
            PcscInstruction::UpdateBinary { .. } => 0xD6,
        }
    }

    pub fn expected_response_len(&self) -> usize {
        match &self.ins {
            PcscInstruction::GetData { le } | PcscInstruction::ReadBinary { le } => {
                if *le == 0 {
                    PcscResponse::MAX_LENGTH
                } else {
                    *le as usize + 2
                }
            }
            PcscInstruction::LoadKeys { .. }
            | PcscInstruction::GeneralAuthenticate { .. }
            | PcscInstruction::Verify { .. }
            | PcscInstruction::UpdateBinary { .. } => 2,
        }
    }
}

impl TryFrom<&[u8]> for PcscCommand {
    type Error = PcscCodecError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < Self::MIN_LENGTH {
            return Err(PcscCodecError::TooShort);
        }
        if value.len() > Self::MAX_LENGTH {
            return Err(PcscCodecError::TooLong);
        }
        if value[0] != 0xFF {
            return Err(PcscCodecError::WrongClass);
        }
        let p1 = value[2];
        let p2 = value[3];
        let ins = match value[1] {
            0xCA => PcscInstruction::GetData { le: value[4] },
            // TODO: check length
            0x82 => PcscInstruction::LoadKeys {
                data: value[5..].to_vec(),
            },
            // TODO: check length, version
            0x86 => PcscInstruction::GeneralAuthenticate {
                address: u16::from_be_bytes([value[6], value[7]]),
                key_type: KeyType::from(value[8]),
                key_id: value[9],
            },
            // TODO: check length
            0x20 => PcscInstruction::Verify {
                data: value[5..].to_vec(),
            },
            0xB0 => PcscInstruction::ReadBinary { le: value[4] },
            // TODO: check length
            0xD6 => PcscInstruction::UpdateBinary {
                data: value[5..].to_vec(),
            },
            _ => todo!(),
        };
        Ok(Self { ins, p1, p2 })
    }
}

impl TryFrom<PcscCommand> for Vec<u8> {
    type Error = PcscCodecError;

    fn try_from(value: PcscCommand) -> Result<Self, Self::Error> {
        let ins = value.ins_code();
        Ok(match value.ins {
            PcscInstruction::GetData { le } | PcscInstruction::ReadBinary { le } => {
                vec![0xFF, ins, value.p1, value.p2, le]
            }
            PcscInstruction::LoadKeys { data }
            | PcscInstruction::Verify { data }
            | PcscInstruction::UpdateBinary { data } => {
                let lc = data.len();
                if lc > u8::MAX as usize {
                    return Err(PcscCodecError::TooLong);
                }
                let mut output = vec![0xFF, 0x82, value.p1, value.p2, lc as u8];
                output.extend(data);
                output
            }
            PcscInstruction::GeneralAuthenticate {
                address,
                key_type,
                key_id,
            } => {
                let [addr_msb, addr_lsb] = address.to_be_bytes();
                vec![
                    0xFF,
                    0x86,
                    value.p1,
                    value.p2,
                    5, // Lc fixed
                    1, // version 1
                    addr_msb,
                    addr_lsb,
                    key_type.into(),
                    key_id,
                ]
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PcscStatusWords {
    Warning(u8),
    AllowedRetries(u8),
    MemoryFailure(u8),
    WrongLength,
    WrongClassByte,
    CommandImpossible(u8),
    CommandError(u8),
    WrongParameter,
    WrongLengthLe(u8),
    Success,
    Unknown { sw1: u8, sw2: u8 },
}

pub enum PcscErrorCodeInfo {
    ResponseCorrupted,
    UnexpectedEndOfData,
    AddressDoesNotExit,
    WritingFailed,
    CommandIncompatible,
    CardKeyNotSupported,
    ReaderKeyNotSupported,
    PlainTransmissionNotSupported,
    SecuredTransmissionNotSupported,
    VolatileMemoryUnavailable,
    NonVolatileMemoryUnavailable,
    KeyNumberNotValid,
    KeyLengthIncorrect,
    SecurityStatusUnsatisfied,
    ReferenceKeyUnusable,
    UnknownKeyType,
    CommandNotAllowed,
    FunctionNotSupported,
    FileNotFound,
    ReferenceDataNotFound,
}

impl PcscStatusWords {
    pub fn extra_info(&self, ins: u8) -> Option<PcscErrorCodeInfo> {
        match self {
            // 0x62
            PcscStatusWords::Warning(sw2) => match sw2 {
                0x81 => Some(PcscErrorCodeInfo::ResponseCorrupted),
                0x82 => Some(PcscErrorCodeInfo::UnexpectedEndOfData),
                _ => None,
            },
            // 0x65
            PcscStatusWords::MemoryFailure(sw2) => match (ins, sw2) {
                (0xCA, 0x81) => Some(PcscErrorCodeInfo::AddressDoesNotExit),
                (0x86, 0x81) => Some(PcscErrorCodeInfo::AddressDoesNotExit),
                (0x20, 0x81) => Some(PcscErrorCodeInfo::WritingFailed),
                (0xD6, 0x81) => Some(PcscErrorCodeInfo::WritingFailed),
                _ => None,
            },
            // 0x69
            PcscStatusWords::CommandImpossible(sw2) => match (ins, sw2) {
                // Load Keys errors
                (0x82, 0x82) => Some(PcscErrorCodeInfo::CardKeyNotSupported),
                (0x82, 0x83) => Some(PcscErrorCodeInfo::ReaderKeyNotSupported),
                (0x82, 0x84) => Some(PcscErrorCodeInfo::PlainTransmissionNotSupported),
                (0x82, 0x85) => Some(PcscErrorCodeInfo::SecuredTransmissionNotSupported),
                (0x82, 0x86) => Some(PcscErrorCodeInfo::VolatileMemoryUnavailable),
                (0x82, 0x87) => Some(PcscErrorCodeInfo::NonVolatileMemoryUnavailable),
                (0x82, 0x88) => Some(PcscErrorCodeInfo::KeyNumberNotValid),
                (0x82, 0x89) => Some(PcscErrorCodeInfo::KeyLengthIncorrect),
                // Authenticate errors
                (0x86, 0x82) => Some(PcscErrorCodeInfo::SecurityStatusUnsatisfied),
                (0x86, 0x83) => Some(PcscErrorCodeInfo::CommandNotAllowed),
                (0x86, 0x84) => Some(PcscErrorCodeInfo::ReferenceKeyUnusable),
                (0x86, 0x86) => Some(PcscErrorCodeInfo::UnknownKeyType),
                (0x86, 0x88) => Some(PcscErrorCodeInfo::KeyNumberNotValid),
                // Verify errors
                (0x20, 0x82) => Some(PcscErrorCodeInfo::SecurityStatusUnsatisfied),
                (0x20, 0x83) => Some(PcscErrorCodeInfo::CommandNotAllowed),
                (0x20, 0x84) => Some(PcscErrorCodeInfo::ReferenceKeyUnusable),
                // Read Binary errors
                (0xB0, 0x81) => Some(PcscErrorCodeInfo::CommandIncompatible),
                (0xB0, 0x82) => Some(PcscErrorCodeInfo::SecurityStatusUnsatisfied),
                (0xB0, 0x86) => Some(PcscErrorCodeInfo::CommandNotAllowed),
                // Update Binary errors
                (0xD6, 0x81) => Some(PcscErrorCodeInfo::CommandIncompatible),
                (0xD6, 0x82) => Some(PcscErrorCodeInfo::SecurityStatusUnsatisfied),
                (0xD6, 0x86) => Some(PcscErrorCodeInfo::CommandNotAllowed),
                _ => None,
            },
            // 0x6A
            PcscStatusWords::CommandError(sw2) => match sw2 {
                0x81 => Some(PcscErrorCodeInfo::FunctionNotSupported),
                0x82 => Some(PcscErrorCodeInfo::FileNotFound),
                0x88 => Some(PcscErrorCodeInfo::ReferenceDataNotFound),
                _ => None,
            },
            PcscStatusWords::AllowedRetries(_)
            | PcscStatusWords::WrongLength
            | PcscStatusWords::WrongClassByte
            | PcscStatusWords::WrongParameter
            | PcscStatusWords::WrongLengthLe(_)
            | PcscStatusWords::Success
            | PcscStatusWords::Unknown { .. } => None,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct PcscResponse {
    data: Vec<u8>,
    sw: PcscStatusWords,
}

impl PcscResponse {
    pub const MIN_LENGTH: usize = 2;
    pub const MAX_LENGTH: usize = 2 + u8::MAX as usize;
}

impl TryFrom<&[u8]> for PcscResponse {
    type Error = PcscCodecError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (data, eod) = match value.len() {
            0 | 1 => return Err(PcscCodecError::TooShort),
            Self::MIN_LENGTH => (vec![], 0),
            len => (value[0..len - 2].to_vec(), len - 2),
        };
        let sw = match value[eod] {
            0x62 => PcscStatusWords::Warning(value[eod + 1]),
            0x63 => PcscStatusWords::AllowedRetries(value[eod + 1]),
            0x65 => PcscStatusWords::MemoryFailure(value[eod + 1]),
            0x67 => PcscStatusWords::WrongLength,
            0x68 => PcscStatusWords::WrongClassByte,
            0x69 => PcscStatusWords::CommandImpossible(value[eod + 1]),
            0x6A => PcscStatusWords::CommandError(value[eod + 1]),
            0x6B => PcscStatusWords::WrongParameter,
            0x6C => PcscStatusWords::WrongLengthLe(value[eod + 1]),
            0x90 => PcscStatusWords::Success,
            sw1 => PcscStatusWords::Unknown {
                sw1,
                sw2: value[eod + 1],
            },
        };
        Ok(Self { data, sw })
    }
}

impl From<PcscResponse> for Vec<u8> {
    fn from(value: PcscResponse) -> Self {
        let mut output = value.data;
        output.extend(match value.sw {
            PcscStatusWords::Warning(sw2) => [0x62, sw2],
            PcscStatusWords::AllowedRetries(sw2) => [0x63, sw2],
            PcscStatusWords::MemoryFailure(sw2) => [0x65, sw2],
            PcscStatusWords::WrongLength => [0x67, 0x00],
            PcscStatusWords::WrongClassByte => [0x68, 0x00],
            PcscStatusWords::CommandImpossible(sw2) => [0x69, sw2],
            PcscStatusWords::CommandError(sw2) => [0x6A, sw2],
            PcscStatusWords::WrongParameter => [0x6B, 0x00],
            PcscStatusWords::WrongLengthLe(sw2) => [0x6C, sw2],
            PcscStatusWords::Success => [0x90, 0x00],
            PcscStatusWords::Unknown { sw1, sw2 } => [sw1, sw2],
        });
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_data() -> [u8; 5] {
        [0xff, 0xca, 0x00, 0x00, 0x00]
    }

    fn load_authentication_keys(key_number: u8, key: [u8; 6]) -> [u8; 11] {
        [
            0xff, 0x82, 0x00, key_number, 0x06, key[0], key[1], key[2], key[3], key[4], key[5],
        ]
    }

    // fn authentication(block_number: u8, key_type: KeyType, key_number: u8) -> [u8; 10] {
    //     [
    //         // Class
    //         0xff,
    //         // INS (authentication)
    //         0x86,
    //         // P1
    //         0x00,
    //         // P2
    //         0x00,
    //         // Lc
    //         0x05,
    //         // Version
    //         0x01,
    //         0x00,
    //         block_number,
    //         key_type as u8,
    //         key_number,
    //     ]
    // }

    #[test]
    fn test_get_data_from_u8() {
        let expected = PcscCommand {
            ins: PcscInstruction::GetData { le: 0 },
            p1: 0,
            p2: 0,
        };
        let get_data = get_data();
        let command = PcscCommand::try_from(&get_data[..]).unwrap();
        assert_eq!(command, expected);
    }

    #[test]
    fn test_u8_from_get_data() {
        let expected = get_data().to_vec();
        let input = PcscCommand {
            ins: PcscInstruction::GetData { le: 0 },
            p1: 0,
            p2: 0,
        };
        let bytes: Vec<u8> = input.try_into().unwrap();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn load_keys_from_u8() {
        let expected = PcscCommand {
            ins: PcscInstruction::LoadKeys {
                data: vec![0, 1, 2, 3, 4, 5],
            },
            p1: 0,
            p2: 1,
        };
        let load_keys = load_authentication_keys(1, [0, 1, 2, 3, 4, 5]);
        let command = PcscCommand::try_from(&load_keys[..]).unwrap();
        assert_eq!(command, expected);
    }
}
