// use std::ffi::{CStr, CString};

use pcsc::{
    Card, Context, Error, Protocols, ReaderState, Scope, ShareMode, State, PNP_NOTIFICATION,
};

// const ACR_122_NAME: &CStr = c"acr122";
// const ACR_125_NAME: &CStr = c"acr125";

#[derive(Debug, Clone, Copy)]
pub enum TagType {
    Iso14443_3,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum KeyType {
    Unknown,
    MifareA = 0x60,
    MifareB = 0x61,
}

impl From<u8> for KeyType {
    fn from(value: u8) -> Self {
        match value {
            0x60 => KeyType::MifareA,
            0x61 => KeyType::MifareB,
            _ => KeyType::Unknown,
        }
    }
}

pub struct RfidTag {
    tag_type: TagType,
    card: Card,
}

impl RfidTag {
    pub fn tag_type(&self) -> TagType {
        self.tag_type
    }

    pub fn run_command(&self, command: PcscCommand) -> Result<PcscResponse, Error> {
        let command_bytes: Vec<u8> = command.into();
        let mut buf = [0u8; PcscResponse::MAX_LENGTH];
        self.card.transmit(&command_bytes, &mut buf)?;
        if u16::from_be_bytes(buf[0..2].try_into().unwrap()) != 9000 {
            // bail
        }
        let response = PcscResponse::try_from(&buf[2..]).unwrap();
        Ok(response)
    }
}

pub struct Reader {
    context: Context,
    state: [ReaderState; 1],
    is_alive: bool,
}

impl Reader {
    pub fn get_card(&mut self) -> Result<Option<RfidTag>, Error> {
        if !self.is_alive {
            return Err(Error::ReaderUnavailable);
        }
        self.context.get_status_change(None, &mut self.state)?;
        let event = self.state[0].event_state();
        if event.intersects(State::UNKNOWN | State::IGNORE) {
            self.is_alive = false;
        }
        let card = if event != self.state[0].current_state() {
            if event == State::PRESENT {
                let card = self.context.connect(
                    self.state[0].name(),
                    ShareMode::Shared,
                    Protocols::ANY,
                )?;
                let tag_type = match self.state[0].atr().get(5) {
                    Some(0x4f) => TagType::Iso14443_3,
                    _ => TagType::Unknown,
                };
                Some(RfidTag { tag_type, card })
            } else {
                None
            }
        } else {
            None
        };
        self.state[0].sync_current_state();
        Ok(card)
    }

    pub fn state(&self) -> State {
        self.state[0].current_state()
    }
}

pub struct Pcsc {
    context: Context,
}

impl Pcsc {
    pub fn new() -> Result<Self, Error> {
        let context = Context::establish(Scope::System)?;
        Ok(Self { context })
    }

    pub fn get_readers(&mut self) -> Result<Vec<Reader>, Error> {
        let mut reader_state = vec![ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE)];
        self.context.get_status_change(None, &mut reader_state)?;
        // Ignore readers marked as removed
        reader_state.retain(|rs| !rs.event_state().intersects(State::UNKNOWN | State::IGNORE));
        // Return any new readers
        self.context.list_readers_owned().map(|readers| {
            readers
                .iter()
                .filter_map(|reader_name| {
                    if !reader_state
                        .iter()
                        .any(|rs| rs.name() == reader_name.as_c_str())
                    {
                        Some(Reader {
                            context: self.context.clone(),
                            state: [ReaderState::new(reader_name.to_owned(), State::UNAWARE)],
                            is_alive: true,
                        })
                    } else {
                        None
                    }
                })
                .collect()
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
enum PcscInstruction {
    GetData {
        le: u8,
    },
    LoadKeys {
        data: Vec<u8>,
    },
    // Authenticate = 0x88,
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
    const MIN_LENGTH: usize = 5; // class + ins + p1 + p2 + le/lc
                                 // const MAX_LENGTH: usize = 5 + u8::MAX as usize;

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
}

impl TryFrom<&[u8]> for PcscCommand {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < Self::MIN_LENGTH {
            // bail
        }
        if value[0] != 0xFF {
            // bail
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

impl From<PcscCommand> for Vec<u8> {
    fn from(value: PcscCommand) -> Self {
        let ins = value.ins_code();
        match value.ins {
            PcscInstruction::GetData { le } | PcscInstruction::ReadBinary { le } => {
                vec![0xFF, ins, value.p1, value.p2, le]
            }
            // TODO: check length
            PcscInstruction::LoadKeys { data }
            | PcscInstruction::Verify { data }
            | PcscInstruction::UpdateBinary { data } => {
                let mut output = vec![0xFF, 0x82, value.p1, value.p2, data.len() as u8];
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
                    5, // Lc
                    1, // version 1
                    addr_msb,
                    addr_lsb,
                    key_type as u8,
                    key_id,
                ]
            }
        }
    }
}

// enum PcscErrorCode {

// }

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PcscErrorCode {
    Warning(u8) = 0x62,
    AllowedRetries(u8) = 0x63,
    MemoryFailure(u8) = 0x65,
    WrongLength = 0x67,
    WrongClassByte = 0x68,
    CommandImpossible(u8) = 0x69,
    CommandError(u8) = 0x6A,
    WrongParameter = 0x6B,
    WrongLengthLe(u8) = 0x6C,
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

impl PcscErrorCode {
    pub fn extra_info(&self, ins: u8) -> Option<PcscErrorCodeInfo> {
        match self {
            // 0x62
            PcscErrorCode::Warning(sw2) => match sw2 {
                0x81 => Some(PcscErrorCodeInfo::ResponseCorrupted),
                0x82 => Some(PcscErrorCodeInfo::UnexpectedEndOfData),
                _ => None,
            },
            // 0x65
            PcscErrorCode::MemoryFailure(sw2) => match (ins, sw2) {
                (0xCA, 0x81) => Some(PcscErrorCodeInfo::AddressDoesNotExit),
                (0x86, 0x81) => Some(PcscErrorCodeInfo::AddressDoesNotExit),
                (0x20, 0x81) => Some(PcscErrorCodeInfo::WritingFailed),
                (0xD6, 0x81) => Some(PcscErrorCodeInfo::WritingFailed),
                _ => None,
            },
            // 0x69
            PcscErrorCode::CommandImpossible(sw2) => match (ins, sw2) {
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
            PcscErrorCode::CommandError(sw2) => match sw2 {
                0x81 => Some(PcscErrorCodeInfo::FunctionNotSupported),
                0x82 => Some(PcscErrorCodeInfo::FileNotFound),
                0x88 => Some(PcscErrorCodeInfo::ReferenceDataNotFound),
                _ => None,
            },
            PcscErrorCode::AllowedRetries(_)
            | PcscErrorCode::WrongLength
            | PcscErrorCode::WrongClassByte
            | PcscErrorCode::WrongParameter
            | PcscErrorCode::WrongLengthLe(_) => None,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum PcscSw {
    Response { sw1: u8, sw2: u8 },
    Error(PcscErrorCode),
}

#[derive(Debug, PartialEq)]
pub struct PcscResponse {
    data: Vec<u8>,
    sw: PcscSw,
}

impl PcscResponse {
    const MIN_LENGTH: usize = 2;
    const MAX_LENGTH: usize = 2 + u8::MAX as usize;
}

impl TryFrom<&[u8]> for PcscResponse {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (data, eod) = match value.len() {
            0 | 1 => todo!(),
            Self::MIN_LENGTH => (vec![], 0),
            len => (value[0..len - 2].to_vec(), len - 2),
        };
        let sw = match value[eod] {
            0x62 => PcscSw::Error(PcscErrorCode::Warning(value[eod + 1])),
            0x63 => PcscSw::Error(PcscErrorCode::AllowedRetries(value[eod + 1])),
            0x65 => PcscSw::Error(PcscErrorCode::MemoryFailure(value[eod + 1])),
            0x67 => PcscSw::Error(PcscErrorCode::WrongLength),
            0x68 => PcscSw::Error(PcscErrorCode::WrongClassByte),
            0x69 => PcscSw::Error(PcscErrorCode::CommandImpossible(value[eod + 1])),
            0x6A => PcscSw::Error(PcscErrorCode::CommandError(value[eod + 1])),
            0x6B => PcscSw::Error(PcscErrorCode::WrongParameter),
            0x6C => PcscSw::Error(PcscErrorCode::WrongLengthLe(value[eod + 1])),
            sw1 => PcscSw::Response {
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
            PcscSw::Response { sw1, sw2 } => [sw1, sw2],
            PcscSw::Error(pcsc_error_code) => match pcsc_error_code {
                PcscErrorCode::Warning(sw2) => [0x62, sw2],
                PcscErrorCode::AllowedRetries(sw2) => [0x63, sw2],
                PcscErrorCode::MemoryFailure(sw2) => [0x65, sw2],
                PcscErrorCode::WrongLength => [0x67, 0x00],
                PcscErrorCode::WrongClassByte => [0x68, 0x00],
                PcscErrorCode::CommandImpossible(sw2) => [0x69, sw2],
                PcscErrorCode::CommandError(sw2) => [0x6A, sw2],
                PcscErrorCode::WrongParameter => [0x6B, 0x00],
                PcscErrorCode::WrongLengthLe(sw2) => [0x6C, sw2],
            },
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

    fn authentication(block_number: u8, key_type: KeyType, key_number: u8) -> [u8; 10] {
        [
            // Class
            0xff,
            // INS (authentication)
            0x86,
            // P1
            0x00,
            // P2
            0x00,
            // Lc
            0x05,
            // Version
            0x01,
            0x00,
            block_number,
            key_type as u8,
            key_number,
        ]
    }

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
        let bytes: Vec<u8> = input.into();
        assert_eq!(bytes, expected);
    }
}
