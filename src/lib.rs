// use std::ffi::{CStr, CString};

use pcsc::{
    Card, Context, Error, Protocols, ReaderState, Scope, ShareMode, State, PNP_NOTIFICATION,
};

// const ACR_122_NAME: &CStr = c"acr122";
// const ACR_125_NAME: &CStr = c"acr125";

#[derive(Clone, Copy)]
enum TagType {
    Iso14443_3,
    Unknown,
}

#[repr(u8)]
enum KeyType {
    A = 0x60,
    B = 0x61,
}

pub struct RfidTag {
    tag_type: TagType,
    card: Card,
}

impl RfidTag {
    fn tag_type(&self) -> TagType {
        self.tag_type
    }

    fn read(&self) -> Result<Vec<u8>, Error> {
        // TODO: check
        let mut buf = [0u8; 1024];
        self.card.transmit(&get_data(), &mut buf)?;
        if u16::from_be_bytes(buf[0..2].try_into().unwrap()) != 9000 {}
        Ok(vec![])
    }
}

pub struct Reader {
    context: Context,
    state: [ReaderState; 1],
    is_alive: bool,
}

impl Reader {
    fn get_card(&mut self) -> Result<Option<RfidTag>, Error> {
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

    fn state(&self) -> State {
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

    fn get_readers(&mut self) -> Result<Vec<Reader>, Error> {
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

fn get_data() -> [u8; 5] {
    [0xff, 0xca, 0x00, 0x00, 0x00]
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum PcscInstruction {
    GetData = 0xCA,
    LoadKeys = 0x82,
    // Obsolete
    // Authenticate = 0x88,
    GeneralAuthenticate = 0x86,
    Verify = 0x20,
    ReadBinary = 0xB0,
    UpdateBinary = 0xD6,
}

// enum PcscErrorCode {
//     ResponseCorrupted = 0x6281, // warning
//     UnexpectedEndOfData = 0x6282, // warning
//     NoInformationGiven = 0x6300, // warning
//     MemoryP1P2Error = 0x6581,
//     CommandIncompatible = 0x6981,
//     SecurityStatusUnsatisfied = 0x6982,
//     // CardKeyNotSupported = 0x6982,
//     ReaderKeyNotSupported = 0x6983,
//     PlainTransmissionNotSupported = 0x6984,
//     SecuredTransmissionNotSupported = 0x6985,
//     VolatileMemoryUnavailable = 0x6986,
//     NonVolatileMemoryUnavailable = 0x6987,
//     KeyNumberNotValid = 0x6988,
//     KeyLengthNotValue = 0x6989,
//     FunctionNotSupported = 0x6A81,
//     FileNotFound = 0x6A82,
// }

#[derive(Debug, Clone, Copy, PartialEq)]
enum Sw1ErrorCode {
    Warning = 0x62,
    NoInformation = 0x63,
    MemoryFailure = 0x65,
    WrongLength = 0x67,
    WrongClassByte = 0x68,
    CommandImpossible = 0x69,
    CommandError = 0x6A,
    WrongParameter = 0x6B,
    WrongLengthLe = 0x6C,
}

#[derive(Debug, PartialEq)]
struct PcscCommand {
    ins: PcscInstruction,
    p1: u8,
    p2: u8,
    le: Option<u8>,
    data: Vec<u8>,
}

struct PcscResponse {
    data: Vec<u8>,
    // TODO: non-errors also appear here
    sw1: Sw1ErrorCode,
    sw2: u8,
}

impl TryFrom<&[u8]> for PcscCommand {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes = value.as_ref();
        if bytes.len() < 4 {
            // bail
        }
        if bytes[0] != 0xFF {
            // bail
        }
        let p1 = bytes[2];
        let p2 = bytes[3];
        let (ins, le, data) = match bytes[1] {
            0xCA => (PcscInstruction::GetData, Some(bytes[4]), vec![]),
            // TODO: check length
            0x82 => (PcscInstruction::LoadKeys, None, bytes[5..].to_vec()),
            // TODO: check fixed length 5
            0x86 => (
                PcscInstruction::GeneralAuthenticate,
                None,
                bytes[5..].to_vec(),
            ),
            // TODO: check length
            0x20 => (PcscInstruction::Verify, None, bytes[5..].to_vec()),
            0xB0 => (PcscInstruction::ReadBinary, Some(bytes[4]), vec![]),
            // TODO: check length
            0xD6 => (PcscInstruction::UpdateBinary, None, bytes[5..].to_vec()),
            _ => todo!(),
        };
        Ok(Self {
            ins,
            p1,
            p2,
            le,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
        
    #[test]
    fn test_get_data_from_u8() {
        let expected = PcscCommand {
            ins: PcscInstruction::GetData,
            p1: 0,
            p2: 0,
            le: Some(0),
            data: vec![],
        };
        let get_data = get_data();
        let command = PcscCommand::try_from(&get_data[..]).unwrap();
        assert_eq!(command, expected);
    }
}
