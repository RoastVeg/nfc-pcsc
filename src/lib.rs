//#![deny(missing_docs)]

//! `nfc-pcsc` - an implementation of the PC/SC workgroup ISO14443 and ISO15693 part 3 spec

pub mod atr;
pub mod command;

use atr::{CardName, Standard, TagType};
use command::{PcscCodecError, PcscCommand, PcscResponse};

use pcsc::{
    Card, Context, Error as PcscError, Protocols, ReaderState, Scope, ShareMode, State,
    PNP_NOTIFICATION,
};

pub struct RfidTag {
    tag_type: Option<TagType>,
    standard: Option<Standard>,
    card_name: Option<CardName>,
    card: Card,
}

impl RfidTag {
    pub fn tag_type(&self) -> Option<TagType> {
        self.tag_type
    }

    pub fn standard(&self) -> Option<Standard> {
        self.standard
    }

    pub fn card_name(&self) -> Option<CardName> {
        self.card_name
    }

    pub fn run_command(&self, command: PcscCommand) -> Result<PcscResponse, PcscCodecError> {
        let response_size = command.expected_response_len();
        let command_bytes: Vec<u8> = command.try_into()?;
        let response_bytes = self
            .send_apdu(&command_bytes, response_size)
            .map_err(PcscCodecError::Pcsc)?;
        let response = PcscResponse::try_from(&response_bytes[..])?;
        Ok(response)
    }

    pub fn send_apdu(&self, apdu: &[u8], response_size: usize) -> Result<Vec<u8>, PcscError> {
        let mut buf = Vec::with_capacity(response_size);
        self.card.transmit(apdu, &mut buf)?;
        Ok(buf)
    }
}

pub struct Reader {
    context: Context,
    state: [ReaderState; 1],
    is_alive: bool,
}

impl Reader {
    pub fn get_card(&mut self) -> Result<Option<RfidTag>, PcscError> {
        if !self.is_alive {
            return Err(PcscError::ReaderUnavailable);
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
                let (tag_type, standard, card_name) = atr::parse_atr(self.state[0].atr());
                Some(RfidTag {
                    tag_type,
                    standard,
                    card_name,
                    card,
                })
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
    pub fn new() -> Result<Self, PcscError> {
        let context = Context::establish(Scope::System)?;
        Ok(Self { context })
    }

    pub fn get_readers(&mut self) -> Result<Vec<Reader>, PcscError> {
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
