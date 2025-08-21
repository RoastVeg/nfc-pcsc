use thiserror::Error;

const STORAGE_CARD_RID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x06];

#[derive(Debug, Error)]
#[error("Unknown")]
pub struct Unknown;

/// Known NFC tag types based on their ATR
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum TagType {
    StorageCard,
    Iso14443_4,
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
#[non_exhaustive]
pub enum Standard {
    NoInformation = 0b0000_0000,
    Iso14443APart1 = 0b0000_0001,
    Iso14443APart2 = 0b0000_0010,
    Iso14443APart3 = 0b0000_0011,
    Iso14443BPart1 = 0b0000_0101,
    Iso14443BPart2 = 0b0000_0110,
    Iso14443BPart3 = 0b0000_0111,
    Iso15693Part1 = 0b0000_1001,
    Iso15693Part2 = 0b0000_1010,
    Iso15693Part3 = 0b0000_1011,
    Iso15693Part4 = 0b0000_1100,
    Iso7816_10I2c = 0b000_1101,
    Iso7816_10I2cExtended = 0b0000_1110,
    Iso7816_10_2Wbp = 0b0000_1111,
    Iso7816_10_3Wbp = 0b0001_0000,
    FeliCa = 0b0001_0001,
    LowFrequencyContactless = 0b0100_0000,
}

impl TryFrom<u8> for Standard {
    type Error = Unknown;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b0000_0000 => Ok(Self::NoInformation),
            0b0000_0001 => Ok(Self::Iso14443APart1),
            0b0000_0010 => Ok(Self::Iso14443APart2),
            0b0000_0011 => Ok(Self::Iso14443APart3),
            0b0000_0101 => Ok(Self::Iso14443BPart1),
            0b0000_0110 => Ok(Self::Iso14443BPart2),
            0b0000_0111 => Ok(Self::Iso14443BPart3),
            0b0000_1001 => Ok(Self::Iso15693Part1),
            0b0000_1010 => Ok(Self::Iso15693Part2),
            0b0000_1011 => Ok(Self::Iso15693Part3),
            0b0000_1100 => Ok(Self::Iso15693Part4),
            0b0000_1101 => Ok(Self::Iso7816_10I2c),
            0b0000_1110 => Ok(Self::Iso7816_10I2cExtended),
            0b0000_1111 => Ok(Self::Iso7816_10_2Wbp),
            0b0001_0000 => Ok(Self::Iso7816_10_3Wbp),
            0b0001_0001 => Ok(Self::FeliCa),
            0b0100_0000 => Ok(Self::LowFrequencyContactless),
            _ => Err(Unknown),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
#[non_exhaustive]
pub enum CardName {
    NoInformation = 0x00_00,
    MifareStandard1K = 0x00_01,
    MifareStandard4K = 0x00_02,
    MifareUltraLight = 0x00_03,
    Sle55R = 0x00_04,
    Sr176 = 0x00_06,
    SriX4K = 0x00_07,
    At88Rr020 = 0x00_08,
    At88Sc0204Crf = 0x00_09,
    At88Sc0808Crf = 0x00_0A,
    At88Sc1616Crf = 0x00_0B,
    At88Sc3216Crf = 0x00_0C,
    At88Sc6416Crf = 0x00_0D,
    Srf55V10P = 0x00_0E,
    Srf55V02P = 0x00_0F,
    Srf55V10S = 0x00_10,
    Srf55V02S = 0x00_11,
    TagIt = 0x00_12,
    Lri512 = 0x00_13,
    ICodeSli = 0x00_14,
    TempSens = 0x00_15,
    ICode1 = 0x00_16,
    PicoPass2K = 0x00_17,
    PicoPass2KS = 0x00_18,
    PicoPass16K = 0x00_19,
    PicoPass16Ks = 0x00_1A,
    PicoPass16K8x2 = 0x00_1B,
    PicoPass16Ks8x2 = 0x00_1C,
    PicoPass32Ks16plus16 = 0x00_1D,
    PicoPass32Ks16plus8x2 = 0x00_1E,
    PicoPass32Ks8x2plus16 = 0x00_1F,
    PicoPass32Ks8x2plus8x2 = 0x00_20,
    Lri64 = 0x00_21,
    ICodeUid = 0x00_22,
    ICodeEpc = 0x00_23,
    Lri12 = 0x00_24,
    Lri128 = 0x00_25,
    MifareMini = 0x00_26,
    MyDMove = 0x00_27,
    MyDNfc = 0x00_28,
    MyDProximity2 = 0x00_29,
    MyDProximityEnhanced = 0x00_2A,
    MyDLight = 0x00_2B,
    PjmStackTag = 0x00_2C,
    PjmItemTag = 0x00_2D,
    PjmLight = 0x00_2E,
    JewelTag = 0x00_2F,
    TopazNfcTag = 0x00_30,
    At88Sc0104Crf = 0x00_31,
    At88Sc0404Crf = 0x00_32,
    At88Rf01C = 0x00_33,
    At88Rf04C = 0x00_34,
    ICodeSl2 = 0x00_35,
    MifarePlusSl1_2K = 0x00_36,
    MifarePlusSl1_4K = 0x00_37,
    MifarePlusSl2_2K = 0x00_38,
    MifarePlusSl2_4K = 0x00_39,
    MifareUltralightC = 0x00_3A,
    FeliCa = 0x00_3B,
    MelexisSensorTag = 0x00_3C,
    MifareUltralightEv1 = 0x00_3D,
}

impl TryFrom<u16> for CardName {
    type Error = Unknown;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x00_00 => Ok(Self::NoInformation),
            0x00_01 => Ok(Self::MifareStandard1K),
            0x00_02 => Ok(Self::MifareStandard4K),
            0x00_03 => Ok(Self::MifareUltraLight),
            0x00_04 => Ok(Self::Sle55R),
            0x00_06 => Ok(Self::Sr176),
            0x00_07 => Ok(Self::SriX4K),
            0x00_08 => Ok(Self::At88Rr020),
            0x00_09 => Ok(Self::At88Sc0204Crf),
            0x00_0A => Ok(Self::At88Sc0808Crf),
            0x00_0B => Ok(Self::At88Sc1616Crf),
            0x00_0C => Ok(Self::At88Sc3216Crf),
            0x00_0D => Ok(Self::At88Sc6416Crf),
            0x00_0E => Ok(Self::Srf55V10P),
            0x00_0F => Ok(Self::Srf55V02P),
            0x00_10 => Ok(Self::Srf55V10S),
            0x00_11 => Ok(Self::Srf55V02S),
            0x00_12 => Ok(Self::TagIt),
            0x00_13 => Ok(Self::Lri512),
            0x00_14 => Ok(Self::ICodeSli),
            0x00_15 => Ok(Self::TempSens),
            0x00_16 => Ok(Self::ICode1),
            0x00_17 => Ok(Self::PicoPass2K),
            0x00_18 => Ok(Self::PicoPass2KS),
            0x00_19 => Ok(Self::PicoPass16K),
            0x00_1A => Ok(Self::PicoPass16Ks),
            0x00_1B => Ok(Self::PicoPass16K8x2),
            0x00_1C => Ok(Self::PicoPass16Ks8x2),
            0x00_1D => Ok(Self::PicoPass32Ks16plus16),
            0x00_1E => Ok(Self::PicoPass32Ks16plus8x2),
            0x00_1F => Ok(Self::PicoPass32Ks8x2plus16),
            0x00_20 => Ok(Self::PicoPass32Ks8x2plus8x2),
            0x00_21 => Ok(Self::Lri64),
            0x00_22 => Ok(Self::ICodeUid),
            0x00_23 => Ok(Self::ICodeEpc),
            0x00_24 => Ok(Self::Lri12),
            0x00_25 => Ok(Self::Lri128),
            0x00_26 => Ok(Self::MifareMini),
            0x00_27 => Ok(Self::MyDMove),
            0x00_28 => Ok(Self::MyDNfc),
            0x00_29 => Ok(Self::MyDProximity2),
            0x00_2A => Ok(Self::MyDProximityEnhanced),
            0x00_2B => Ok(Self::MyDLight),
            0x00_2C => Ok(Self::PjmStackTag),
            0x00_2D => Ok(Self::PjmItemTag),
            0x00_2E => Ok(Self::PjmLight),
            0x00_2F => Ok(Self::JewelTag),
            0x00_30 => Ok(Self::TopazNfcTag),
            0x00_31 => Ok(Self::At88Sc0104Crf),
            0x00_32 => Ok(Self::At88Sc0404Crf),
            0x00_33 => Ok(Self::At88Rf01C),
            0x00_34 => Ok(Self::At88Rf04C),
            0x00_35 => Ok(Self::ICodeSl2),
            0x00_36 => Ok(Self::MifarePlusSl1_2K),
            0x00_37 => Ok(Self::MifarePlusSl1_4K),
            0x00_38 => Ok(Self::MifarePlusSl2_2K),
            0x00_39 => Ok(Self::MifarePlusSl2_4K),
            0x00_3A => Ok(Self::MifareUltralightC),
            0x00_3B => Ok(Self::FeliCa),
            0x00_3C => Ok(Self::MelexisSensorTag),
            0x00_3D => Ok(Self::MifareUltralightEv1),
            _ => Err(Unknown),
        }
    }
}

pub fn parse_atr(atr: &[u8]) -> (Option<TagType>, Option<Standard>, Option<CardName>) {
    match atr.get(0..5) {
        Some([0x3B, len, 0x80, 0x01, 0x80]) => {
            match (len, atr.get(5)) {
                // Storage card per PC/SC spec
                (_, Some(0x4f)) => {
                    if atr.get(7..12) == Some(&STORAGE_CARD_RID) {
                        let standard = atr.get(13).and_then(|ss| Standard::try_from(*ss).ok());
                        let card_name = atr
                            .get(14..15)
                            .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()))
                            .and_then(|nn| CardName::try_from(nn).ok());
                        (Some(TagType::StorageCard), standard, card_name)
                    } else {
                        (Some(TagType::StorageCard), None, None)
                    }
                }
                // Mifare DESFire (multiple)
                (0x81, Some(0x80)) => (Some(TagType::StorageCard), None, None),
                // Uncertain
                _ => (None, None, None),
            }
        }
        // ISO14443-4 card per MSDN and PC/SC spec
        Some([0x3B, _len, 0x80, 0x01, _]) => (Some(TagType::Iso14443_4), None, None),
        _ => (None, None, None),
    }
}
