//! TLV8 encoding, ported from `fake_atv.py` (`read_tlv`/`write_tlv`).

use std::collections::BTreeMap;

/// TLV8 value tags used by Companion pairing (mirrors `TlvValue`).
pub mod tags {
    pub const METHOD: u8 = 0x00;
    pub const IDENTIFIER: u8 = 0x01;
    pub const SALT: u8 = 0x02;
    pub const PUBLIC_KEY: u8 = 0x03;
    pub const PROOF: u8 = 0x04;
    pub const ENCRYPTED_DATA: u8 = 0x05;
    pub const SEQ_NO: u8 = 0x06;
    pub const ERROR: u8 = 0x07;
    pub const SIGNATURE: u8 = 0x0A;
}

/// Read TLV8 data. Repeated tags (values longer than 255 bytes) are merged
/// by concatenation, exactly like Python's `read_tlv`.
pub fn read(data: &[u8]) -> BTreeMap<u8, Vec<u8>> {
    let mut result: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    let mut pos = 0;
    while pos + 2 <= data.len() {
        let tag = data[pos];
        let length = data[pos + 1] as usize;
        let end = (pos + 2 + length).min(data.len());
        result
            .entry(tag)
            .or_default()
            .extend_from_slice(&data[pos + 2..end]);
        pos += 2 + length;
    }
    result
}

/// Write TLV8 data, splitting values longer than 255 bytes into repeated
/// tags, exactly like Python's `write_tlv`.
pub fn write(entries: &[(u8, &[u8])]) -> Vec<u8> {
    let mut output = Vec::new();
    for (tag, value) in entries {
        let mut pos = 0;
        while pos < value.len() {
            let chunk = &value[pos..(pos + 255).min(value.len())];
            output.push(*tag);
            output.push(chunk.len() as u8);
            output.extend_from_slice(chunk);
            pos += chunk.len();
        }
    }
    output
}
