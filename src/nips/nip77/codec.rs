//! The Negentropy V1 binary codec: varints, bound encoding and message
//! parsing. The reconciliation logic lives in `super`.

use super::{Bound, Mode, PROTOCOL_VERSION, Range};

/// Base-128 varints, most significant digit first.
pub(crate) fn write_varint(out: &mut [u8], mut value: u64) -> usize {
    // Most significant base-128 digit first; high bit set on all but the last.
    let mut digits = [0u8; 10];
    let mut n = 0;
    loop {
        digits[n] = (value & 0x7f) as u8;
        value >>= 7;
        n += 1;
        if value == 0 {
            break;
        }
    }
    for (i, &d) in digits[..n].iter().rev().enumerate() {
        out[i] = if i + 1 == n { d } else { d | 0x80 };
    }
    n
}

pub(crate) fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value = 0u64;
    loop {
        let b = *data
            .get(*pos)
            .ok_or_else(|| "truncated varint".to_string())?;
        *pos += 1;
        value = value
            .checked_mul(128)
            .and_then(|v| v.checked_add((b & 0x7f) as u64))
            .ok_or_else(|| "varint overflow".to_string())?;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
}

// ----- bound encoding -----

/// Encodes a bound. `prev_ts` tracks the offset delta encoding.
pub(crate) fn write_bound(out: &mut Vec<u8>, bound: &Bound, prev_ts: &mut u64) {
    let encoded = if bound.ts == u64::MAX {
        0
    } else {
        1 + (bound.ts.saturating_sub(*prev_ts))
    };
    *prev_ts = bound.ts;
    let mut buf = [0u8; 10];
    let n = write_varint(&mut buf, encoded);
    out.extend_from_slice(&buf[..n]);
    let n = write_varint(&mut buf, bound.prefix.len() as u64);
    out.extend_from_slice(&buf[..n]);
    out.extend_from_slice(&bound.prefix);
}

pub(crate) fn read_bound(data: &[u8], pos: &mut usize, prev_ts: &mut u64) -> Result<Bound, String> {
    let encoded = read_varint(data, pos)?;
    let ts = if encoded == 0 {
        u64::MAX
    } else {
        prev_ts.saturating_add(encoded - 1)
    };
    *prev_ts = ts;
    let len = read_varint(data, pos)? as usize;
    if len > 32 {
        return Err("bound prefix too long".into());
    }
    let prefix = data
        .get(*pos..*pos + len)
        .ok_or_else(|| "truncated bound prefix".to_string())?
        .to_vec();
    *pos += len;
    Ok(Bound { ts, prefix })
}

// ----- message parsing -----

pub(crate) fn parse_message(data: &[u8]) -> Result<Vec<Range>, String> {
    if data.is_empty() {
        return Err("empty message".into());
    }
    if data[0] != PROTOCOL_VERSION {
        return Err("unsupported protocol version".into());
    }
    let mut pos = 1usize;
    let mut prev_ts = 0u64;
    let mut ranges = Vec::new();
    while pos < data.len() {
        let upper = read_bound(data, &mut pos, &mut prev_ts)?;
        let mode = read_varint(data, &mut pos)?;
        let mode = match mode {
            0 => Mode::Skip,
            1 => {
                let mut fp = [0u8; 16];
                let end = pos + 16;
                let bytes = data
                    .get(pos..end)
                    .ok_or_else(|| "truncated fingerprint".to_string())?;
                fp.copy_from_slice(bytes);
                pos = end;
                Mode::Fingerprint(fp)
            }
            2 => {
                let len = read_varint(data, &mut pos)? as usize;
                if len > 10_000_000 {
                    return Err("id list too long".into());
                }
                let end = pos
                    .checked_add(len * 32)
                    .ok_or_else(|| "id list too long".to_string())?;
                if end > data.len() {
                    return Err("truncated id list".into());
                }
                pos = end;
                Mode::IdList
            }
            other => return Err(format!("unknown mode {other}")),
        };
        ranges.push(Range { upper, mode });
    }
    Ok(ranges)
}
