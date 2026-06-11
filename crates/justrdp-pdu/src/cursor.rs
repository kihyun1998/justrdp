//! `ReadCursor` — a zero-copy, position-tracking reader over a byte slice (plan.md §2). Every
//! read is length-checked and returns [`DecodeError::NotEnoughBytes`] on underflow rather than
//! panicking, so partial frames surface as the sans-IO "wait for more bytes" signal. Little-endian
//! is the default (RDP's wire default); big-endian variants carry the `_be` suffix.
//!
//! Read-side only for now; `WriteCursor` and the object-safe `Encode`/`Decode` traits (plan.md §2)
//! arrive when an encoding path needs them.

use crate::error::DecodeError;

/// A cursor reading forward through `buf`, tagging underflow errors with `context`.
#[derive(Debug, Clone)]
pub struct ReadCursor<'a> {
    buf: &'a [u8],
    pos: usize,
    context: &'static str,
}

impl<'a> ReadCursor<'a> {
    /// Create a cursor over `buf`. `context` labels any `NotEnoughBytes` error (e.g. the PDU name).
    pub fn new(buf: &'a [u8], context: &'static str) -> Self {
        Self {
            buf,
            pos: 0,
            context,
        }
    }

    /// The number of bytes already consumed.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The number of bytes left to read.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Ensure at least `size` bytes remain, or return `NotEnoughBytes`.
    fn ensure(&self, size: usize) -> Result<(), DecodeError> {
        if self.remaining() < size {
            return Err(DecodeError::NotEnoughBytes {
                context: self.context,
                needed: size,
                got: self.remaining(),
            });
        }
        Ok(())
    }

    /// Read one byte, advancing the cursor.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        self.ensure(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Read a little-endian `u16`, advancing the cursor 2 bytes.
    pub fn read_u16_le(&mut self) -> Result<u16, DecodeError> {
        self.ensure(2)?;
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Read a big-endian `u16`, advancing the cursor 2 bytes.
    pub fn read_u16_be(&mut self) -> Result<u16, DecodeError> {
        self.ensure(2)?;
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Read a little-endian `u32`, advancing the cursor 4 bytes.
    pub fn read_u32_le(&mut self) -> Result<u32, DecodeError> {
        self.ensure(4)?;
        let v = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Read a big-endian `u32`, advancing the cursor 4 bytes.
    pub fn read_u32_be(&mut self) -> Result<u32, DecodeError> {
        self.ensure(4)?;
        let v = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Read the next `len` bytes as a borrowed slice, advancing the cursor.
    pub fn read_slice(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        self.ensure(len)?;
        let s = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }

    /// Return the next byte without advancing the cursor.
    pub fn peek_u8(&self) -> Result<u8, DecodeError> {
        self.ensure(1)?;
        Ok(self.buf[self.pos])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_u32_le_reads_four_bytes() {
        let mut c = ReadCursor::new(&[0x0B, 0x00, 0x00, 0x00], "t");
        assert_eq!(c.read_u32_le().unwrap(), 0x0000_000B);
        assert!(matches!(
            c.read_u32_le().unwrap_err(),
            DecodeError::NotEnoughBytes {
                needed: 4,
                got: 0,
                ..
            }
        ));
    }

    #[test]
    fn read_slice_borrows_bytes_and_advances() {
        let mut c = ReadCursor::new(&[0xAA, 0xBB, 0xCC, 0xDD], "t");
        assert_eq!(c.read_slice(3).unwrap(), &[0xAA, 0xBB, 0xCC]);
        assert_eq!(c.position(), 3);
        assert!(matches!(
            c.read_slice(2).unwrap_err(),
            DecodeError::NotEnoughBytes {
                needed: 2,
                got: 1,
                ..
            }
        ));
    }

    #[test]
    fn peek_u8_reads_without_advancing() {
        let mut c = ReadCursor::new(&[0xD0, 0xE0], "t");
        assert_eq!(c.peek_u8().unwrap(), 0xD0);
        assert_eq!(c.position(), 0);
        assert_eq!(c.read_u8().unwrap(), 0xD0);
        let empty = ReadCursor::new(&[], "t");
        assert!(matches!(
            empty.peek_u8().unwrap_err(),
            DecodeError::NotEnoughBytes {
                needed: 1,
                got: 0,
                ..
            }
        ));
    }

    #[test]
    fn read_u16_le_and_be_read_in_their_byte_orders() {
        let mut c = ReadCursor::new(&[0x01, 0x02, 0x03, 0x04], "t");
        assert_eq!(c.read_u16_le().unwrap(), 0x0201);
        assert_eq!(c.read_u16_be().unwrap(), 0x0304);
        assert!(matches!(
            c.read_u16_le().unwrap_err(),
            DecodeError::NotEnoughBytes {
                needed: 2,
                got: 0,
                ..
            }
        ));
    }

    #[test]
    fn read_u8_returns_each_byte_then_underflows() {
        let mut c = ReadCursor::new(&[0xAB, 0xCD], "test");
        assert_eq!(c.read_u8().unwrap(), 0xAB);
        assert_eq!(c.position(), 1);
        assert_eq!(c.read_u8().unwrap(), 0xCD);
        assert_eq!(c.position(), 2);
        assert_eq!(c.remaining(), 0);
        assert_eq!(
            c.read_u8().unwrap_err(),
            DecodeError::NotEnoughBytes {
                context: "test",
                needed: 1,
                got: 0,
            }
        );
    }
}
