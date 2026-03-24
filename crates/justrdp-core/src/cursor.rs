#![forbid(unsafe_code)]

use crate::error::{DecodeError, DecodeResult, EncodeError, EncodeResult};

/// A zero-copy read cursor over a byte slice.
///
/// Tracks the current read position and provides methods to read
/// primitive types in little-endian byte order (RDP default).
#[derive(Debug)]
pub struct ReadCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ReadCursor<'a> {
    /// Create a new read cursor over the given byte slice.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Returns the total length of the underlying slice.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the underlying slice is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the current read position.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the number of bytes remaining to read.
    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    /// Returns the remaining bytes as a slice without advancing the cursor.
    pub fn peek_remaining(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    /// Ensure that at least `n` bytes are available.
    fn ensure(&self, n: usize, context: &'static str) -> DecodeResult<()> {
        if self.remaining() < n {
            Err(DecodeError::not_enough_bytes(
                context,
                n,
                self.remaining(),
            ))
        } else {
            Ok(())
        }
    }

    /// Read a byte slice of length `n` and advance the cursor.
    pub fn read_slice(&mut self, n: usize, context: &'static str) -> DecodeResult<&'a [u8]> {
        self.ensure(n, context)?;
        let slice = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read a `u8` and advance the cursor.
    pub fn read_u8(&mut self, context: &'static str) -> DecodeResult<u8> {
        self.ensure(1, context)?;
        let val = self.bytes[self.pos];
        self.pos += 1;
        Ok(val)
    }

    /// Read a little-endian `u16` and advance the cursor.
    pub fn read_u16_le(&mut self, context: &'static str) -> DecodeResult<u16> {
        self.ensure(2, context)?;
        let val = u16::from_le_bytes([self.bytes[self.pos], self.bytes[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    /// Read a big-endian `u16` and advance the cursor.
    pub fn read_u16_be(&mut self, context: &'static str) -> DecodeResult<u16> {
        self.ensure(2, context)?;
        let val = u16::from_be_bytes([self.bytes[self.pos], self.bytes[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    /// Read a little-endian `u32` and advance the cursor.
    pub fn read_u32_le(&mut self, context: &'static str) -> DecodeResult<u32> {
        self.ensure(4, context)?;
        let val = u32::from_le_bytes([
            self.bytes[self.pos],
            self.bytes[self.pos + 1],
            self.bytes[self.pos + 2],
            self.bytes[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    /// Read a big-endian `u32` and advance the cursor.
    pub fn read_u32_be(&mut self, context: &'static str) -> DecodeResult<u32> {
        self.ensure(4, context)?;
        let val = u32::from_be_bytes([
            self.bytes[self.pos],
            self.bytes[self.pos + 1],
            self.bytes[self.pos + 2],
            self.bytes[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    /// Read a little-endian `u64` and advance the cursor.
    pub fn read_u64_le(&mut self, context: &'static str) -> DecodeResult<u64> {
        self.ensure(8, context)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.bytes[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(buf))
    }

    /// Read a little-endian `i16` and advance the cursor.
    pub fn read_i16_le(&mut self, context: &'static str) -> DecodeResult<i16> {
        self.ensure(2, context)?;
        let val = i16::from_le_bytes([self.bytes[self.pos], self.bytes[self.pos + 1]]);
        self.pos += 2;
        Ok(val)
    }

    /// Read a little-endian `i32` and advance the cursor.
    pub fn read_i32_le(&mut self, context: &'static str) -> DecodeResult<i32> {
        self.ensure(4, context)?;
        let val = i32::from_le_bytes([
            self.bytes[self.pos],
            self.bytes[self.pos + 1],
            self.bytes[self.pos + 2],
            self.bytes[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(val)
    }

    /// Skip `n` bytes without reading them.
    pub fn skip(&mut self, n: usize, context: &'static str) -> DecodeResult<()> {
        self.ensure(n, context)?;
        self.pos += n;
        Ok(())
    }

    /// Peek at the next byte without advancing the cursor.
    pub fn peek_u8(&self, context: &'static str) -> DecodeResult<u8> {
        self.ensure(1, context)?;
        Ok(self.bytes[self.pos])
    }

    /// Peek at the next two bytes as a little-endian `u16` without advancing.
    pub fn peek_u16_le(&self, context: &'static str) -> DecodeResult<u16> {
        self.ensure(2, context)?;
        Ok(u16::from_le_bytes([
            self.bytes[self.pos],
            self.bytes[self.pos + 1],
        ]))
    }
}

/// A write cursor over a mutable byte slice.
///
/// Tracks the current write position and provides methods to write
/// primitive types in little-endian byte order (RDP default).
#[derive(Debug)]
pub struct WriteCursor<'a> {
    bytes: &'a mut [u8],
    pos: usize,
}

impl<'a> WriteCursor<'a> {
    /// Create a new write cursor over the given mutable byte slice.
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Returns the total length of the underlying slice.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the underlying slice is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the current write position (number of bytes written).
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the number of bytes remaining to write.
    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    /// Ensure that at least `n` bytes are available for writing.
    fn ensure(&self, n: usize, context: &'static str) -> EncodeResult<()> {
        if self.remaining() < n {
            Err(EncodeError::not_enough_space(
                context,
                n,
                self.remaining(),
            ))
        } else {
            Ok(())
        }
    }

    /// Write a byte slice and advance the cursor.
    pub fn write_slice(&mut self, data: &[u8], context: &'static str) -> EncodeResult<()> {
        self.ensure(data.len(), context)?;
        self.bytes[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }

    /// Write a `u8` and advance the cursor.
    pub fn write_u8(&mut self, val: u8, context: &'static str) -> EncodeResult<()> {
        self.ensure(1, context)?;
        self.bytes[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    /// Write a little-endian `u16` and advance the cursor.
    pub fn write_u16_le(&mut self, val: u16, context: &'static str) -> EncodeResult<()> {
        self.ensure(2, context)?;
        let bytes = val.to_le_bytes();
        self.bytes[self.pos] = bytes[0];
        self.bytes[self.pos + 1] = bytes[1];
        self.pos += 2;
        Ok(())
    }

    /// Write a big-endian `u16` and advance the cursor.
    pub fn write_u16_be(&mut self, val: u16, context: &'static str) -> EncodeResult<()> {
        self.ensure(2, context)?;
        let bytes = val.to_be_bytes();
        self.bytes[self.pos] = bytes[0];
        self.bytes[self.pos + 1] = bytes[1];
        self.pos += 2;
        Ok(())
    }

    /// Write a little-endian `u32` and advance the cursor.
    pub fn write_u32_le(&mut self, val: u32, context: &'static str) -> EncodeResult<()> {
        self.ensure(4, context)?;
        let bytes = val.to_le_bytes();
        self.bytes[self.pos..self.pos + 4].copy_from_slice(&bytes);
        self.pos += 4;
        Ok(())
    }

    /// Write a big-endian `u32` and advance the cursor.
    pub fn write_u32_be(&mut self, val: u32, context: &'static str) -> EncodeResult<()> {
        self.ensure(4, context)?;
        let bytes = val.to_be_bytes();
        self.bytes[self.pos..self.pos + 4].copy_from_slice(&bytes);
        self.pos += 4;
        Ok(())
    }

    /// Write a little-endian `u64` and advance the cursor.
    pub fn write_u64_le(&mut self, val: u64, context: &'static str) -> EncodeResult<()> {
        self.ensure(8, context)?;
        let bytes = val.to_le_bytes();
        self.bytes[self.pos..self.pos + 8].copy_from_slice(&bytes);
        self.pos += 8;
        Ok(())
    }

    /// Write a little-endian `i16` and advance the cursor.
    pub fn write_i16_le(&mut self, val: i16, context: &'static str) -> EncodeResult<()> {
        self.ensure(2, context)?;
        let bytes = val.to_le_bytes();
        self.bytes[self.pos] = bytes[0];
        self.bytes[self.pos + 1] = bytes[1];
        self.pos += 2;
        Ok(())
    }

    /// Write a little-endian `i32` and advance the cursor.
    pub fn write_i32_le(&mut self, val: i32, context: &'static str) -> EncodeResult<()> {
        self.ensure(4, context)?;
        let bytes = val.to_le_bytes();
        self.bytes[self.pos..self.pos + 4].copy_from_slice(&bytes);
        self.pos += 4;
        Ok(())
    }

    /// Write `n` zero bytes and advance the cursor.
    pub fn write_zeros(&mut self, n: usize, context: &'static str) -> EncodeResult<()> {
        self.ensure(n, context)?;
        for i in 0..n {
            self.bytes[self.pos + i] = 0;
        }
        self.pos += n;
        Ok(())
    }

    /// Skip `n` bytes without writing (leaves current content unchanged).
    pub fn skip(&mut self, n: usize, context: &'static str) -> EncodeResult<()> {
        self.ensure(n, context)?;
        self.pos += n;
        Ok(())
    }
}
