#![forbid(unsafe_code)]

//! RFX tile management (MS-RDPRFX §2.2.2.3.4.1).

use alloc::vec::Vec;
use super::quant::CodecQuant;

/// A single RFX tile (64×64 pixels).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfxTile {
    /// Tile X position in the screen tile grid (pixel_x / 64).
    pub x_idx: u16,
    /// Tile Y position in the screen tile grid (pixel_y / 64).
    pub y_idx: u16,
    /// RLGR-encoded Y component data.
    pub y_data: Vec<u8>,
    /// RLGR-encoded Cb component data.
    pub cb_data: Vec<u8>,
    /// RLGR-encoded Cr component data.
    pub cr_data: Vec<u8>,
    /// Index into the quantization table for Y.
    pub quant_idx_y: u8,
    /// Index into the quantization table for Cb.
    pub quant_idx_cb: u8,
    /// Index into the quantization table for Cr.
    pub quant_idx_cr: u8,
}

/// A set of RFX tiles with shared quantization tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RfxTileSet {
    /// Quantization tables.
    pub quant_vals: Vec<CodecQuant>,
    /// Tiles in this set.
    pub tiles: Vec<RfxTile>,
}

impl RfxTileSet {
    /// Look up quantization tables for a tile by its quant indices.
    ///
    /// Returns `None` if any index is out of bounds.
    pub fn quant_for_tile(&self, tile: &RfxTile) -> Option<(&CodecQuant, &CodecQuant, &CodecQuant)> {
        let y = self.quant_vals.get(tile.quant_idx_y as usize)?;
        let cb = self.quant_vals.get(tile.quant_idx_cb as usize)?;
        let cr = self.quant_vals.get(tile.quant_idx_cr as usize)?;
        Some((y, cb, cr))
    }
}
