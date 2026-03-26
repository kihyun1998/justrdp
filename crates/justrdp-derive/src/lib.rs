//! Derive macros for JustRDP `Encode` and `Decode` traits.
//!
//! # Usage
//!
//! ```rust,ignore
//! use justrdp_derive::{Encode, Decode};
//!
//! #[derive(Encode, Decode)]
//! pub struct MyPdu {
//!     #[pdu(u16_le)]
//!     pub field_a: u16,
//!     #[pdu(u32_le)]
//!     pub field_b: u32,
//!     #[pdu(u8)]
//!     pub field_c: u8,
//! }
//! ```
//!
//! ## Supported field attributes
//!
//! | Attribute | Size |
//! |-----------|------|
//! | `#[pdu(u8)]` | 1 |
//! | `#[pdu(u16_le)]` / `#[pdu(u16_be)]` | 2 |
//! | `#[pdu(u32_le)]` / `#[pdu(u32_be)]` | 4 |
//! | `#[pdu(u64_le)]` | 8 |
//! | `#[pdu(i16_le)]` / `#[pdu(i32_le)]` | 2 / 4 |
//! | `#[pdu(bytes = N)]` | N (fixed array) |
//! | `#[pdu(rest)]` | dynamic (Vec<u8>) |
//! | `#[pdu(pad = N)]` | N (zeros on encode, skip on decode). Field type must impl `Default`. Use `()` for padding fields. |

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, LitInt};

/// Parsed `#[pdu(...)]` attribute.
#[derive(Debug)]
enum FieldKind {
    U8,
    U16Le,
    U16Be,
    U32Le,
    U32Be,
    U64Le,
    I16Le,
    I32Le,
    Bytes(usize),
    Rest,
    Pad(usize),
}

fn parse_pdu_attr(field: &syn::Field) -> Option<FieldKind> {
    for attr in &field.attrs {
        if !attr.path().is_ident("pdu") {
            continue;
        }

        let mut result = None;

        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("u8") { result = Some(FieldKind::U8); return Ok(()); }
            if meta.path.is_ident("u16_le") { result = Some(FieldKind::U16Le); return Ok(()); }
            if meta.path.is_ident("u16_be") { result = Some(FieldKind::U16Be); return Ok(()); }
            if meta.path.is_ident("u32_le") { result = Some(FieldKind::U32Le); return Ok(()); }
            if meta.path.is_ident("u32_be") { result = Some(FieldKind::U32Be); return Ok(()); }
            if meta.path.is_ident("u64_le") { result = Some(FieldKind::U64Le); return Ok(()); }
            if meta.path.is_ident("i16_le") { result = Some(FieldKind::I16Le); return Ok(()); }
            if meta.path.is_ident("i32_le") { result = Some(FieldKind::I32Le); return Ok(()); }
            if meta.path.is_ident("rest") { result = Some(FieldKind::Rest); return Ok(()); }
            if meta.path.is_ident("bytes") {
                let value = meta.value()?;
                let lit: LitInt = value.parse()?;
                let n: usize = lit.base10_parse()?;
                result = Some(FieldKind::Bytes(n));
                return Ok(());
            }
            if meta.path.is_ident("pad") {
                let value = meta.value()?;
                let lit: LitInt = value.parse()?;
                let n: usize = lit.base10_parse()?;
                result = Some(FieldKind::Pad(n));
                return Ok(());
            }
            Err(meta.error("unknown pdu attribute"))
        });

        if result.is_some() {
            return result;
        }
    }
    None
}

/// Derive `Encode` for a struct with `#[pdu(...)]` field attributes.
#[proc_macro_derive(Encode, attributes(pdu))]
pub fn derive_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let name_str = name.to_string();

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("Encode derive only supports named fields"),
        },
        _ => panic!("Encode derive only supports structs"),
    };

    let mut encode_stmts = Vec::new();
    let mut size_stmts = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let ctx = format!("{}::{}", name_str, field_name);

        let kind = parse_pdu_attr(field)
            .unwrap_or_else(|| panic!("Field `{}` in `{}` is missing #[pdu(...)] attribute", field_name, name_str));

        match kind {
            FieldKind::U8 => {
                encode_stmts.push(quote! { dst.write_u8(self.#field_name, #ctx)?; });
                size_stmts.push(quote! { 1 });
            }
            FieldKind::U16Le => {
                encode_stmts.push(quote! { dst.write_u16_le(self.#field_name, #ctx)?; });
                size_stmts.push(quote! { 2 });
            }
            FieldKind::U16Be => {
                encode_stmts.push(quote! { dst.write_u16_be(self.#field_name, #ctx)?; });
                size_stmts.push(quote! { 2 });
            }
            FieldKind::U32Le => {
                encode_stmts.push(quote! { dst.write_u32_le(self.#field_name, #ctx)?; });
                size_stmts.push(quote! { 4 });
            }
            FieldKind::U32Be => {
                encode_stmts.push(quote! { dst.write_u32_be(self.#field_name, #ctx)?; });
                size_stmts.push(quote! { 4 });
            }
            FieldKind::U64Le => {
                encode_stmts.push(quote! { dst.write_u64_le(self.#field_name, #ctx)?; });
                size_stmts.push(quote! { 8 });
            }
            FieldKind::I16Le => {
                encode_stmts.push(quote! { dst.write_i16_le(self.#field_name, #ctx)?; });
                size_stmts.push(quote! { 2 });
            }
            FieldKind::I32Le => {
                encode_stmts.push(quote! { dst.write_i32_le(self.#field_name, #ctx)?; });
                size_stmts.push(quote! { 4 });
            }
            FieldKind::Bytes(n) => {
                encode_stmts.push(quote! { dst.write_slice(&self.#field_name, #ctx)?; });
                size_stmts.push(quote! { #n });
            }
            FieldKind::Rest => {
                encode_stmts.push(quote! { dst.write_slice(&self.#field_name, #ctx)?; });
                size_stmts.push(quote! { self.#field_name.len() });
            }
            FieldKind::Pad(n) => {
                encode_stmts.push(quote! { dst.write_zeros(#n, #ctx)?; });
                size_stmts.push(quote! { #n });
            }
        }
    }

    let expanded = quote! {
        impl justrdp_core::Encode for #name {
            fn encode(&self, dst: &mut justrdp_core::WriteCursor<'_>) -> justrdp_core::EncodeResult<()> {
                #(#encode_stmts)*
                Ok(())
            }

            fn name(&self) -> &'static str {
                #name_str
            }

            fn size(&self) -> usize {
                0 #(+ #size_stmts)*
            }
        }
    };

    TokenStream::from(expanded)
}

/// Derive `Decode<'de>` for a struct with `#[pdu(...)]` field attributes.
#[proc_macro_derive(Decode, attributes(pdu))]
pub fn derive_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let name_str = name.to_string();

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("Decode derive only supports named fields"),
        },
        _ => panic!("Decode derive only supports structs"),
    };

    let mut decode_stmts = Vec::new();
    let mut field_names = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let ctx = format!("{}::{}", name_str, field_name);

        let kind = parse_pdu_attr(field)
            .unwrap_or_else(|| panic!("Field `{}` in `{}` is missing #[pdu(...)] attribute", field_name, name_str));

        field_names.push(field_name.clone());

        match kind {
            FieldKind::U8 => {
                decode_stmts.push(quote! { let #field_name = src.read_u8(#ctx)?; });
            }
            FieldKind::U16Le => {
                decode_stmts.push(quote! { let #field_name = src.read_u16_le(#ctx)?; });
            }
            FieldKind::U16Be => {
                decode_stmts.push(quote! { let #field_name = src.read_u16_be(#ctx)?; });
            }
            FieldKind::U32Le => {
                decode_stmts.push(quote! { let #field_name = src.read_u32_le(#ctx)?; });
            }
            FieldKind::U32Be => {
                decode_stmts.push(quote! { let #field_name = src.read_u32_be(#ctx)?; });
            }
            FieldKind::U64Le => {
                decode_stmts.push(quote! { let #field_name = src.read_u64_le(#ctx)?; });
            }
            FieldKind::I16Le => {
                decode_stmts.push(quote! { let #field_name = src.read_i16_le(#ctx)?; });
            }
            FieldKind::I32Le => {
                decode_stmts.push(quote! { let #field_name = src.read_i32_le(#ctx)?; });
            }
            FieldKind::Bytes(n) => {
                decode_stmts.push(quote! {
                    let #field_name = {
                        let slice = src.read_slice(#n, #ctx)?;
                        let mut arr = [0u8; #n];
                        arr.copy_from_slice(slice);
                        arr
                    };
                });
            }
            FieldKind::Rest => {
                decode_stmts.push(quote! {
                    let #field_name = {
                        let remaining = src.remaining();
                        src.read_slice(remaining, #ctx)?.to_vec()
                    };
                });
            }
            FieldKind::Pad(n) => {
                decode_stmts.push(quote! {
                    src.skip(#n, #ctx)?;
                    let #field_name = Default::default();
                });
            }
        }
    }

    let expanded = quote! {
        impl<'de> justrdp_core::Decode<'de> for #name {
            fn decode(src: &mut justrdp_core::ReadCursor<'de>) -> justrdp_core::DecodeResult<Self> {
                #(#decode_stmts)*
                Ok(Self {
                    #(#field_names),*
                })
            }
        }
    };

    TokenStream::from(expanded)
}
