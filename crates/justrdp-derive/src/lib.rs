#![forbid(unsafe_code)]

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
//! | `#[pdu(bytes = N)]` | N (fixed array `[u8; N]`) |
//! | `#[pdu(rest)]` | dynamic (`Vec<u8>`). **Must be the last field in the struct.** |
//! | `#[pdu(pad = N)]` | N (zeros on encode, skip on decode). Field type must impl `Default`. Use `()` for padding fields. |
//!
//! ## Crate path
//!
//! The generated `impl` blocks reference `justrdp_core::` directly. The consuming
//! crate must have `justrdp-core` as a dependency under its canonical name.

use proc_macro::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Fields, LitInt, parse_macro_input};

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

/// A successfully parsed struct field with its resolved `#[pdu(...)]` kind.
struct ParsedField {
    ident: syn::Ident,
    ctx: String,
    kind: FieldKind,
}

/// Parse a `#[pdu(...)]` attribute on a struct field.
///
/// Returns a compile-time error if:
/// - the field has no `#[pdu(...)]` attribute
/// - the attribute is empty (`#[pdu()]`)
/// - the attribute contains multiple or unrecognized keys
/// - the attribute is syntactically malformed
fn parse_pdu_attr(field: &syn::Field) -> Result<FieldKind, syn::Error> {
    for attr in &field.attrs {
        if !attr.path().is_ident("pdu") {
            continue;
        }

        let mut result = None;

        let parse_result = attr.parse_nested_meta(|meta| {
            // Reject duplicate keys (e.g. `#[pdu(u8, u16_le)]`).
            if result.is_some() {
                return Err(meta.error("only one pdu kind is allowed per field"));
            }

            if meta.path.is_ident("u8") {
                result = Some(FieldKind::U8);
                return Ok(());
            }
            if meta.path.is_ident("u16_le") {
                result = Some(FieldKind::U16Le);
                return Ok(());
            }
            if meta.path.is_ident("u16_be") {
                result = Some(FieldKind::U16Be);
                return Ok(());
            }
            if meta.path.is_ident("u32_le") {
                result = Some(FieldKind::U32Le);
                return Ok(());
            }
            if meta.path.is_ident("u32_be") {
                result = Some(FieldKind::U32Be);
                return Ok(());
            }
            if meta.path.is_ident("u64_le") {
                result = Some(FieldKind::U64Le);
                return Ok(());
            }
            if meta.path.is_ident("i16_le") {
                result = Some(FieldKind::I16Le);
                return Ok(());
            }
            if meta.path.is_ident("i32_le") {
                result = Some(FieldKind::I32Le);
                return Ok(());
            }
            if meta.path.is_ident("rest") {
                result = Some(FieldKind::Rest);
                return Ok(());
            }
            if meta.path.is_ident("bytes") {
                let value = meta.value()?;
                let lit: LitInt = value.parse()?;
                let n: usize = lit.base10_parse()?;
                if n == 0 {
                    return Err(meta.error("bytes value must be > 0"));
                }
                result = Some(FieldKind::Bytes(n));
                return Ok(());
            }
            if meta.path.is_ident("pad") {
                let value = meta.value()?;
                let lit: LitInt = value.parse()?;
                let n: usize = lit.base10_parse()?;
                if n == 0 {
                    return Err(meta.error("pad value must be > 0"));
                }
                result = Some(FieldKind::Pad(n));
                return Ok(());
            }
            Err(meta.error("unknown pdu attribute"))
        });

        // Always propagate parse errors — trailing junk or unknown keys
        // must be rejected even if a valid key was already matched.
        parse_result?;

        // Detect empty attribute: `#[pdu()]`
        if let Some(kind) = result {
            return Ok(kind);
        }

        return Err(syn::Error::new_spanned(
            attr,
            "#[pdu(...)] must not be empty; expected one of: u8, u16_le, u16_be, \
             u32_le, u32_be, u64_le, i16_le, i32_le, bytes = N, rest, pad = N",
        ));
    }

    Err(syn::Error::new(
        field.span(),
        format!(
            "field `{}` is missing #[pdu(...)] attribute",
            field
                .ident
                .as_ref()
                .map(|i| i.to_string())
                .unwrap_or_default()
        ),
    ))
}

/// Extract named fields from a struct [`DeriveInput`], returning a span-anchored
/// compile error for enums, unions, tuple structs, and unit structs.
fn extract_named_fields(
    input: &DeriveInput,
) -> Result<&syn::punctuated::Punctuated<syn::Field, syn::token::Comma>, syn::Error> {
    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => Ok(&fields.named),
            _ => Err(syn::Error::new_spanned(
                &input.ident,
                "derive only supports structs with named fields",
            )),
        },
        _ => Err(syn::Error::new_spanned(
            &input.ident,
            "derive only supports structs",
        )),
    }
}

/// Parse and validate all fields of a struct for derive.
///
/// Iterates named fields, resolves each `#[pdu(...)]` attribute, and enforces
/// that `#[pdu(rest)]` appears only as the last field.
fn parse_fields(input: &DeriveInput) -> Result<Vec<ParsedField>, syn::Error> {
    let fields = extract_named_fields(input)?;
    let name_str = input.ident.to_string();
    let mut parsed = Vec::new();
    let mut rest_seen = false;

    for field in fields {
        let ident = field
            .ident
            .as_ref()
            .expect("named field must have ident — guarded by extract_named_fields")
            .clone();
        let ctx = format!("{name_str}::{ident}");

        let kind = parse_pdu_attr(field)?;

        if rest_seen {
            return Err(syn::Error::new_spanned(
                &ident,
                "no fields are allowed after #[pdu(rest)]",
            ));
        }

        if matches!(kind, FieldKind::Rest) {
            rest_seen = true;
        }

        parsed.push(ParsedField { ident, ctx, kind });
    }

    Ok(parsed)
}

/// Derive `Encode` for a struct with `#[pdu(...)]` field attributes.
#[proc_macro_derive(Encode, attributes(pdu))]
pub fn derive_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let name_str = name.to_string();

    let parsed = match parse_fields(&input) {
        Ok(p) => p,
        Err(e) => return e.to_compile_error().into(),
    };

    let mut encode_stmts = Vec::new();
    let mut size_stmts = Vec::new();

    for ParsedField {
        ident: field_name,
        ctx,
        kind,
    } in &parsed
    {
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
                encode_stmts.push(quote! {
                    assert_eq!(self.#field_name.len(), #n, "pdu(bytes = N): field length must equal N");
                    dst.write_slice(&self.#field_name[..#n], #ctx)?;
                });
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
    let parsed = match parse_fields(&input) {
        Ok(p) => p,
        Err(e) => return e.to_compile_error().into(),
    };

    let mut decode_stmts = Vec::new();
    let mut field_names = Vec::new();

    for ParsedField {
        ident: field_name,
        ctx,
        kind,
    } in &parsed
    {
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
