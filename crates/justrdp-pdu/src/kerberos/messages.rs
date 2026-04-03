#![forbid(unsafe_code)]

//! Kerberos v5 message types (RFC 4120).

use alloc::vec;
use alloc::vec::Vec;

use super::asn1::*;
use super::*;
use justrdp_core::DecodeResult;

fn err_unexpected_msg(msg: &'static str) -> justrdp_core::DecodeError {
    justrdp_core::DecodeError::new(
        "Kerberos",
        justrdp_core::DecodeErrorKind::UnexpectedValue { field: "msg-type", got: msg },
    )
}

// ── Common Types ──

/// PrincipalName ::= SEQUENCE {
///     name-type   [0] Int32,
///     name-string [1] SEQUENCE OF KerberosString
/// }
#[derive(Debug, Clone)]
pub struct PrincipalName {
    pub name_type: i32,
    pub name_string: Vec<Vec<u8>>,
}

impl PrincipalName {
    pub fn new(name_type: i32, names: Vec<Vec<u8>>) -> Self {
        Self {
            name_type,
            name_string: names,
        }
    }

    /// Create an NT-PRINCIPAL name (e.g., "user@REALM").
    pub fn principal(name: &[u8]) -> Self {
        Self::new(NT_PRINCIPAL, vec![name.to_vec()])
    }

    /// Create an NT-SRV-INST name (e.g., "krbtgt/REALM").
    pub fn service(service: &[u8], instance: &[u8]) -> Self {
        Self::new(NT_SRV_INST, vec![service.to_vec(), instance.to_vec()])
    }

    pub fn encode(&self) -> Vec<u8> {
        build_sequence(|w| {
            // [0] name-type
            let t0 = build_context_tag(0, |w| w.write_integer(self.name_type as i64));
            w.write_raw(&t0);
            // [1] name-string SEQUENCE OF GeneralString
            let names = build_sequence(|w| {
                for name in &self.name_string {
                    w.write_general_string(name);
                }
            });
            let t1 = build_context_tag(1, |w| w.write_raw(&names));
            w.write_raw(&t1);
        })
    }

    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut seq = r.read_sequence()?;

        let mut t0 = seq.read_context_tag(0)?;
        let name_type = t0.read_integer()? as i32;

        let mut t1 = seq.read_context_tag(1)?;
        let mut names_seq = t1.read_sequence()?;
        let mut name_string = Vec::new();
        while !names_seq.is_empty() {
            name_string.push(names_seq.read_general_string()?.to_vec());
        }

        Ok(Self {
            name_type,
            name_string,
        })
    }
}

/// EncryptedData ::= SEQUENCE {
///     etype   [0] Int32,
///     kvno    [1] UInt32 OPTIONAL,
///     cipher  [2] OCTET STRING
/// }
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub etype: i32,
    pub kvno: Option<u32>,
    pub cipher: Vec<u8>,
}

impl EncryptedData {
    pub fn new(etype: i32, cipher: Vec<u8>) -> Self {
        Self {
            etype,
            kvno: None,
            cipher,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        build_sequence(|w| {
            let t0 = build_context_tag(0, |w| w.write_integer(self.etype as i64));
            w.write_raw(&t0);
            if let Some(kvno) = self.kvno {
                let t1 = build_context_tag(1, |w| w.write_integer(kvno as i64));
                w.write_raw(&t1);
            }
            let t2 = build_context_tag(2, |w| w.write_octet_string(&self.cipher));
            w.write_raw(&t2);
        })
    }

    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut seq = r.read_sequence()?;

        let mut t0 = seq.read_context_tag(0)?;
        let etype = t0.read_integer()? as i32;

        let kvno = if let Some(mut t1) = seq.read_optional_context_tag(1)? {
            Some(t1.read_integer()? as u32)
        } else {
            None
        };

        let mut t2 = seq.read_context_tag(2)?;
        let cipher = t2.read_octet_string()?.to_vec();

        Ok(Self {
            etype,
            kvno,
            cipher,
        })
    }
}

/// Ticket ::= [APPLICATION 1] SEQUENCE {
///     tkt-vno  [0] INTEGER (5),
///     realm    [1] Realm,
///     sname    [2] PrincipalName,
///     enc-part [3] EncryptedData
/// }
#[derive(Debug, Clone)]
pub struct Ticket {
    pub realm: Vec<u8>,
    pub sname: PrincipalName,
    pub enc_part: EncryptedData,
}

impl Ticket {
    pub fn encode(&self) -> Vec<u8> {
        build_application_tag(1, |w| {
            let inner = build_sequence(|w| {
                // [0] tkt-vno
                let t0 = build_context_tag(0, |w| w.write_integer(KRB5_PVNO));
                w.write_raw(&t0);
                // [1] realm
                let t1 = build_context_tag(1, |w| w.write_general_string(&self.realm));
                w.write_raw(&t1);
                // [2] sname
                let sname_enc = self.sname.encode();
                let t2 = build_context_tag(2, |w| w.write_raw(&sname_enc));
                w.write_raw(&t2);
                // [3] enc-part
                let enc_enc = self.enc_part.encode();
                let t3 = build_context_tag(3, |w| w.write_raw(&enc_enc));
                w.write_raw(&t3);
            });
            w.write_raw(&inner);
        })
    }

    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut app = r.read_application_tag(1)?;
        let mut seq = app.read_sequence()?;

        // [0] tkt-vno
        let mut t0 = seq.read_context_tag(0)?;
        let _vno = t0.read_integer()?;

        // [1] realm
        let mut t1 = seq.read_context_tag(1)?;
        let realm = t1.read_general_string()?.to_vec();

        // [2] sname
        let mut t2 = seq.read_context_tag(2)?;
        let sname_data = t2.read_remaining();
        let sname = PrincipalName::decode(sname_data)?;

        // [3] enc-part
        let mut t3 = seq.read_context_tag(3)?;
        let enc_data = t3.read_remaining();
        let enc_part = EncryptedData::decode(enc_data)?;

        Ok(Self {
            realm,
            sname,
            enc_part,
        })
    }
}

/// PA-DATA ::= SEQUENCE {
///     padata-type  [1] Int32,
///     padata-value [2] OCTET STRING
/// }
#[derive(Debug, Clone)]
pub struct PaData {
    pub padata_type: i32,
    pub padata_value: Vec<u8>,
}

impl PaData {
    pub fn new(padata_type: i32, padata_value: Vec<u8>) -> Self {
        Self {
            padata_type,
            padata_value,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        build_sequence(|w| {
            let t1 = build_context_tag(1, |w| w.write_integer(self.padata_type as i64));
            w.write_raw(&t1);
            let t2 = build_context_tag(2, |w| w.write_octet_string(&self.padata_value));
            w.write_raw(&t2);
        })
    }

    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut seq = r.read_sequence()?;

        let mut t1 = seq.read_context_tag(1)?;
        let padata_type = t1.read_integer()? as i32;

        let mut t2 = seq.read_context_tag(2)?;
        let padata_value = t2.read_octet_string()?.to_vec();

        Ok(Self {
            padata_type,
            padata_value,
        })
    }
}

/// Checksum ::= SEQUENCE {
///     cksumtype [0] Int32,
///     checksum  [1] OCTET STRING
/// }
#[derive(Debug, Clone)]
pub struct Checksum {
    pub cksumtype: i32,
    pub checksum: Vec<u8>,
}

impl Checksum {
    pub fn encode(&self) -> Vec<u8> {
        build_sequence(|w| {
            let t0 = build_context_tag(0, |w| w.write_integer(self.cksumtype as i64));
            w.write_raw(&t0);
            let t1 = build_context_tag(1, |w| w.write_octet_string(&self.checksum));
            w.write_raw(&t1);
        })
    }
}

/// EncryptionKey ::= SEQUENCE {
///     keytype  [0] Int32,
///     keyvalue [1] OCTET STRING
/// }
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    pub keytype: i32,
    pub keyvalue: Vec<u8>,
}

impl EncryptionKey {
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut seq = r.read_sequence()?;

        let mut t0 = seq.read_context_tag(0)?;
        let keytype = t0.read_integer()? as i32;

        let mut t1 = seq.read_context_tag(1)?;
        let keyvalue = t1.read_octet_string()?.to_vec();

        Ok(Self { keytype, keyvalue })
    }

    pub fn encode(&self) -> Vec<u8> {
        build_sequence(|w| {
            let t0 = build_context_tag(0, |w| w.write_integer(self.keytype as i64));
            w.write_raw(&t0);
            let t1 = build_context_tag(1, |w| w.write_octet_string(&self.keyvalue));
            w.write_raw(&t1);
        })
    }
}

// ── KDC Request/Response ──

/// KDC-REQ-BODY ::= SEQUENCE { ... }
/// Used in both AS-REQ and TGS-REQ.
#[derive(Debug, Clone)]
pub struct KdcReqBody {
    pub kdc_options: u32,
    pub cname: Option<PrincipalName>,
    pub realm: Vec<u8>,
    pub sname: Option<PrincipalName>,
    pub till: Vec<u8>,  // GeneralizedTime as bytes
    pub nonce: u32,
    pub etype: Vec<i32>,
}

impl KdcReqBody {
    pub fn encode(&self) -> Vec<u8> {
        build_sequence(|w| {
            // [0] kdc-options (KDCOptions = BIT STRING)
            let opts = self.kdc_options.to_be_bytes();
            let t0 = build_context_tag(0, |w| w.write_bit_string(&opts));
            w.write_raw(&t0);

            // [1] cname (OPTIONAL)
            if let Some(ref cname) = self.cname {
                let cname_enc = cname.encode();
                let t1 = build_context_tag(1, |w| w.write_raw(&cname_enc));
                w.write_raw(&t1);
            }

            // [2] realm
            let t2 = build_context_tag(2, |w| w.write_general_string(&self.realm));
            w.write_raw(&t2);

            // [3] sname (OPTIONAL)
            if let Some(ref sname) = self.sname {
                let sname_enc = sname.encode();
                let t3 = build_context_tag(3, |w| w.write_raw(&sname_enc));
                w.write_raw(&t3);
            }

            // [5] till
            let t5 = build_context_tag(5, |w| w.write_generalized_time(&self.till));
            w.write_raw(&t5);

            // [7] nonce
            let t7 = build_context_tag(7, |w| w.write_integer(self.nonce as i64));
            w.write_raw(&t7);

            // [8] etype SEQUENCE OF Int32
            let etypes = build_sequence(|w| {
                for &e in &self.etype {
                    w.write_integer(e as i64);
                }
            });
            let t8 = build_context_tag(8, |w| w.write_raw(&etypes));
            w.write_raw(&t8);
        })
    }

    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut seq = r.read_sequence()?;

        // [0] kdc-options
        let mut t0 = seq.read_context_tag(0)?;
        let opts_bytes = t0.read_bit_string()?;
        let kdc_options = if opts_bytes.len() >= 4 {
            u32::from_be_bytes([opts_bytes[0], opts_bytes[1], opts_bytes[2], opts_bytes[3]])
        } else {
            0
        };

        // [1] cname OPTIONAL
        let cname = if let Some(mut t1) = seq.read_optional_context_tag(1)? {
            let data = t1.read_remaining();
            Some(PrincipalName::decode(data)?)
        } else {
            None
        };

        // [2] realm
        let mut t2 = seq.read_context_tag(2)?;
        let realm = t2.read_general_string()?.to_vec();

        // [3] sname OPTIONAL
        let sname = if let Some(mut t3) = seq.read_optional_context_tag(3)? {
            let data = t3.read_remaining();
            Some(PrincipalName::decode(data)?)
        } else {
            None
        };

        // [4] from OPTIONAL - skip
        let _from = seq.read_optional_context_tag(4)?;

        // [5] till
        let mut t5 = seq.read_context_tag(5)?;
        let till = t5.read_generalized_time()?.to_vec();

        // [6] rtime OPTIONAL - skip
        let _rtime = seq.read_optional_context_tag(6)?;

        // [7] nonce
        let mut t7 = seq.read_context_tag(7)?;
        let nonce = t7.read_integer()? as u32;

        // [8] etype
        let mut t8 = seq.read_context_tag(8)?;
        let mut etype_seq = t8.read_sequence()?;
        let mut etype = Vec::new();
        while !etype_seq.is_empty() {
            etype.push(etype_seq.read_integer()? as i32);
        }

        Ok(Self {
            kdc_options,
            cname,
            realm,
            sname,
            till,
            nonce,
            etype,
        })
    }
}

/// AS-REQ ::= [APPLICATION 10] KDC-REQ
/// TGS-REQ ::= [APPLICATION 12] KDC-REQ
///
/// KDC-REQ ::= SEQUENCE {
///     pvno     [1] INTEGER (5),
///     msg-type [2] INTEGER,
///     padata   [3] SEQUENCE OF PA-DATA OPTIONAL,
///     req-body [4] KDC-REQ-BODY
/// }
#[derive(Debug, Clone)]
pub struct KdcReq {
    pub msg_type: i64,
    pub padata: Vec<PaData>,
    pub req_body: KdcReqBody,
}

impl KdcReq {
    pub fn as_req(padata: Vec<PaData>, req_body: KdcReqBody) -> Self {
        Self {
            msg_type: KRB_AS_REQ,
            padata,
            req_body,
        }
    }

    pub fn tgs_req(padata: Vec<PaData>, req_body: KdcReqBody) -> Self {
        Self {
            msg_type: KRB_TGS_REQ,
            padata,
            req_body,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let app_tag = if self.msg_type == KRB_AS_REQ { 10 } else { 12 };
        build_application_tag(app_tag, |w| {
            let inner = build_sequence(|w| {
                // [1] pvno
                let t1 = build_context_tag(1, |w| w.write_integer(KRB5_PVNO));
                w.write_raw(&t1);
                // [2] msg-type
                let t2 = build_context_tag(2, |w| w.write_integer(self.msg_type));
                w.write_raw(&t2);
                // [3] padata OPTIONAL
                if !self.padata.is_empty() {
                    let pa_seq = build_sequence(|w| {
                        for pa in &self.padata {
                            w.write_raw(&pa.encode());
                        }
                    });
                    let t3 = build_context_tag(3, |w| w.write_raw(&pa_seq));
                    w.write_raw(&t3);
                }
                // [4] req-body
                let body = self.req_body.encode();
                let t4 = build_context_tag(4, |w| w.write_raw(&body));
                w.write_raw(&t4);
            });
            w.write_raw(&inner);
        })
    }
}

/// KDC-REP ::= SEQUENCE {
///     pvno     [0] INTEGER (5),
///     msg-type [1] INTEGER,
///     padata   [2] SEQUENCE OF PA-DATA OPTIONAL,
///     crealm   [3] Realm,
///     cname    [4] PrincipalName,
///     ticket   [5] Ticket,
///     enc-part [6] EncryptedData
/// }
#[derive(Debug, Clone)]
pub struct KdcRep {
    pub msg_type: i64,
    pub padata: Vec<PaData>,
    pub crealm: Vec<u8>,
    pub cname: PrincipalName,
    pub ticket: Ticket,
    pub enc_part: EncryptedData,
}

impl KdcRep {
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);

        // Read APPLICATION tag (11 for AS-REP, 13 for TGS-REP)
        let tag = r.peek_tag()?;
        let app_tag = tag & 0x1F;
        let msg_type = match app_tag {
            11 => KRB_AS_REP,
            13 => KRB_TGS_REP,
            _ => {
                return Err(err_unexpected_msg("unknown KDC-REP application tag"))
            }
        };

        let mut app = r.read_application_tag(app_tag)?;
        let mut seq = app.read_sequence()?;

        // [0] pvno
        let mut t0 = seq.read_context_tag(0)?;
        let _pvno = t0.read_integer()?;

        // [1] msg-type
        let mut t1 = seq.read_context_tag(1)?;
        let _msg_type = t1.read_integer()?;

        // [2] padata OPTIONAL
        let padata = if let Some(mut t2) = seq.read_optional_context_tag(2)? {
            let mut pa_seq = t2.read_sequence()?;
            let mut padata = Vec::new();
            while !pa_seq.is_empty() {
                let (_, pa_bytes) = pa_seq.read_tlv()?;
                // Each element is a PA-DATA SEQUENCE; reconstruct with tag
                let mut full = Vec::new();
                full.push(TAG_SEQUENCE);
                // Re-encode length
                if pa_bytes.len() < 0x80 {
                    full.push(pa_bytes.len() as u8);
                } else if pa_bytes.len() <= 0xFF {
                    full.push(0x81);
                    full.push(pa_bytes.len() as u8);
                } else {
                    full.push(0x82);
                    full.push((pa_bytes.len() >> 8) as u8);
                    full.push(pa_bytes.len() as u8);
                }
                full.extend_from_slice(pa_bytes);
                padata.push(PaData::decode(&full)?);
            }
            padata
        } else {
            Vec::new()
        };

        // [3] crealm
        let mut t3 = seq.read_context_tag(3)?;
        let crealm = t3.read_general_string()?.to_vec();

        // [4] cname
        let mut t4 = seq.read_context_tag(4)?;
        let cname_data = t4.read_remaining();
        let cname = PrincipalName::decode(cname_data)?;

        // [5] ticket
        let mut t5 = seq.read_context_tag(5)?;
        let ticket_data = t5.read_remaining();
        let ticket = Ticket::decode(ticket_data)?;

        // [6] enc-part
        let mut t6 = seq.read_context_tag(6)?;
        let enc_data = t6.read_remaining();
        let enc_part = EncryptedData::decode(enc_data)?;

        Ok(Self {
            msg_type,
            padata,
            crealm,
            cname,
            ticket,
            enc_part,
        })
    }
}

/// EncASRepPart / EncTGSRepPart ::= SEQUENCE {
///     key       [0] EncryptionKey,
///     ...
///     nonce     [7] UInt32,
///     ...
///     srealm    [9] Realm,
///     sname     [10] PrincipalName,
///     ...
/// }
///
/// We only decode the fields we need.
#[derive(Debug, Clone)]
pub struct EncKdcRepPart {
    pub key: EncryptionKey,
    pub nonce: u32,
    pub srealm: Vec<u8>,
    pub sname: PrincipalName,
}

impl EncKdcRepPart {
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);

        // May be wrapped in APPLICATION 25 (EncASRepPart) or 26 (EncTGSRepPart)
        let tag = r.peek_tag()?;
        let mut seq_reader = if tag & 0x40 != 0 {
            // APPLICATION tag present
            let app_tag = tag & 0x1F;
            let mut app = r.read_application_tag(app_tag)?;
            app.read_sequence()?
        } else {
            r.read_sequence()?
        };

        // [0] key
        let mut t0 = seq_reader.read_context_tag(0)?;
        let key_data = t0.read_remaining();
        let key = EncryptionKey::decode(key_data)?;

        // RFC 4120: EncKDCRepPart fields:
        // [0] key, [1] last-req, [2] nonce, [3] key-expiration OPTIONAL,
        // [4] flags, [5] authtime, [6] starttime OPTIONAL, [7] endtime,
        // [8] renew-till OPTIONAL, [9] srealm, [10] sname, [11] caddr OPTIONAL

        // [1] last-req (skip)
        let _t1 = seq_reader.read_optional_context_tag(1)?;

        // [2] nonce
        let mut t2 = seq_reader.read_context_tag(2)?;
        let nonce = t2.read_integer()? as u32;

        // [3] key-expiration OPTIONAL (skip)
        let _t3 = seq_reader.read_optional_context_tag(3)?;

        // [4] flags (skip)
        let _t4 = seq_reader.read_optional_context_tag(4)?;

        // [5] authtime (skip)
        let _t5 = seq_reader.read_optional_context_tag(5)?;

        // [6] starttime OPTIONAL (skip)
        let _t6 = seq_reader.read_optional_context_tag(6)?;

        // [7] endtime (skip)
        let _t7 = seq_reader.read_optional_context_tag(7)?;

        // [8] renew-till OPTIONAL (skip)
        let _t8 = seq_reader.read_optional_context_tag(8)?;

        // [9] srealm
        let mut t9 = seq_reader.read_context_tag(9)?;
        let srealm = t9.read_general_string()?.to_vec();

        // [10] sname
        let mut t10 = seq_reader.read_context_tag(10)?;
        let sname_data = t10.read_remaining();
        let sname = PrincipalName::decode(sname_data)?;

        Ok(Self {
            key,
            nonce,
            srealm,
            sname,
        })
    }
}

// ── AP-REQ / AP-REP ──

/// AP-REQ ::= [APPLICATION 14] SEQUENCE {
///     pvno          [0] INTEGER (5),
///     msg-type      [1] INTEGER (14),
///     ap-options    [2] APOptions (BIT STRING),
///     ticket        [3] Ticket,
///     authenticator [4] EncryptedData
/// }
#[derive(Debug, Clone)]
pub struct ApReq {
    pub ap_options: u32,
    pub ticket: Ticket,
    pub authenticator: EncryptedData,
}

impl ApReq {
    pub fn encode(&self) -> Vec<u8> {
        build_application_tag(14, |w| {
            let inner = build_sequence(|w| {
                // [0] pvno
                let t0 = build_context_tag(0, |w| w.write_integer(KRB5_PVNO));
                w.write_raw(&t0);
                // [1] msg-type
                let t1 = build_context_tag(1, |w| w.write_integer(KRB_AP_REQ));
                w.write_raw(&t1);
                // [2] ap-options
                let opts = self.ap_options.to_be_bytes();
                let t2 = build_context_tag(2, |w| w.write_bit_string(&opts));
                w.write_raw(&t2);
                // [3] ticket
                let ticket_enc = self.ticket.encode();
                let t3 = build_context_tag(3, |w| w.write_raw(&ticket_enc));
                w.write_raw(&t3);
                // [4] authenticator
                let auth_enc = self.authenticator.encode();
                let t4 = build_context_tag(4, |w| w.write_raw(&auth_enc));
                w.write_raw(&t4);
            });
            w.write_raw(&inner);
        })
    }
}

/// Authenticator ::= [APPLICATION 2] SEQUENCE {
///     authenticator-vno [0] INTEGER (5),
///     crealm           [1] Realm,
///     cname            [2] PrincipalName,
///     cksum            [3] Checksum OPTIONAL,
///     cusec            [4] Microseconds,
///     ctime            [5] KerberosTime,
///     subkey           [6] EncryptionKey OPTIONAL,
///     seq-number       [7] UInt32 OPTIONAL,
///     ...
/// }
#[derive(Debug, Clone)]
pub struct Authenticator {
    pub crealm: Vec<u8>,
    pub cname: PrincipalName,
    pub cksum: Option<Checksum>,
    pub cusec: u32,
    pub ctime: Vec<u8>,
    pub subkey: Option<EncryptionKey>,
    pub seq_number: Option<u32>,
}

impl Authenticator {
    pub fn encode(&self) -> Vec<u8> {
        build_application_tag(2, |w| {
            let inner = build_sequence(|w| {
                // [0] authenticator-vno
                let t0 = build_context_tag(0, |w| w.write_integer(KRB5_PVNO));
                w.write_raw(&t0);
                // [1] crealm
                let t1 = build_context_tag(1, |w| w.write_general_string(&self.crealm));
                w.write_raw(&t1);
                // [2] cname
                let cname_enc = self.cname.encode();
                let t2 = build_context_tag(2, |w| w.write_raw(&cname_enc));
                w.write_raw(&t2);
                // [3] cksum OPTIONAL
                if let Some(ref cksum) = self.cksum {
                    let cksum_enc = cksum.encode();
                    let t3 = build_context_tag(3, |w| w.write_raw(&cksum_enc));
                    w.write_raw(&t3);
                }
                // [4] cusec
                let t4 = build_context_tag(4, |w| w.write_integer(self.cusec as i64));
                w.write_raw(&t4);
                // [5] ctime
                let t5 = build_context_tag(5, |w| w.write_generalized_time(&self.ctime));
                w.write_raw(&t5);
                // [6] subkey OPTIONAL
                if let Some(ref subkey) = self.subkey {
                    let key_enc = subkey.encode();
                    let t6 = build_context_tag(6, |w| w.write_raw(&key_enc));
                    w.write_raw(&t6);
                }
                // [7] seq-number OPTIONAL
                if let Some(seq) = self.seq_number {
                    let t7 = build_context_tag(7, |w| w.write_integer(seq as i64));
                    w.write_raw(&t7);
                }
            });
            w.write_raw(&inner);
        })
    }
}

/// AP-REP ::= [APPLICATION 15] SEQUENCE {
///     pvno     [0] INTEGER (5),
///     msg-type [1] INTEGER (15),
///     enc-part [2] EncryptedData
/// }
#[derive(Debug, Clone)]
pub struct ApRep {
    pub enc_part: EncryptedData,
}

impl ApRep {
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut app = r.read_application_tag(15)?;
        let mut seq = app.read_sequence()?;

        // [0] pvno
        let mut t0 = seq.read_context_tag(0)?;
        let _pvno = t0.read_integer()?;

        // [1] msg-type
        let mut t1 = seq.read_context_tag(1)?;
        let _msg_type = t1.read_integer()?;

        // [2] enc-part
        let mut t2 = seq.read_context_tag(2)?;
        let enc_data = t2.read_remaining();
        let enc_part = EncryptedData::decode(enc_data)?;

        Ok(Self { enc_part })
    }
}

/// EncAPRepPart ::= [APPLICATION 27] SEQUENCE {
///     ctime    [0] KerberosTime,
///     cusec    [1] Microseconds,
///     subkey   [2] EncryptionKey OPTIONAL,
///     seq-number [3] UInt32 OPTIONAL
/// }
#[derive(Debug, Clone)]
pub struct EncApRepPart {
    pub ctime: Vec<u8>,
    pub cusec: u32,
    pub subkey: Option<EncryptionKey>,
    pub seq_number: Option<u32>,
}

impl EncApRepPart {
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut app = r.read_application_tag(27)?;
        let mut seq = app.read_sequence()?;

        let mut t0 = seq.read_context_tag(0)?;
        let ctime = t0.read_generalized_time()?.to_vec();

        let mut t1 = seq.read_context_tag(1)?;
        let cusec = t1.read_integer()? as u32;

        let subkey = if let Some(mut t2) = seq.read_optional_context_tag(2)? {
            let key_data = t2.read_remaining();
            Some(EncryptionKey::decode(key_data)?)
        } else {
            None
        };

        let seq_number = if let Some(mut t3) = seq.read_optional_context_tag(3)? {
            Some(t3.read_integer()? as u32)
        } else {
            None
        };

        Ok(Self {
            ctime,
            cusec,
            subkey,
            seq_number,
        })
    }
}

// ── KRB-ERROR ──

/// KRB-ERROR ::= [APPLICATION 30] SEQUENCE { ... }
/// We only decode the fields we need.
#[derive(Debug, Clone)]
pub struct KrbError {
    pub error_code: i32,
    pub e_data: Option<Vec<u8>>,
}

impl KrbError {
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut app = r.read_application_tag(30)?;
        let mut seq = app.read_sequence()?;

        // [0] pvno
        let _t0 = seq.read_optional_context_tag(0)?;
        // [1] msg-type
        let _t1 = seq.read_optional_context_tag(1)?;
        // [2] ctime OPTIONAL
        let _t2 = seq.read_optional_context_tag(2)?;
        // [3] cusec OPTIONAL
        let _t3 = seq.read_optional_context_tag(3)?;
        // [4] stime
        let _t4 = seq.read_optional_context_tag(4)?;
        // [5] susec
        let _t5 = seq.read_optional_context_tag(5)?;
        // [6] error-code
        let mut t6 = seq.read_context_tag(6)?;
        let error_code = t6.read_integer()? as i32;

        // Skip [7] crealm, [8] cname, [9] realm, [10] sname, [11] e-text
        let _t7 = seq.read_optional_context_tag(7)?;
        let _t8 = seq.read_optional_context_tag(8)?;
        let _t9 = seq.read_optional_context_tag(9)?;
        let _t10 = seq.read_optional_context_tag(10)?;
        let _t11 = seq.read_optional_context_tag(11)?;

        // [12] e-data OPTIONAL
        let e_data = if let Some(mut t12) = seq.read_optional_context_tag(12)? {
            Some(t12.read_octet_string()?.to_vec())
        } else {
            None
        };

        Ok(Self { error_code, e_data })
    }
}

/// ETYPE-INFO2-ENTRY ::= SEQUENCE {
///     etype     [0] Int32,
///     salt      [1] KerberosString OPTIONAL,
///     s2kparams [2] OCTET STRING OPTIONAL
/// }
#[derive(Debug, Clone)]
pub struct ETypeInfo2Entry {
    pub etype: i32,
    pub salt: Option<Vec<u8>>,
    pub s2kparams: Option<Vec<u8>>,
}

impl ETypeInfo2Entry {
    pub fn decode(data: &[u8]) -> DecodeResult<Self> {
        let mut r = DerReader::new(data);
        let mut seq = r.read_sequence()?;

        let mut t0 = seq.read_context_tag(0)?;
        let etype = t0.read_integer()? as i32;

        let salt = if let Some(mut t1) = seq.read_optional_context_tag(1)? {
            Some(t1.read_general_string()?.to_vec())
        } else {
            None
        };

        let s2kparams = if let Some(mut t2) = seq.read_optional_context_tag(2)? {
            Some(t2.read_octet_string()?.to_vec())
        } else {
            None
        };

        Ok(Self {
            etype,
            salt,
            s2kparams,
        })
    }
}

/// PA-ENC-TIMESTAMP (encrypted timestamp for pre-authentication).
/// This is an EncryptedData containing PA-ENC-TS-ENC.
///
/// PA-ENC-TS-ENC ::= SEQUENCE {
///     patimestamp [0] KerberosTime,
///     pausec      [1] Microseconds OPTIONAL
/// }
pub fn encode_pa_enc_ts_enc(timestamp: &[u8], usec: u32) -> Vec<u8> {
    build_sequence(|w| {
        let t0 = build_context_tag(0, |w| w.write_generalized_time(timestamp));
        w.write_raw(&t0);
        let t1 = build_context_tag(1, |w| w.write_integer(usec as i64));
        w.write_raw(&t1);
    })
}

/// PA-PAC-REQUEST ::= SEQUENCE {
///     include-pac [0] BOOLEAN
/// }
pub fn encode_pa_pac_request(include: bool) -> Vec<u8> {
    build_sequence(|w| {
        let t0 = build_context_tag(0, |w| w.write_boolean(include));
        w.write_raw(&t0);
    })
}

/// Detect message type from the APPLICATION tag of a KRB message.
pub fn detect_krb_message_type(data: &[u8]) -> Option<i64> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    if tag & 0x60 != 0x60 {
        // Not APPLICATION | CONSTRUCTED
        return None;
    }
    let app_tag = (tag & 0x1F) as i64;
    Some(app_tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_name_roundtrip() {
        let name = PrincipalName::service(b"krbtgt", b"EXAMPLE.COM");
        let encoded = name.encode();
        let decoded = PrincipalName::decode(&encoded).unwrap();
        assert_eq!(decoded.name_type, NT_SRV_INST);
        assert_eq!(decoded.name_string.len(), 2);
        assert_eq!(decoded.name_string[0], b"krbtgt");
        assert_eq!(decoded.name_string[1], b"EXAMPLE.COM");
    }

    #[test]
    fn encrypted_data_roundtrip() {
        let ed = EncryptedData {
            etype: ETYPE_AES256_CTS_HMAC_SHA1,
            kvno: Some(2),
            cipher: vec![0x01, 0x02, 0x03],
        };
        let encoded = ed.encode();
        let decoded = EncryptedData::decode(&encoded).unwrap();
        assert_eq!(decoded.etype, ETYPE_AES256_CTS_HMAC_SHA1);
        assert_eq!(decoded.kvno, Some(2));
        assert_eq!(decoded.cipher, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn kdc_req_body_roundtrip() {
        let body = KdcReqBody {
            kdc_options: KDC_OPT_FORWARDABLE | KDC_OPT_RENEWABLE | KDC_OPT_CANONICALIZE,
            cname: Some(PrincipalName::principal(b"user")),
            realm: b"EXAMPLE.COM".to_vec(),
            sname: Some(PrincipalName::service(b"krbtgt", b"EXAMPLE.COM")),
            till: b"20370913024805Z".to_vec(),
            nonce: 12345,
            etype: vec![ETYPE_AES256_CTS_HMAC_SHA1, ETYPE_AES128_CTS_HMAC_SHA1],
        };
        let encoded = body.encode();
        let decoded = KdcReqBody::decode(&encoded).unwrap();
        assert_eq!(decoded.kdc_options, body.kdc_options);
        assert_eq!(decoded.realm, b"EXAMPLE.COM");
        assert_eq!(decoded.nonce, 12345);
        assert_eq!(decoded.etype, vec![ETYPE_AES256_CTS_HMAC_SHA1, ETYPE_AES128_CTS_HMAC_SHA1]);
    }
}
