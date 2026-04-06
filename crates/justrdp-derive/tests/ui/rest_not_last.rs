use justrdp_derive::Encode;

#[derive(Encode)]
pub struct Bad {
    #[pdu(rest)]
    pub payload: Vec<u8>,
    #[pdu(u8)]
    pub trailing: u8,
}

fn main() {}
