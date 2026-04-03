use justrdp_derive::Encode;

#[derive(Encode)]
pub struct Bad {
    #[pdu(u8, u16_le)]
    pub field: u8,
}

fn main() {}
