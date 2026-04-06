use justrdp_derive::Encode;

#[derive(Encode)]
pub struct Bad {
    #[pdu(bytes = 0)]
    pub field: [u8; 0],
}

fn main() {}
