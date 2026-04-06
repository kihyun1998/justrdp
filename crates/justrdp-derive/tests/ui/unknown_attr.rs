use justrdp_derive::Encode;

#[derive(Encode)]
pub struct Bad {
    #[pdu(foo)]
    pub field: u8,
}

fn main() {}
