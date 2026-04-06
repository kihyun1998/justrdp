use justrdp_derive::Encode;

#[derive(Encode)]
pub struct Bad {
    #[pdu(pad = 0)]
    pub field: (),
}

fn main() {}
