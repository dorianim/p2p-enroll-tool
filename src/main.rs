use std::io::{prelude::*, Cursor};
use std::net::TcpStream;

use binrw::{binrw, helpers::until_eof, BinRead, BinWrite};

#[binrw]
#[derive(Debug)]
struct EnrollInit {
    challenge: [u8; 8],
}

#[binrw]
#[brw(repr(u16))]
#[derive(Debug)]
enum Project {
    Gossip = 2961,
    DHT = 4963,
    RPS = 15882,
    NSE = 7071,
    Onion = 39943,
}

#[binrw]
#[derive(Debug)]
struct EnrollRegister {
    challenge: [u8; 8],
    team_number: u16,
    project_choice: Project,
    nonce: [u8; 8],
    #[br(parse_with = until_eof)]
    string_payload: Vec<u8>,
}

#[binrw]
#[derive(Debug)]
struct EnrollSuccess {
    reserved: u16,
    team_number: u16,
}

#[binrw]
#[derive(Debug)]
struct EnrollFailure {
    reserved: u16,
    error_number: u16,
    #[br(parse_with = until_eof)]
    error_description: Vec<u8>,
}

#[binrw]
#[derive(Debug)]
enum MessageBody {
    #[brw(magic = 680u16)]
    EnrollInit(EnrollInit),
    #[brw(magic = 681u16)]
    EnrollRegister(EnrollRegister),
    #[brw(magic = 682u16)]
    EnrollSuccess(EnrollSuccess),
    #[brw(magic = 683u16)]
    EnrollFailure(EnrollFailure),
}

impl MessageBody {
    fn size(&self) -> Result<u16, String> {
        Ok(match self {
            MessageBody::EnrollInit(_) => 8,
            MessageBody::EnrollRegister(register) => 20 + register.string_payload.len() as u16,
            MessageBody::EnrollSuccess(_) => 4,
            MessageBody::EnrollFailure(failure) => 4 + failure.error_description.len() as u16,
        } + 2)
    }
}

#[binrw]
#[brw(big)]
#[derive(Debug)]
struct Message {
    #[bw(try_calc(body.size().map(|s| s+2)))]
    size: u16,
    body: MessageBody,
}

fn receive_message(stream: &mut TcpStream) -> Message {
    let mut size: [u8; 2] = [0; 2];
    stream.read_exact(&mut size).unwrap();

    let size = u16::from_be_bytes(size) - 2;
    println!("Size: {}", size);

    let mut buf = vec![0; size as usize + 2];
    stream.read_exact(&mut buf[2..]).unwrap();
    buf[0] = (size >> 8) as u8;
    buf[1] = size as u8;

    println!("Received: {:02?}", buf);

    let mut cur = Cursor::new(&buf);
    Message::read(&mut cur).unwrap()
}

fn main() {
    println!("Hello, world!");

    let mut stream = TcpStream::connect("p2psec.net.in.tum.de:13337").unwrap();

    let message = receive_message(&mut stream);
    println!("Received: {:?}", message);

    let MessageBody::EnrollInit(init) = message.body else {
        panic!("Unexpected message!");
    };

    let mut string_payload: String = String::new();
    //string_payload += "dorian.zedler@tum.de\r\n";
    //string_payload += "Dorian\r\n";
    //string_payload += "Zedler\r\n";
    //string_payload += "dorianim";
    string_payload += "thomas.florian@tum.de\r\n";
    string_payload += "Thomas\r\n";
    string_payload += "Florian\r\n";
    string_payload += "flotho";

    let message = Message {
        body: MessageBody::EnrollRegister(EnrollRegister {
            challenge: init.challenge,
            team_number: 5,
            project_choice: Project::Onion,
            nonce: [0; 8],
            string_payload: string_payload.into_bytes(),
        }),
    };

    let mut writer = Cursor::new(Vec::new());
    message.write(&mut writer).unwrap();

    let mut buf = writer.into_inner();
    println!("Buffer: {:?} {:02x?}", buf.len(), buf);
    println!("Body: {:02x?}", &buf[4..]);

    for i in 0..u64::MAX {
        let digest = sha256::digest(&buf[4..]);
        if digest.get(..6).unwrap() == "000000" {
            println!("GOT IT");
            println!("Digest: {:?}", digest);
            break;
        }

        buf[16..24].copy_from_slice(&i.to_be_bytes());
    }

    println!("Sending: {:02x?}", buf);
    stream.write_all(&buf).unwrap();

    let message = receive_message(&mut stream);
    println!("Received: {:?}", message);

    match message.body {
        MessageBody::EnrollSuccess(success) => {
            println!("Enroll success: {:?}", success);
        }
        MessageBody::EnrollFailure(failure) => {
            println!("Enroll failure: {:?}", failure);
            let error_string = String::from_utf8(failure.error_description).unwrap();
            println!("Error: {}", error_string);
        }
        _ => {
            println!("Unexpected message!");
        }
    }
}
