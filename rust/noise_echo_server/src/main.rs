
extern crate rand;
extern crate ecdh_wrapper;
extern crate snow;
extern crate byteorder;

use std::str;
use std::net::TcpListener;
use std::net::TcpStream;
use std::io::Read;
use std::io::Write;
use byteorder::{ByteOrder, BigEndian};

use rand::os::OsRng;

use snow::Builder;
use snow::params::NoiseParams;

use ecdh_wrapper::PrivateKey;


const NOISE_PARAMS: & str = "Noise_XXhfs_25519+Kyber1024_ChaChaPoly_BLAKE2b";
//const NOISE_PARAMS: & str = "Noise_XX_25519_ChaChaPoly_BLAKE2b";
const NOISE_MESSAGE_MAX_SIZE: usize = 65535;

const NOISE_HANDSHAKE_MESSAGE1_SIZE: usize = 1600;
const NOISE_HANDSHAKE_MESSAGE2_SIZE: usize = 1680;
const NOISE_HANDSHAKE_MESSAGE3_SIZE: usize = 64;

/*
const NOISE_HANDSHAKE_MESSAGE1_SIZE: usize = 32;
const NOISE_HANDSHAKE_MESSAGE2_SIZE: usize = 96;
const NOISE_HANDSHAKE_MESSAGE3_SIZE: usize = 64;
*/

const MAC_SIZE: usize = 16;
const NOISE_MESSAGE_HEADER_SIZE: usize = MAC_SIZE + 4;
const HEADER_SIZE: usize = 4;



fn do_noise_handshake(mut stream: TcpStream, handshake_state: &mut snow::HandshakeState) -> TcpStream {
    // -> e, e1
    let mut client_handshake1 = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
    stream.read_exact(&mut client_handshake1).unwrap();
    let mut _msg = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
    handshake_state.read_message(&client_handshake1, &mut _msg).unwrap();

    // <- e, ee, ekem1, s, es
    let mut mesg = [0u8; NOISE_HANDSHAKE_MESSAGE2_SIZE];
    handshake_state.write_message(b"", &mut mesg).unwrap();
    stream.write_all(&mesg).unwrap();

    // -> s, se    
    let mut client_handshake2 = [0u8; NOISE_HANDSHAKE_MESSAGE3_SIZE];
    stream.read_exact(&mut client_handshake2).unwrap();
    let mut _msg2 = [0u8; NOISE_HANDSHAKE_MESSAGE3_SIZE];
    handshake_state.read_message(&client_handshake2, &mut _msg2).unwrap();
    
    stream
}

fn handle_client(stream: TcpStream, private_key: PrivateKey) {
    let params: NoiseParams = NOISE_PARAMS.parse().unwrap();
    let mut hs = Builder::new(params)
        .local_private_key(&private_key.to_vec())
        .build_responder()
        .unwrap();
    let mut stream = do_noise_handshake(stream, &mut hs);
    let mut transport = hs.into_transport_mode().unwrap();

    loop {
        let mut message_header_ciphertext = vec![0u8; NOISE_MESSAGE_HEADER_SIZE];
        match stream.read_exact(&mut message_header_ciphertext) {
            Ok(()) => {
            }
            Err(err) => {
                println!("connection was closed");
                break
            }
        }
        let mut header = [0u8; HEADER_SIZE];
        transport.read_message(&message_header_ciphertext, &mut header).unwrap();
        let ciphertext_size = BigEndian::read_u32(&header);
        let mut ciphertext = vec![0u8; ciphertext_size as usize];
        stream.read_exact(&mut ciphertext).unwrap();
        let mut plaintext = vec![0u8; ciphertext_size as usize - MAC_SIZE];
        transport.read_message(&ciphertext, &mut plaintext).unwrap();

        println!("PLAINTEXT is: {}\n", str::from_utf8(&plaintext).unwrap());
        
        let mut send_header_ciphertext = vec![0u8; MAC_SIZE + 4];
        // reuse "header" because it's the same big endian encoded length
        transport.write_message(&header, &mut send_header_ciphertext).unwrap();
        let mut send_ciphertext = vec![0u8; ciphertext_size as usize];
        transport.write_message(&plaintext, &mut send_ciphertext).unwrap();
        let mut send_message_ciphertext = Vec::new();
        send_message_ciphertext.extend(send_header_ciphertext);
        send_message_ciphertext.extend(send_ciphertext);
        stream.write(&send_message_ciphertext).unwrap();
    }
}

fn main() {
    let mut rng = OsRng::new().unwrap();
    let private_key = PrivateKey::generate(&mut rng).unwrap();
    let public_key = private_key.public_key();
    let server_addr = "127.0.0.1:36669";
    
    println!("public_key: {}", public_key.to_base64());
    println!("starting noise echo server, listening on {}...\n", server_addr);

    let listener = TcpListener::bind(server_addr.clone()).unwrap();

    // XXX fix me: how to make it spawn new threads?
    // private_key does not implement Copy trait
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_client(stream, private_key.clone());
            }
            Err(_) => {
                println!("Error");
            }
        }
    }
}
