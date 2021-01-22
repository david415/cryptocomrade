#[cfg(test)]
mod tests {

    extern crate snow;
    extern crate subtle;
    extern crate ecdh_wrapper;
    extern crate rand;

    use self::subtle::ConstantTimeEq;
    use self::snow::Builder;
    use self::snow::params::NoiseParams;
    use self::ecdh_wrapper::PrivateKey;
    use self::rand::os::OsRng;

    pub const PROLOGUE: [u8;1] = [0u8;1];
    pub const PROLOGUE_SIZE: usize = 1;
    pub const NOISE_MESSAGE_MAX_SIZE: usize = 65535;
    pub const KEY_SIZE: usize = 32;
    pub const NOISE_HANDSHAKE_MESSAGE1_SIZE: usize = PROLOGUE_SIZE + KEY_SIZE;
    
    #[test]
    fn noise_kyber_test() {
        let mut rng = OsRng::new().unwrap();
        let alice_private_key = PrivateKey::generate(&mut rng).unwrap();
        let alice_public_key = alice_private_key.public_key();
        let bob_private_key = PrivateKey::generate(&mut rng).unwrap();
        let bob_public_key = bob_private_key.public_key();
        
        let params: NoiseParams = "Noise_XXhfs_25519+Kyber1024_ChaChaPoly_BLAKE2b".parse().unwrap();
        let mut alice_hs = Builder::new(params.clone())
            .local_private_key(&alice_private_key.to_vec())
            .remote_public_key(&bob_public_key.to_vec())
            .prologue(&PROLOGUE)
            .build_initiator()
            .unwrap();
        let mut bob_hs = Builder::new(params)
            .local_private_key(&bob_private_key.to_vec())
            .remote_public_key(&alice_public_key.to_vec())
            .prologue(&PROLOGUE)
            .build_responder()
            .unwrap();

        // handshake messages
        
        // client side
        let mut msg = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let len = alice_hs.write_message(b"", &mut msg).unwrap();
        assert_eq!(len, 1600);
        let mut client_handshake1 = [0u8; 1600+1];
        client_handshake1[0] = PROLOGUE[0];
        client_handshake1[PROLOGUE_SIZE..].copy_from_slice(&msg[..len]);

        // server side
        assert_eq!(client_handshake1[0..PROLOGUE_SIZE].ct_eq(&PROLOGUE).unwrap_u8(), 1);
        let mut _msg1 = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
        let len = bob_hs.read_message(&client_handshake1[PROLOGUE_SIZE..], &mut _msg1).unwrap();
        assert_eq!(len, 0);

        let mut server_handshake1 = [0u8; 1680];
        let len = bob_hs.write_message(b"", &mut server_handshake1).unwrap();
        assert_eq!(len, 1680);

        // client side
        let mut blah = [0u8; 0];
        let len = alice_hs.read_message(&server_handshake1, &mut blah).unwrap();
        assert_eq!(len, 0);
        let alice_raw_peer_key = alice_hs.get_remote_static().unwrap();
        assert_eq!(alice_raw_peer_key.ct_eq(&bob_public_key.to_vec()).unwrap_u8(), 1);

        // client side
        let mut client_handshake2 = [0u8; 64];
        let len = alice_hs.write_message(b"", &mut client_handshake2).unwrap();
        assert_eq!(len, 64);

        // server side
        let mut raw_auth = [0u8; 1024];
        let len = bob_hs.read_message(&client_handshake2[..len], &mut raw_auth).unwrap();
        assert_eq!(len, 0);

        // data transfer phase

        let mut bob_transport = bob_hs.into_transport_mode().unwrap();
        let mut alice_transport = alice_hs.into_transport_mode().unwrap();

        let bob_plaintext = b"yo what up";
        let mut bob_ciphertext = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let len = bob_transport.write_message(bob_plaintext, &mut bob_ciphertext).unwrap();

        let mut alice_message = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let len = alice_transport.read_message(&bob_ciphertext[..len], &mut alice_message).unwrap();
        assert_eq!(&bob_plaintext[..], &alice_message[..len]);
        
        let alice_plaintext = b"sup!";
        let mut alice_ciphertext = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let len = alice_transport.write_message(alice_plaintext, &mut alice_ciphertext).unwrap();

        let mut bob_message = [0u8; NOISE_MESSAGE_MAX_SIZE];
        let len = bob_transport.read_message(&alice_ciphertext[..len], &mut bob_message).unwrap();
        assert_eq!(&alice_plaintext[..], &bob_message[..len]);
    }
}
