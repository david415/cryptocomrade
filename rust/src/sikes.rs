#[cfg(test)]
mod tests {
    extern crate rust_sike;

    use self::rust_sike::KEM;
    
    #[test]
    fn basic_sike_test() {
        let params = rust_sike::sike_p751_params(None, None).unwrap();
        let kem = KEM::setup(params);

        // Alice runs keygen, publishes pk3. Values s and sk3 are secret
        let (s, sk3, pk3) = kem.keygen().unwrap();

        // Bob uses pk3 to derive a key k and encapsulation c
        let (c, k) = kem.encaps(&pk3).unwrap();

        // Bob sends c to Alice
        // Alice uses s, c, sk3 and pk3 to recover k
        let k_recovered = kem.decaps(&s, &sk3, &pk3, c).unwrap();

        assert_eq!(k, k_recovered);
    }
}
