#[cfg(test)]
mod tests {

    extern crate oqs;
    
    use self::oqs::*;
    
    #[test]
    fn basic_kyber_test() {
        let kemalg = kem::Kem::new(kem::Algorithm::Kyber1024).unwrap();
        let (kem_pk, kem_sk) = kemalg.keypair().unwrap();
        let (kem_ct, b_kem_ss) = kemalg.encapsulate(&kem_pk).unwrap();
        let a_kem_ss = kemalg.decapsulate(&kem_sk, &kem_ct).unwrap();
        assert_eq!(a_kem_ss, b_kem_ss);
    }
}
