#[cfg(test)]
mod tests {

    extern crate pqcrypto_classicmceliece;
    
    use self::pqcrypto_classicmceliece::mceliece8192128::*;
    
    #[test]
    fn basic_classicmceliece_test() {
        let (pk, sk) = keypair();
        let (ss1, ct) = encapsulate(&pk);
        let ss2 = decapsulate(&ct, &sk);
        assert!(ss1 == ss2);
    }
}
