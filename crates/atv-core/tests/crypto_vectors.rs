// Protocol fixtures inherited from atv-core; see THIRD_PARTY_NOTICES.md.
// CompanionCipher/HKDF vectors produced by fake_atv.py.
#![allow(clippy::all)]

use atv_core::crypto::{hkdf_expand, CompanionCipher};

const OUT_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const IN_KEY: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

fn new_cipher() -> CompanionCipher {
    CompanionCipher::new(
        &hex::decode(OUT_KEY).unwrap(),
        &hex::decode(IN_KEY).unwrap(),
        12,
    ).unwrap()
}

#[test]
fn cipher_counter_nonce_encrypt_matches_python() {
    let mut cipher = new_cipher();
    let body = hex::decode("7b225f69223a225f68696443227d").unwrap();
    let header = hex::decode("0800001e").unwrap();
    let expected = hex::decode("639a1d588fdc848e7b0838228d3ef0d3a815a78969c8f73f1ab9b3078947").unwrap();
    assert_eq!(cipher.encrypt(&body, Some(&header), None).unwrap(), expected, "frame 0");
    let body = hex::decode("e3425f69455f68696443425f740a425f63e2a109455f6842745309").unwrap();
    let header = hex::decode("0800002b").unwrap();
    let expected = hex::decode("777d248781bcf443131891ac19359f04425a51d168a6b17fe113fe14f0c5806fa93c695e074d466e0af007").unwrap();
    assert_eq!(cipher.encrypt(&body, Some(&header), None).unwrap(), expected, "frame 1");
    let body = hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let header = hex::decode("08000074").unwrap();
    let expected = hex::decode("8feae02842e728362c58729271d52803dfef493a3f654da549020b052395bfa2ffbebd50df7ebed12229cfc03d570be13511ed612eaba962a2c0bcbc585cff39d3dce7bfdfd5bf6351dd39d5e6dd844fa9b403558e6a34ed86b8c945122af8357d30cefb0d71f305ac2f1899655c57766293c0a2").unwrap();
    assert_eq!(cipher.encrypt(&body, Some(&header), None).unwrap(), expected, "frame 2");
}

#[test]
fn cipher_counter_nonce_decrypt_matches_python() {
    let mut cipher = new_cipher();
    let body = hex::decode("7b225f69223a225f68696443227d").unwrap();
    let header = hex::decode("0800001e").unwrap();
    let encrypted = hex::decode("fb4100b531b2f542f2419da2c7f478456b4ec04fba8bdb3419744e6389e0").unwrap();
    assert_eq!(cipher.decrypt(&encrypted, Some(&header), None).unwrap(), body, "frame 0");
    let body = hex::decode("e3425f69455f68696443425f740a425f63e2a109455f6842745309").unwrap();
    let header = hex::decode("0800002b").unwrap();
    let encrypted = hex::decode("26ec4e5547aae3f18fd5bef9b8459b5dca6a46bd82548deb9786f0d1b2d940781df26f6ad9e8f970ee3a26").unwrap();
    assert_eq!(cipher.decrypt(&encrypted, Some(&header), None).unwrap(), body, "frame 1");
    let body = hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let header = hex::decode("08000074").unwrap();
    let encrypted = hex::decode("93a73cb588876c4628b0fafff0f8def58b38708abbe832c9d8faf236ba45f6492715a57f0e2456d49376caf6efa795c45c52de2f94cb39bd5f8a54347a9c1eb86d866d0998159961c06e75f712cf2c8eed94307410066da5def385d396c21727f4dd57258100a81b31c7a45a770c4fef45e91dbb").unwrap();
    assert_eq!(cipher.decrypt(&encrypted, Some(&header), None).unwrap(), body, "frame 2");
}

#[test]
fn cipher_explicit_nonce_matches_python() {
    let mut cipher = CompanionCipher::new(
        &hex::decode(IN_KEY).unwrap(),
        &hex::decode(IN_KEY).unwrap(),
        8,
    ).unwrap();
    let plain = hex::decode("0109636c69656e742d69640320000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let expected = hex::decode("198f7ba9f7542940bae690be2ab48d4fcba60ebded08c2ada6fadd22b21bb728ffcf12fcfabcacca79eaebde164ade58e30dac75b4026063287b26db6e").unwrap();
    assert_eq!(cipher.encrypt(&plain, None, Some(b"PS-Msg05")).unwrap(), expected);
    assert_eq!(cipher.decrypt(&expected, None, Some(b"PS-Msg05")).unwrap(), plain);
}

#[test]
fn hkdf_matches_python() {
    let shared = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f").unwrap();
    assert_eq!(
        hkdf_expand("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", &shared).to_vec(),
        hex::decode("8f806335e1847b59c5004b131c4689e951ce9808993aed540856475e0dee353b").unwrap(),
    );
    assert_eq!(
        hkdf_expand("", "ServerEncrypt-main", &shared).to_vec(),
        hex::decode("43020386f29e4f8016eadaf9233973760ec466e2af1668eb85f31e4d90231649").unwrap(),
    );
}
