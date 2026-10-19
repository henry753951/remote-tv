// Protocol fixtures inherited from atv-core; see THIRD_PARTY_NOTICES.md.
// SRP pair-setup vector computed with srptools (Apple variant:
// 3072-bit group, SHA-512, 128-bit salt, server private = 32 x 0xaa).
#![allow(clippy::all)]

use atv_core::srp::SrpServer;

#[test]
fn srp_pair_setup_matches_srptools() {
    let salt = hex::decode("00112233445566778899aabbccddeeff").unwrap();
    let mut server = SrpServer::with_salt(1111, &[0xaa; 32], &salt);
    let expected_b = hex::decode("60436d941aaa598a0f600edc71bb2d8a2e6336d5cd931a13d30c99c3167e863b09b26750f433c5ef5865f57d63b3d2faaadd9ddaf0514f91833db5740f1981f07439b3b8d253ff8ad318f897803cf9a6e362d509be9b11dd76926a947f5c9263be1b9706e50102e527af8cb29deb24a69f355e62229b6e09c41a31e116c780011817ffb3b44b8ab5b895a73887676f7636d2aa85b8ca6f9fa33622678ef752498857b7fa5fd9f57307ce3cc637fcc3d4f45d71524955d71901344123f9099495cb3ec1df716d60230a06649f0e33a5dd8b81207630d498fb7f21663b53f762c2f0ba8d09ea8e7be09aa487843c47e30e87e6b7ecc47d667ed4b71ab470f95ee9596f34f655eead21d54ae77f022557ba12fb5e688b40b9fc83384be8bdbbff6462a8982cb6b3f644b36b38fd52f99084e53e3d3014c15286b377e47fa4f637cc781d0339a2a7df9130a6b71e162816a10d3ef539f06dc54d41f50de56bc91c69f52e7112547e4f9709c693820f25365f55f1b429d60167a87e7e4607ae0849cd").unwrap();
    assert_eq!(server.public_key(), expected_b, "server public key B");
    let client_public = hex::decode("bc0e7cf5dc3babf67dcedbb3b140aacc6cac43f4336b43bbd5de48d6ea7c8eda66924e354255225bccad9debe21182e6bb050f3ff3e6cfbb62c229379968c70ca436ad649a0b051373184215eef046f6f1f2256838f958581f6c7b2b85fa4afe326a0e8a951d4489305331aff88a136fd8d108bcc95fceb7e557c889c828bd23fb0702f053e1ca6470fb3c76bce4843fc005c7ea675740f8550212656cfc8919d9db805a434a68229e0d9dfe43fc16dc680a5ce74b77cf374353b05759bc1da3a9dabde30a4209381c87ca83d9483abdf66b86f9b1cbda9ad82c62712b87ce6fb7069b8fc8df344261821a06d0dc5106af76d4245f3f7737a94dbc484b415555dc401842d3011204553ba9f611b02bc38de26eba1a76bf8350205a62c436ba1c3c7c69d59318bd107fd1c1f5d846b3142e85a5d49e522655e020ed1bfe1e186cf923bf328f0b9b4c6a8aa3266ed9125bb98d63827110713be7803122ee4603c54ea31863ce4b10aff31f9073cf63b94733b4f066e72d4ec35687047d5d0db160").unwrap();
    server.process(&client_public).unwrap();
    let client_proof = hex::decode("609fc3b240f3b8e8932fc26b1ce3a9a901a1c6024239e5618d086a46c8709d8b635524d90c41f6c465626128242151ca32f57f5a6a14dea074e4cbe08832bd03").unwrap();
    assert!(server.verify_proof(&client_proof), "client proof M1");
    assert!(!server.verify_proof(&[0u8; 64]), "wrong proof must fail");
    let expected_proof_hash = hex::decode("be9f8aa7f23a0826316277b2dc767d1dae1490c28e4f6c9859347ea67331f8ee1cd445ebc982a9f773c8bc2c3dbfc73271ec4e6245d8e3a7e5104503fff27e57").unwrap();
    assert_eq!(server.key_proof_hash().unwrap(), expected_proof_hash, "H(A|M|K)");
    let expected_key = hex::decode("43cfd784738cbb616f7d1b921b1cfd7df0b0f6b6377c89aad7ac070d86b8b3663729cf32db89c33fa7500fd9977ed262becbaeb29f90580777acb4e622f0a85a").unwrap();
    assert_eq!(server.session_key().unwrap(), &expected_key[..], "session key K");
}
