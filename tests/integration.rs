#[test]
fn ip_is_valid() {
    let _ = ipgen::ip(
        "c0a010fb-2632-40cb-a105-90297cba567a",
        "fd52:f6b0:3162::/48",
    )
    .unwrap();
}
