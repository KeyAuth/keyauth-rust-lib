#[test]
fn webloader() {
    let mut keyauth = crate::v1_2::KeyauthApi::new("library-development", "EdmsTKiuld", "9f752b6a414455175efd942abfd2183667413d57b1d59d6742d8437c71802b49", "1.0", "https://keyauth.win/api/1.2/");
    keyauth.init(None);
    keyauth.web_login(None);
    keyauth.button("shit");
}
