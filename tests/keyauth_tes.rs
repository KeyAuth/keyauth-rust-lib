#[cfg(test)]
#[test]
fn all() {
    let mut auth = keyauth::KeyauthApi::new("unofficial-rust-lib-tests", "EdmsTKiuld", obfstr::obfstr!("ed5f9320adef4718cb4b6da15de74ee86aecbc081373f5556986f9b61f0de40c"), "1.0", "https://keyauth.win/api/1.2/");
    let mut res = auth.init();
    if res.is_ok() {
        assert!(true);
    } else {
        println!("{}", res.err().unwrap());
        assert!(false);
    }
    //register
//    res = auth.register(uuid::Uuid::new_v4().simple().to_string(), uuid::Uuid::new_v4().simple().to_string(), "A14076-E4NEW0-SRJP74-U24P9D-Z3PDA1-4SUQVA".to_string());
//    if res.is_ok() {
//        assert!(true);
//    } else {
//        println!("{}", res.err().unwrap());
//        assert!(false);
//    }

    
}