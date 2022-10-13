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
//    let username = uuid::Uuid::new_v4().simple().to_string();
//    res = auth.register(username.clone(), uuid::Uuid::new_v4().simple().to_string(), "QMNTLV-TMFZZ1-D65IA6-KDTN5D-B526SV-VR2SAY".to_string());
//    if res.is_ok() {
//        assert!(true);
//    } else {
//        println!("{}", res.err().unwrap());
//        assert!(false);
//    }

    //upgrade
//    res = auth.upgrade(username.clone(), "KFGDHI-MVJECD-Z8NR7J-M64HSJ-KL81MY-JBPQ1I".to_string());
//    if res.is_ok() {
//        assert!(true);
//    } else {
//        println!("{}", res.err().unwrap());
//        assert!(false);
//    }

    //login
//    res = auth.login("e5b8584bbf614e32ae65ae677da69f65".to_string(), "idfk".to_string(), None);
//    if res.is_ok() {
//        assert!(true);
//    } else {
//        println!("{}", res.err().unwrap());
//        assert!(false);
//    }
}