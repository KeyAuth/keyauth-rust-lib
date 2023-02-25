/*!
unofficial [keyauth](https://keyauth.cc) library that uses 1.2 api version

basic usage:
```rust
let mut auth = keyauth::KeyauthApi::new("application name", "ownerid", "application secret", "application version", "api url"); // if you dont have a custom domain for api use "https://keyauth.win/api/1.2/"
auth.init().unwrap();
auth.login("username", "password", Some("hwid".to_string())).unwrap(); // if you want to automaticly generate hwid use None insted.
```

also if you want to use an obfuscator for rust i recommend using [obfstr](https://crates.io/crates/obfstr) and [llvm obfuscator](https://github.com/eshard/obfuscator-llvm/wiki/Rust-obfuscation-guide)
*/

use uuid::Uuid;
use std::collections::HashMap;
use reqwest::blocking::Client;
use hmac_sha256::HMAC;
use base16::{decode, encode_lower};

use sha256::{digest, try_digest};
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// every function in this struct (accept log) returns a Result and Err("Request was tampered with") will be returned if the request signature doesnt mathc the sha256 hmac of the message
pub struct KeyauthApi {
    name: String,
    owner_id: String,
    secret: String,
    version: String,
    enckey: String,
    session_id: String,
    pub api_url: String,
    pub num_keys: String,
    pub num_online_users: String,
    pub num_users: String,
    pub app_version: String,
    pub customer_panel_link: String,
    pub username: String,
    pub ip: String,
    pub hwid: String,
    pub create_date: String,
    pub last_login: String,
    pub subscription: String,
    pub message: String,
    pub success: bool,
    pub blacklisted: bool,
    pub response: String,
}

impl KeyauthApi {
    /// creats a new KeyauthApi and its defaults, api_url has to be api version 1.2 example: "https://keyauth.win/api/1.2/" or if you have a custom api domain: "https://api.example.com/1.2/"
    pub fn new(name: &str, owner_id: &str, secret: &str, version: &str, api_url: &str) -> Self {
        Self {
            name: name.to_string(),
            owner_id: owner_id.to_string(),
            secret: secret.to_string(),
            version: version.to_string(),
            enckey: String::new(),
            session_id: String::new(),
            num_keys: String::new(),
            api_url: api_url.to_string(),
            num_online_users: String::new(),
            num_users: String::new(),
            app_version: version.to_string(),
            customer_panel_link: String::new(),
            username: String::new(),
            ip: String::new(),
            hwid: machine_uuid::get(),
            create_date: String::new(),
            last_login: String::new(),
            subscription: String::new(),
            message: String::new(),
            success: false,
            blacklisted: false,
            response: String::new(),
        }
    }

    /// initializes a session, **required to run before any other function in this struct!!!** accept new
    pub fn init(&mut self, hash: Option<&str>) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();
        self.enckey = Self::gen_init_iv();

        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"init"));
        if hash.is_some() {
            req_data.insert("hash", Encryption::encrypt(hash.unwrap(), &self.secret, &init_iv));
        }
        req_data.insert("ver", Encryption::encrypt(&self.version, &self.secret, &init_iv));
        req_data.insert("name", encode_lower(&self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(&self.owner_id.as_bytes()));
        req_data.insert("enckey", Encryption::encrypt(&self.enckey, &self.secret, &init_iv));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.secret, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();
        if json_rep["success"].as_bool().unwrap() {
            self.session_id = json_rep["sessionid"].as_str().unwrap().to_string();
            self.num_keys = json_rep["appinfo"]["numKeys"].as_str().unwrap().to_string();
            self.num_online_users = json_rep["appinfo"]["numOnlineUsers"].as_str().unwrap().to_string();
            self.num_users = json_rep["appinfo"]["numUsers"].as_str().unwrap().to_string();
            self.customer_panel_link = json_rep["appinfo"]["customerPanelLink"].as_str().unwrap_or("").to_string();
            Ok(())
        } else {
            if json_rep["message"].as_str().unwrap() == "invalidver" {
                let download_url = json_rep["download"].as_str().unwrap();
                if !download_url.is_empty() {
                    webbrowser::open(download_url).unwrap();
                }
            }
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// registeres a new user
    pub fn register(&mut self, username: String, password: String, license: String, hwid: Option<String>) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();

        let hwidd = match hwid {
            Some(hwid) => hwid,
            None => machine_uuid::get(),
        };
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"register"));
        req_data.insert("username", Encryption::encrypt(&username, &self.enckey, &init_iv));
        req_data.insert("pass", Encryption::encrypt(&password, &self.enckey, &init_iv));
        req_data.insert("key", Encryption::encrypt(&license, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("hwid", Encryption::encrypt(&hwidd, &self.enckey, &init_iv));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();
        if json_rep["success"].as_bool().unwrap() {
            self.username = username;
            self.ip = json_rep["info"]["ip"].as_str().unwrap().to_string();
            self.create_date = json_rep["info"]["createdate"].as_str().unwrap().to_string();
            self.last_login = json_rep["info"]["lastlogin"].as_str().unwrap().to_string();
            self.subscription = json_rep["info"]["subscriptions"][0]["subscription"].as_str().unwrap().to_string();
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// upgrades a user license level or extends a license
    pub fn upgrade(&mut self, username: String, license: String) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();

        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"upgrade"));
        req_data.insert("username", Encryption::encrypt(&username, &self.enckey, &init_iv));
        req_data.insert("key", Encryption::encrypt(&license, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();
        if json_rep["success"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// login self explanatory
    pub fn login(&mut self, username: String, password: String, hwid: Option<String>) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();
        let hwidd = match hwid {
            Some(hwid) => hwid,
            None => machine_uuid::get(),
        };
        self.hwid = hwidd.clone();

        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"login"));
        req_data.insert("username", Encryption::encrypt(&username, &self.enckey, &init_iv));
        req_data.insert("pass", Encryption::encrypt(&password, &self.enckey, &init_iv));
        req_data.insert("hwid", Encryption::encrypt(&hwidd, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            self.username = username;
            self.ip = json_rep["info"]["ip"].as_str().unwrap().to_string();
            self.hwid = hwidd;
            self.create_date = json_rep["info"]["createdate"].as_str().unwrap().to_string();
            self.last_login = json_rep["info"]["lastlogin"].as_str().unwrap().to_string();
            self.subscription = json_rep["info"]["subscriptions"][0]["subscription"].as_str().unwrap().to_string();
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// <https://docs.keyauth.cc/api/license>
    pub fn license(&mut self, license: String, hwid: Option<String>) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();
        let hwidd = match hwid {
            Some(hwid) => hwid,
            None => machine_uuid::get(),
        };

        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"license"));
        req_data.insert("key", Encryption::encrypt(&license, &self.enckey, &init_iv));
        req_data.insert("hwid", Encryption::encrypt(&hwidd, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            self.username = json_rep["info"]["username"].as_str().unwrap().to_string();
            self.ip = json_rep["info"]["ip"].as_str().unwrap().to_string();
            self.hwid = hwidd;
            self.create_date = json_rep["info"]["createdate"].as_str().unwrap().to_string();
            self.last_login = json_rep["info"]["lastlogin"].as_str().unwrap().to_string();
            self.subscription = json_rep["info"]["subscriptions"][0]["subscription"].as_str().unwrap().to_string();
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// this will get a global variable (not user) and return it
    pub fn var(&mut self, varid: String) -> Result<String, String> {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"var"));
        req_data.insert("varid", Encryption::encrypt(&varid, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["message"].as_str().unwrap().to_string())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// downloads a file, and decodes using base16::decode
    pub fn file(&mut self, fileid: String) -> Result<Vec<u8>, String> {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"file"));
        req_data.insert("fileid", Encryption::encrypt(&fileid, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(decode(json_rep["contents"].as_str().unwrap()).unwrap())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// sends a webhook from keyauth's servers so the url isnt exposed
    pub fn webhook(&mut self, webid: String, params: String) -> Result<String, String> {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"webhook"));
        req_data.insert("webid", Encryption::encrypt(&webid, &self.enckey, &init_iv));
        req_data.insert("params", Encryption::encrypt(&params, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["message"].as_str().unwrap().to_string())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// checks if the user is blacklisted and sets self.blacklisted acordingly
    pub fn checkblacklist(&mut self) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"checkblacklist"));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("hwid", Encryption::encrypt(&self.hwid, &self.enckey, &init_iv));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            self.blacklisted = true;
            Ok(())
        } else {
            self.blacklisted = false;
            Ok(())
        }
    }

    /// checks if the session is still active or if it expired
    pub fn check_session(&mut self) -> Result<bool, String> {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"check"));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        Ok(json_rep["success"].as_bool().unwrap())
    }

    /// gets json of online users
    pub fn fetch_online(&mut self) -> Result<serde_json::Value, String> {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"fetchOnline"));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["users"].clone())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// gets the arry of messages in a channel
    pub fn get_chat(&mut self, channel: String) -> Result<serde_json::Value, String> {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"chatget"));
        req_data.insert("channel", Encryption::encrypt(&channel, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["messages"].clone())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// sends a chat message in a channel
    pub fn send_chat_message(&mut self, channel: String, message: String) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"chatsend"));
        req_data.insert("channel", Encryption::encrypt(&channel, &self.enckey, &init_iv));
        req_data.insert("message", Encryption::encrypt(&message, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// self explanatory
    pub fn ban(&mut self) {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"ban"));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        Self::request(req_data, &self.api_url);
    }

    /// sets a user variable to varvalue
    pub fn setvar(&mut self, varname: String, varvalue: String) -> Result<(), String> {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"setvar"));
        req_data.insert("var", Encryption::encrypt(&varname, &self.enckey, &init_iv));
        req_data.insert("data", Encryption::encrypt(&varvalue, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        self.message = json_rep["message"].as_str().unwrap().to_string();
        self.success = json_rep["success"].as_bool().unwrap();
        Ok(())
    }

    /// gets a user variable
    pub fn getvar(&mut self, varname: String) -> Result<String, String> {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"getvar"));
        req_data.insert("var", Encryption::encrypt(&varname, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["response"].as_str().unwrap().to_string())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    /// logs somethink to keyauth
    pub fn log(&mut self, message: String, pcuser: Option<String>) {
        let init_iv = Self::gen_init_iv();
        let usr = match pcuser {
            Some(pcuser) => pcuser,
            None => self.username.clone(),
        };

        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"log"));
        req_data.insert("message", Encryption::encrypt(&message, &self.enckey, &init_iv));
        req_data.insert("pcuser", Encryption::encrypt(&usr, &self.enckey, &init_iv));
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        Self::request(req_data, &self.api_url);
    }

    /// changes Username, 
    pub fn change_username(&mut self, new_username: String) -> Result<String, String> {
        let init_iv = Self::gen_init_iv();
        let mut req_data = HashMap::new();
        req_data.insert("type", encode_lower(b"changeUsername"));
        req_data.insert("newUsername", new_username);
        req_data.insert("sessionid", encode_lower(self.session_id.as_bytes()));
        req_data.insert("name", encode_lower(self.name.as_bytes()));
        req_data.insert("ownerid", encode_lower(self.owner_id.as_bytes()));
        req_data.insert("init_iv", init_iv.to_string());

        let req = Self::request(req_data, &self.api_url);
        let resp = req.text().unwrap();

        let resp = Encryption::decrypt(resp, &self.enckey, &init_iv);
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        if json_rep["success"].as_bool().unwrap() {
            Ok(json_rep["message"].as_str().unwrap().to_string())
        } else {
            Err(json_rep["message"].as_str().unwrap().to_string())
        }
    }

    fn request(req_data: HashMap<&str, String>, url: &str) -> reqwest::blocking::Response {
        let client = Client::new();
        let mut req_data_str = String::new();
        for d in req_data {
            req_data_str.push_str(&format!("{}={}&", d.0, d.1))
        }
        req_data_str = req_data_str.strip_suffix("&").unwrap().to_string();
        client.post(url.to_string())
            .body(req_data_str)
            .header("User-Agent", "KeyAuth")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send().unwrap()
    }

    fn gen_init_iv() -> String {
        let session_iv = Uuid::new_v4().to_string()[..8].to_string();
        digest(session_iv.as_bytes())
    }
}

struct Encryption;
impl Encryption {
    fn encrypt_string(plain_text: &[u8], key: &[u8], iv: &[u8]) -> String {
        let mut buffer = [0u8; 128];
        let pos = plain_text.len();
        buffer[..pos].copy_from_slice(plain_text);
        let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
        let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
        encode_lower(ciphertext)
    }

    fn decrypt_string(cipher_text: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        let cipher_text = decode(cipher_text).unwrap();
        let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
        cipher.decrypt_vec(&cipher_text).unwrap()
    }

    fn encrypt(message: &str, enc_key: &str, iv: &str) -> String {
        let mut hasher = sha256::digest(enc_key.as_bytes());
        let key: String = hasher[..32].to_owned();

        let mut hasher = sha256::digest(iv.as_bytes());
        let iv: String = hasher[..16].to_owned();
        Encryption::encrypt_string(message.as_bytes(), key.as_bytes(), iv.as_bytes())
    }

    fn decrypt(message: String, enc_key: &str, iv: &str) -> String {
        let mut hasher = sha256::digest(enc_key.as_bytes());
        let key: String = hasher[..32].to_owned();

        let mut hasher = sha256::digest(iv.as_bytes());
        let iv: String = hasher[..16].to_owned();
        String::from_utf8(Encryption::decrypt_string(
            message.as_bytes(),
            key.as_bytes(),
            iv.as_bytes(),
        ))
            .unwrap()
    }
}