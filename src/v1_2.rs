/*!
unofficial [keyauth](https://keyauth.cc) library that uses 1.2 api version

basic usage:
```rust
let mut auth = keyauth::v1_2::KeyauthApi::new("application name", "ownerid", "application secret", "application version", "api url"); // if you dont have a custom domain for api use "https://keyauth.win/api/1.2/"
auth.init().unwrap();
auth.login("username", "password", Some("hwid".to_string()).unwrap()); // if you want to automaticly generate hwid use None insted.
```

also if you want to use an obfuscator for rust i recommend using [obfstr](https://crates.io/crates/obfstr) and [llvm obfuscator](https://github.com/eshard/obfuscator-llvm/wiki/Rust-obfuscation-guide)
*/

use base16::decode;
use debugoff::multi_ptraceme_or_die;
use goldberg::goldberg_stmts;
use hmac_sha256::HMAC;
use httparse::Header;
use reqwest::header::HeaderMap;
use reqwest::Client;
use reqwest::Response;
use std::collections::HashMap;
use std::io::Read;
use std::net::TcpListener;
use uuid::Uuid;

macro_rules! nodebug {
    () => {
        #[cfg(target_os = "linux")]
        #[cfg(not(debug_assertions))]
        multi_ptraceme_or_die();
    };
}

pub struct Res<T>(Result<T, String>);

impl Default for Res<()> {
    fn default() -> Self {
        Res(Err("Default Error".to_string()))
    }
}

impl Res<()> {
    pub fn inner(self) -> Result<(), String> {
        self.0
    }

    pub fn clone_inner(&self) -> Result<(), String> {
        self.0.clone()
    }

}

struct Resp {
    res: String,
    head: HeaderMap,
}

impl Default for Resp {
    fn default() -> Self {
        Resp {
            res: "Default Resp Error".to_string(),
            head: HeaderMap::new(),
        }
    }
}

struct Data(String);

impl Data {
    fn insert<T: ToString, G: ToString>(&mut self, key: T, val: G) {
        self.0
            .push_str(&format!("{}={}&", key.to_string(), val.to_string()));
    }
}

fn copy_string(bytes: &[u8]) -> String {
    let bytes: Vec<u8> = bytes.to_vec();
    let bytes = bytes.clone();
    let mut string = String::new();
    for byte in bytes {
        string.push(byte as char);
    }
    string
}

/// every function in this struct (accept log) returns a Result and Err("Request was tampered with") will be returned if the request signature doesnt mathc the sha256 hmac of the message
#[derive(Default, Clone)]
pub struct KeyauthApi {
    name: String,
    owner_id: String,
    secret: String,
    version: String,
    enckey: String,
    enckey_s: String,
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
        let res: Self = goldberg_stmts! {{
            nodebug!();
        Self {
            name: name.to_string(),
            owner_id: owner_id.to_string(),
            secret: secret.to_string(),
            version: version.to_string(),
            enckey: String::new(),
            enckey_s: String::new(),
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
        }}};
        res
    }

    /// initializes a session, **required to run before any other function in this struct!!!** accept new
    pub async fn init(&mut self, hash: Option<&str>) -> Res<()> {
        let res = goldberg_stmts! {{
            nodebug!();
        self.enckey = Uuid::new_v4().simple().to_string();
        self.enckey_s = format!("{}-{}", self.enckey, self.secret);
            let mut data = Data(String::new());
            data.insert("type", "init");
            if hash.is_some() {
                data.insert("hash", hash.unwrap());
            }
            data.insert("ver", &self.version);
            data.insert("name", &self.name);
            data.insert("ownerid", &self.owner_id);
            data.insert("enckey", &self.enckey);

        let req = Self::request(data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if resp == "KeyAuth_Invalid" {
            return Res(Err("The application doesn't exist".to_string()));
        }
        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.secret) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();
            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            self.session_id = json_rep["sessionid"].as_str().unwrap().to_string();
            self.num_keys = json_rep["appinfo"]["numKeys"].as_str().unwrap().to_string();
            self.num_online_users = json_rep["appinfo"]["numOnlineUsers"].as_str().unwrap().to_string();
            self.num_users = json_rep["appinfo"]["numUsers"].as_str().unwrap().to_string();
            self.customer_panel_link = json_rep["appinfo"]["customerPanelLink"].as_str().unwrap_or("").to_string();
            Res(Ok(()))
        } else {
            if json_rep["message"].as_str().unwrap() == "invalidver" {
                let download_url = json_rep["download"].as_str().unwrap();
                if !download_url.is_empty() {
                    webbrowser::open(download_url).unwrap();
                }
            }
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// registeres a new user
    pub async fn register(
        &mut self,
        username: String,
        password: String,
        license: String,
        hwid: Option<String>,
    ) -> Res<()> {
        let res = goldberg_stmts! {{
            nodebug!();
        let hwidd = match hwid {
            Some(hwid) => hwid,
            None => machine_uuid::get(),
        };
            let mut req_data = Data(String::new());
            req_data.insert("type", "register");
            req_data.insert("username", &username);
            req_data.insert("pass", &password);
            req_data.insert("key", &license);
            req_data.insert("sessionid", &self.session_id);
            req_data.insert("name", &self.name);
            req_data.insert("ownerid", &self.owner_id);
            req_data.insert("hwid", &hwidd);


        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();
            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            self.username = copy_string(username.as_bytes());
            self.ip = json_rep["info"]["ip"].as_str().unwrap().to_string();
            self.create_date = json_rep["info"]["createdate"].as_str().unwrap().to_string();
            self.last_login = json_rep["info"]["lastlogin"].as_str().unwrap().to_string();
            self.subscription = json_rep["info"]["subscriptions"][0]["subscription"].as_str().unwrap().to_string();
            Res(Ok(()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// upgrades a user license level or extends a license
    pub async fn upgrade(&mut self, username: String, license: String) -> Res<()> {
        let res = goldberg_stmts! {{
            nodebug!();
            let mut req_data = Data(String::new());
            req_data.insert("type", "upgrade");
            req_data.insert("username", &username);
            req_data.insert("key", &license);
            req_data.insert("sessionid", &self.session_id);
            req_data.insert("name", &self.name);
            req_data.insert("ownerid", &self.owner_id);


        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();
            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            Res(Ok(()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// login self explanatory
    pub async fn login(
        &mut self,
        username: String,
        password: String,
        hwid: Option<String>,
    ) -> Res<()> {
        let res = goldberg_stmts! {{
            nodebug!();
        let hwidd = match hwid {
            Some(hwid) => hwid,
            None => machine_uuid::get(),
        };

            let mut req_data = Data(String::new());
            req_data.insert("type", "login");
            req_data.insert("username", &username);
            req_data.insert("pass", &password);
            req_data.insert("hwid", &hwidd);
            req_data.insert("sessionid", &self.session_id);
            req_data.insert("name", &self.name);
            req_data.insert("ownerid", &self.owner_id);


        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            self.username = copy_string(username.as_bytes());
            self.ip = json_rep["info"]["ip"].as_str().unwrap().to_string();
            self.hwid = copy_string(hwidd.as_bytes());
            self.create_date = json_rep["info"]["createdate"].as_str().unwrap().to_string();
            self.last_login = json_rep["info"]["lastlogin"].as_str().unwrap().to_string();
            self.subscription = json_rep["info"]["subscriptions"][0]["subscription"].as_str().unwrap().to_string();
            Res(Ok(()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// <https://docs.keyauth.cc/api/license>
    pub async fn license(&mut self, license: String, hwid: Option<String>) -> Res<()> {
        let res = goldberg_stmts! {{
            nodebug!();
        let hwidd = match hwid {
            Some(hwid) => hwid,
            None => machine_uuid::get(),
        };

            let mut req_data = Data(String::new());
            req_data.insert("type", "license");
            req_data.insert("key", &license);
            req_data.insert("hwid", &hwidd);
            req_data.insert("sessionid", &self.session_id);
            req_data.insert("name", &self.name);
            req_data.insert("ownerid", &self.owner_id);


        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            self.username = json_rep["info"]["username"].as_str().unwrap().to_string();
            self.ip = json_rep["info"]["ip"].as_str().unwrap().to_string();
            self.hwid = copy_string(hwidd.as_bytes());
            self.create_date = json_rep["info"]["createdate"].as_str().unwrap().to_string();
            self.last_login = json_rep["info"]["lastlogin"].as_str().unwrap().to_string();
            self.subscription = json_rep["info"]["subscriptions"][0]["subscription"].as_str().unwrap().to_string();
            Res(Ok(()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// this will get a global variable (not user) and return it
    pub async fn var(&mut self, varid: String) -> Res<String> {
        let res = goldberg_stmts! {{
            nodebug!();
            let mut req_data = Data(String::new());
            req_data.insert("type", "var");
            req_data.insert("varid", &varid);
            req_data.insert("sessionid", &self.session_id);
            req_data.insert("name", &self.name);
            req_data.insert("ownerid", &self.owner_id);


        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            Res(Ok(json_rep["message"].as_str().unwrap().to_string()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// downloads a file, and decodes using base16::decode
    pub async fn file(&mut self, fileid: String) -> Res<Vec<u8>> {
        let res = goldberg_stmts! {{
            nodebug!();
            let mut req_data = Data(String::new());
            req_data.insert("type", "file");
            req_data.insert("fileid", &fileid);
            req_data.insert("sessionid", &self.session_id);
            req_data.insert("name", &self.name);
            req_data.insert("ownerid", &self.owner_id);


        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            Res(Ok(decode(json_rep["contents"].as_str().unwrap()).unwrap()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// sends a webhook from keyauth's servers so the url isnt exposed
    pub async fn webhook(&mut self, webid: String, params: String) -> Res<String> {
        let res = goldberg_stmts! {{
            nodebug!();
            let mut req_data = Data(String::new());
            req_data.insert("type", "webhook");
            req_data.insert("webid", &webid);
            req_data.insert("params", &params);
            req_data.insert("sessionid", &self.session_id);
            req_data.insert("name", &self.name);
            req_data.insert("ownerid", &self.owner_id);


        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            Res(Ok(json_rep["message"].as_str().unwrap().to_string()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// checks if the user is blacklisted and sets self.blacklisted acordingly
    pub async fn checkblacklist(&mut self) -> Res<()> {
        let res = goldberg_stmts! {{
            nodebug!();
        let mut req_data = Data(String::new());
        req_data.insert("type", "checkblacklist");
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            self.blacklisted = true;
            Res(Ok(()))
        } else {
            self.blacklisted = false;
            Res(Ok(()))
        }}};
        res
    }

    /// checks if the session is still active or if it expired
    pub async fn check_session(&mut self) -> Res<bool> {
        let res = goldberg_stmts! {{
            nodebug!();
        let mut req_data = Data(String::new());
        req_data.insert("type", "check");
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        Res(Ok(json_rep["success"].as_bool().unwrap()))
            }};
        res
    }

    /// gets json of online users
    pub async fn fetch_online(&mut self) -> Res<serde_json::Value> {
        let res = goldberg_stmts! {{
            nodebug!();
        let mut req_data = Data(String::new());
        req_data.insert("type", "fetchOnline");
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            Res(Ok(json_rep["users"].clone()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// gets the arry of messages in a channel
    pub async fn get_chat(&mut self, channel: String) -> Res<serde_json::Value> {
        let res = goldberg_stmts! {{
            nodebug!();
        let mut req_data = Data(String::new());
        req_data.insert("type", "chatget");
        req_data.insert("channel", &channel);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            Res(Ok(json_rep["messages"].clone()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// sends a chat message in a channel
    pub async fn send_chat_message(&mut self, channel: String, message: String) -> Res<()> {
        let res = goldberg_stmts! {{
            nodebug!();
        let mut req_data = Data(String::new());
        req_data.insert("type", "chatsend");
        req_data.insert("channel", &channel);
        req_data.insert("message", &message);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            Res(Ok(()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// self explanatory
    pub async fn ban(&mut self) {
        goldberg_stmts! {{
            nodebug!();
        let mut req_data = Data(String::new());
        req_data.insert("type", "ban");
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

            nodebug!();
        Self::request(req_data, &self.api_url).await;}};
    }

    /// sets a user variable to varvalue
    pub async fn setvar(&mut self, varname: String, varvalue: String) -> Res<()> {
        let res = goldberg_stmts! {{
            nodebug!();
        let mut req_data = Data(String::new());
        req_data.insert("type", "setvar");
        req_data.insert("var", &varname);
        req_data.insert("data", &varvalue);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

        self.message = json_rep["message"].as_str().unwrap().to_string();
        self.success = json_rep["success"].as_bool().unwrap();
            nodebug!();
        Res(Ok(()))}};
        res
    }

    /// gets a user variable
    pub async fn getvar(&mut self, varname: String) -> Res<String> {
        let res = goldberg_stmts! {{
            nodebug!();
        let mut req_data = Data(String::new());
        req_data.insert("type", "getvar");
        req_data.insert("var", &varname);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            Res(Ok(json_rep["response"].as_str().unwrap().to_string()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }}};
        res
    }

    /// logs somethink to keyauth
    pub async fn log(&mut self, message: String, pcuser: Option<String>) {
        goldberg_stmts! {{
            nodebug!();
        let usr = match pcuser {
            Some(pcuser) => pcuser,
            None => self.username.clone(),
        };

        let mut req_data = Data(String::new());
        req_data.insert("type", "log");
        req_data.insert("message", &message);
        req_data.insert("pcuser", &usr);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

            nodebug!();
        Self::request(req_data, &self.api_url).await;}}
    }

    /// changes Username,
    pub async fn change_username(&mut self, new_username: String) -> Res<String> {
        let res: Res<String> = goldberg_stmts! {{
            nodebug!();
        let mut req_data = Data(String::new());
        req_data.insert("type", "changeUsername");
        req_data.insert("newUsername", &new_username);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);

        let req = Self::request(req_data, &self.api_url).await;
            let resp = req.res;
            let head = req.head;

        if !head.contains_key("signature") {

            return Res(Err("response was tampered with".to_string()));
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.enckey_s) {

            return Res(Err("response was tampered with".to_string()));
        }
        let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();

            nodebug!();
        if json_rep["success"].as_bool().unwrap() {
            Res(Ok(json_rep["message"].as_str().unwrap().to_string()))
        } else {
            Res(Err(json_rep["message"].as_str().unwrap().to_string()))
        }
        }};
        res
    }

    /// WARNING THIS FUNCTION ISNT OBFUSCATED DUE TO ERRORS
    #[cfg(feature = "web_loader")]
    pub async fn web_login(&mut self, hwid: Option<String>) -> Res<()> {
        use std::io::Write;

        let hwidd = match hwid {
            Some(hwid) => hwid,
            None => self.hwid.clone(),
        };

        let listener = TcpListener::bind("127.0.0.1:1337");
        if listener.is_err() {
            return Res(Err("Couldnt bind to port 1337".to_string()));
        }
        let listener = listener.unwrap();

        for stream in listener.incoming() {
            if stream.is_err() {
                continue;
            }
            let mut stream = stream.unwrap();
            let mut buf = [0u8; 4096];
            stream.read(&mut buf).unwrap();
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut req = httparse::Request::new(&mut headers);
            req.parse(&buf).unwrap();
            if req.path.unwrap().starts_with("/handshake") {
                let s = req.path.unwrap();
                let start = s.find("?user=").unwrap_or(0) + 6;
                let end = s.rfind("&token=").unwrap_or(s.len());
                let user = &s[start..end];
                let start = s.find("&token=").unwrap_or(0) + 7;
                let token = &s[start..];
                let mut req_data = Data(String::new());
                req_data.insert("type", "login");
                req_data.insert("username", &user);
                req_data.insert("token", &token);
                req_data.insert("name", &self.name);
                req_data.insert("ownerid", &self.owner_id);
                req_data.insert("hwid", &self.hwid);
                req_data.insert("sessionid", &self.session_id);

                let req = Self::request(req_data, &self.api_url).await;
                let resp = req.res;
                let head = req.head;

                if !head.contains_key("signature") {
                    return Res(Err("response was tampered with".to_string()));
                }
                let sig = head.get("signature").unwrap().to_str().unwrap();
                if sig != Self::make_hmac(&resp, &self.enckey_s) {
                    return Res(Err("Response was tampered with".to_string()));
                }
                let json_rep: serde_json::Value = serde_json::from_str(&resp).unwrap();
                let (status, body) = if json_rep["success"].as_bool().unwrap() {
                    self.username = copy_string(user.as_bytes());
                    self.ip = json_rep["info"]["ip"].as_str().unwrap().to_string();
                    self.hwid = copy_string(hwidd.as_bytes());
                    self.create_date = json_rep["info"]["createdate"].as_str().unwrap().to_string();
                    self.last_login = json_rep["info"]["lastlogin"].as_str().unwrap().to_string();
                    self.subscription = json_rep["info"]["subscriptions"][0]["subscription"]
                        .as_str()
                        .unwrap()
                        .to_string();

                    ("420", "SHEESH")
                } else {
                    ("200", json_rep["message"].as_str().unwrap())
                };
                let response = format!(
                    r#"HTTP/1.1 {} OK
Access-Control-Allow-Methods: Get, Post
Access-Control-Allow-Origin: *
Via: hugzho's big brain
Location: your kernel ;)
Retry-After: never lmao
Server: \r\n\r\n
{}"#,
                    status, body
                );
                stream.write_all(response.as_bytes()).unwrap();
                return Res(Ok(()));
            }
        }
        Res(Ok(()))
    }

    #[cfg(feature = "web_loader")]
    pub async fn button(&self, button: &str) -> Res<()> {
        let res = goldberg_stmts! {{
        use std::io::Write;

        let listener = TcpListener::bind("127.0.0.1:1337");
        if listener.is_err() {
            return Res(Err("Couldnt bind to port 1337".to_string()));
        }
        let listener = listener.unwrap();

        for stream in listener.incoming() {
            if stream.is_err() {
                continue;
            }
            let mut stream = stream.unwrap();
            let mut buf = [0u8; 4096];
            stream.read(&mut buf).unwrap();
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut req = httparse::Request::new(&mut headers);
            req.parse(&buf).unwrap();
            if req.path.unwrap().starts_with(format!("/{}", button).as_str()) {
                let response = format!(r#"HTTP/1.1 {} OK
Access-Control-Allow-Methods: Get, Post
Access-Control-Allow-Origin: *
Via: hugzho's big brain
Location: your kernel ;)
Retry-After: never lmao
Server: \r\n\r\n

{}"#, 420, "SHEESH");
                stream.write_all(response.as_bytes()).unwrap();
                return Res(Ok(()));
            }
        }
        Res(Ok(()))}};
        res
    }

    async fn request(req_data: Data, url: &str) -> Resp {
        let res: Resp = goldberg_stmts! {{
        let client = Client::new();
        let req_data_str = req_data.0.strip_suffix("&").unwrap().to_string();
            nodebug!();
        let res = client.post(url.to_string())
            .body(req_data_str)
            .header("User-Agent", "KeyAuth")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send().await.unwrap();
        let resp = Resp {
            head: res.headers().clone(),
            res: res.text().await.unwrap()
        };
        resp}};
        res
    }

    fn make_hmac(message: &str, key: &str) -> String {
        let res: String = goldberg_stmts! {{ hex::encode(HMAC::mac(message, key)).to_string()}};
        res
    }
}
