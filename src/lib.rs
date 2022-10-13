use uuid::Uuid;
use std::collections::HashMap;
use reqwest::blocking::Client;
use hmac_sha256::HMAC;

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
    pub fn new(name: &str, owner_id: &str, secret: &str, version: &str, api_url: &str) -> Self {
        Self {
            name: name.to_string(),
            owner_id: owner_id.to_string(),
            secret: secret.to_string(),
            version: version.to_string(),
            enckey: String::new(),
            enckey_s: String::new(),
            session_id: String::new(),
            api_url: api_url.to_string(),
            num_keys: String::new(),
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

    pub fn init(&mut self) -> Result<(), String> {
        self.enckey = Uuid::new_v4().simple().to_string();
        self.enckey_s = format!("{}-{}", self.enckey, self.secret);
        let mut req_data = HashMap::new();
        req_data.insert("type", "init");
        req_data.insert("ver", &self.version);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);
        req_data.insert("enckey", &self.enckey);

        let req = Self::request(req_data, &self.api_url);
        let head = req.headers().clone();
        let resp = req.text().unwrap();

        if resp == "KeyAuth_Invalid" {
            return Err("The application doesn't exist".to_string());
        }
        if head.contains_key("signature") == false {
            return Err("Request was tampered with".to_string());
        }
        let sig = head.get("signature").unwrap().to_str().unwrap();
        if sig != Self::make_hmac(&resp, &self.secret) {
            return Err("Request was tampered with".to_string());
        }
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

    pub fn register(&mut self, username: String, password: String, license: String) -> Result<(), String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "register");
        req_data.insert("username", &username);
        req_data.insert("pass", &password);
        req_data.insert("key", &license);
        req_data.insert("sessionid", &self.session_id);
        req_data.insert("name", &self.name);
        req_data.insert("ownerid", &self.owner_id);
        req_data.insert("hwid", &self.hwid);

        let req = Self::request(req_data, &self.api_url);
        let head = req.headers().clone();
        let resp = req.text().unwrap();

    }

    fn request(req_data: HashMap<&str, &str>, url: &str) -> reqwest::blocking::Response {
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

    fn make_hmac(message: &str, key: &str) -> String {
        hex::encode(HMAC::mac(message, key)).to_string()
    }
}