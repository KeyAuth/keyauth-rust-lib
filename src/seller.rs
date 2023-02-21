use std::collections::HashMap;
use reqwest::blocking::{Client};
use serde_json::Value;

pub(crate) fn request(req_data: HashMap<&str, &str>, url: String) -> reqwest::blocking::Response {
    let client = Client::new();
    client.get(url)
        .query(&req_data)
        .header("User-Agent", "KeyAuth")
        .send().unwrap()
}

/// https://docs.keyauth.cc/seller/licenses
pub mod licenses {
    use std::collections::HashMap;
    use reqwest::StatusCode;
    use serde_json::Value;

    /// returns a list of licenses, if errors returns a response message
    pub fn create(sellerkey: &str, url: String, expiry: u64, mask: Option<String>, level: Option<i32>, amount: Option<u8>, owner: Option<String>) -> Result<Vec<String>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("type", "add");
        req_data.insert("sellerkey", &sellerkey);
        let expiry = expiry.to_string();
        req_data.insert("expiry", expiry.as_str());
        let mask = match mask {
            Some(m) => m,
            None => "XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX".to_string(),
        };
        req_data.insert("mask", mask.as_str());
        let level = match level {
            Some(l) => l,
            None => 1,
        };
        let level = level.to_string();
        req_data.insert("level", level.as_str());
        let amount = match amount {
            Some(a) => a,
            None => 1,
        };
        let amount = amount.to_string();
        req_data.insert("amount", amount.as_str());
        let owner = match owner {
            Some(o) => o,
            None => "none".to_string(),
        };
        if owner != "none" {
            req_data.insert("owner", owner.as_str());
        }


        let res = super::request(req_data, url);
        let status = res.status();
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if !json["success"].as_bool().unwrap() {
            return Err(json["message"].to_string());
        }
        if status == StatusCode::OK {
            return Ok(vec![json["key"].as_str().unwrap().to_string()]);
        } else if status == StatusCode::FOUND {
            return Ok(json["keys"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect());
        }
        Err("SOMETHING RLY BAD HAPPENED PLEASE CONTACT THE LIB DEVELOPER".to_string())
    }

    /// returns message from keyauth Ok(message) if success = true and Err(message) if success = false
    pub fn verify_license_exists(sellerkey: &str, url: String, license: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("key", license);
        req_data.insert("type", "verify");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    /// returns message from keyauth Ok(message) if success = true and Err(message) if success = false
    pub fn use_license_create_user(sellerkey: &str, url: String, user: &str, license: &str, pass: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("key", license);
        req_data.insert("type", "activate");
        req_data.insert("user", user);
        req_data.insert("pass", pass);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    /// user_too = 1 deletes the user too, None or 0 for no
    pub fn delete(sellerkey: &str, url: String, license: &str, user_too: Option<bool>) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("key", license);
        req_data.insert("type", "del");
        let user_too = match user_too {
            Some(u) => u,
            None => false,
        };
        let user_too = if user_too { 1 } else { 0 };
        let user_too = user_too.to_string();
        req_data.insert("user_too", user_too.as_str());

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete_unused(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delunused");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete_used(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delused");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete_all(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delalllicenses");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    /// if success = true returns a vector of all keys, the json/Value format can be found here https://docs.keyauth.cc/seller/licenses in the example response
    pub fn fetch_all(sellerkey: &str, url: String) -> Result<Vec<Value>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchallkeys");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["keys"].as_array().unwrap().to_owned());
        }
        Err(json["message"].to_string())
    }

    /// time is in number of days according to api docs
    pub fn add_time_to_unused(sellerkey: &str, url: String, time: u64) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "addtime");
        let time = time.to_string();
        req_data.insert("time", time.as_str());

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn ban(sellerkey: &str, url: String, license: &str, reason: &str, user_too: Option<bool>) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "ban");
        req_data.insert("key", license);
        req_data.insert("reason", reason);
        let user_too = match user_too {
            Some(u) => u,
            None => false,
        };
        let user_too = if user_too { 1 } else { 0 };
        let user_too = user_too.to_string();
        req_data.insert("user_too", user_too.as_str());

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn unban(sellerkey: &str, url: String, license: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "unban");
        req_data.insert("key", license);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn retrieve_from_user(sellerkey: &str, url: String, user: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "getkey");
        req_data.insert("user", user);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["key"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn set_note(sellerkey: &str, url: String, license: &str, note: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "setnote");
        req_data.insert("key", license);
        req_data.insert("note", note);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }
}
/// https://docs.keyauth.cc/seller/users
pub mod user {
    use std::collections::HashMap;
    use serde_json::Value;

    /// if pass -> Null then the password will be set when the user first logs in
    pub fn create(sellerkey: &str, url: String, name: &str, sub: &str, expiry: u64, pass: Option<String>) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "adduser");
        req_data.insert("user", name);
        req_data.insert("sub", sub);
        let expiry = expiry.to_string();
        req_data.insert("expiry", expiry.as_str());
        let pass = match pass {
            Some(p) => p,
            None => "null".to_string(),
        };
        if pass != "null" {
            req_data.insert("pass", pass.as_str());
        }


        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete(sellerkey: &str, url: String, name: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "deluser");
        req_data.insert("user", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete_expired(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delexpusers");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn reset_hwid(sellerkey: &str, url: String, name: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "resetuser");
        req_data.insert("user", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    /// name can be all or a specific user
    pub fn set_var(sellerkey: &str, url: String, name: &str, var: &str, value: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "setvar");
        req_data.insert("user", name);
        req_data.insert("var", var);
        req_data.insert("data", value);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn get_var_data(sellerkey: &str, url: String, name: &str, var: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "getvar");
        req_data.insert("user", name);
        req_data.insert("var", var);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["response"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn del_all_vars(sellerkey: &str, url: String, var: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "massUserVarDelete");
        req_data.insert("name", var);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn ban(sellerkey: &str, url: String, name: &str, reason: Option<String>) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "banuser");
        req_data.insert("user", name);
        let reason = match reason {
            Some(r) => r,
            None => "null".to_string(),
        };
        if reason != "null" {
            req_data.insert("reason", &reason);
        }

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn unban(sellerkey: &str, url: String, name: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "unbanuser");
        req_data.insert("user", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete_var(sellerkey: &str, url: String, name: &str, var: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "deluservar");
        req_data.insert("user", name);
        req_data.insert("var", var);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete_user_subscription(sellerkey: &str, url: String, name: &str, sub: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delsub");
        req_data.insert("user", name);
        req_data.insert("sub", sub);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    /// name can be all
    pub fn extend_user_subscription(sellerkey: &str, url: String, name: &str, sub: &str, days: &str, active_only: Option<bool>) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "extend");
        req_data.insert("user", name);
        req_data.insert("sub", sub);
        req_data.insert("expiry", days);
        let active_only = match active_only {
            Some(a) => a,
            None => false,
        };
        let active_only = if active_only { "1" } else { "0" };
        req_data.insert("active_only", active_only);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    /// name can be all
    pub fn subtract_subscription(sellerkey: &str, url: String, name: &str, sub: &str, seconds: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "subtract");
        req_data.insert("user", name);
        req_data.insert("sub", sub);
        req_data.insert("seconds", seconds);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete_all_user_subscriptions(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "dellallusers");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn reset_all_hwid(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "resetalluser");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn verify_exists(sellerkey: &str, url: String, name: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "verifyuser");
        req_data.insert("user", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn add_hwid(sellerkey: &str, url: String, name: &str, hwid: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "addhwiduser");
        req_data.insert("user", name);
        req_data.insert("hwid", hwid);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    /// json/Value structure can be found https://docs.keyauth.cc/seller/users in the example response
    pub fn fetch_all_users(sellerkey: &str, url: String) -> Result<Vec<Value>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchallusers");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["users"].as_array().unwrap().to_vec());
        }
        Err(json["message"].to_string())
    }

    pub fn change_password(sellerkey: &str, url: String, name: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "resetpw");
        req_data.insert("user", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    /// json/Value structure can be found https://docs.keyauth.cc/seller/users in the example response
    pub fn fetch_all_vars(sellerkey: &str, url: String) -> Result<Vec<Value>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchalluservars");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["vars"].as_array().unwrap().to_vec());
        }
        Err(json["message"].to_string())
    }

    pub fn user_data(sellerkey: &str, url: String, name: &str) -> Result<Value, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "userdata");
        req_data.insert("user", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json);
        }
        Err(json["message"].to_string())
    }

    pub fn fetch_all_usernames(sellerkey: &str, url: String) -> Result<Vec<String>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchallusernames");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["usernames"].as_array().unwrap().iter().map(|x| x.to_string()).collect());
        }
        Err(json["message"].to_string())
    }

    pub fn count_subscriptions(sellerkey: &str, url: String, name: &str) -> Result<i64, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "countsubs");
        req_data.insert("name", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["count"].as_i64().unwrap());
        }
        Err(json["message"].to_string())
    }

    /// cooldown in seconds
    pub fn set_user_cooldown(sellerkey: &str, url: String, name: &str, cooldown: i64) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "setcooldown");
        req_data.insert("user", name);
        let cooldown = cooldown.to_string();
        req_data.insert("cooldown", cooldown.as_str());

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }
}

pub mod subscriptions {
    use std::collections::HashMap;
    use serde_json::Value;

    pub fn create(sellerkey: &str, url: String, name: &str, level: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "addsub");
        req_data.insert("name", name);
        req_data.insert("level", level);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete(sellerkey: &str, url: String, name: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delappsub");
        req_data.insert("name", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct Sub {
        pub name: String,
        pub level: String,
    }

    pub fn fetch_all(sellerkey: &str, url: String) -> Result<Vec<Sub>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchallsubs");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["subs"].as_array().unwrap().to_vec().iter().map(|x| serde_json::from_value(x.clone()).unwrap()).collect());
        }
        Err(json["message"].to_string())
    }

    pub fn edit(sellerkey: &str, url: String, name: &str, level: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "editsub");
        req_data.insert("name", name);
        req_data.insert("level", level);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }
}

pub mod chat {
    use std::collections::HashMap;
    use serde_json::Value;

    /// delay in seconds
    pub fn create_channel(sellerkey: &str, url: String, name: &str, delay: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "addchannel");
        req_data.insert("name", name);
        req_data.insert("delay", delay);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete_channel(sellerkey: &str, url: String, name: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delchannel");
        req_data.insert("name", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn edit_channel(sellerkey: &str, url: String, name: &str, delay: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "editchan");
        req_data.insert("name", name);
        req_data.insert("delay", delay);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn clear_channel(sellerkey: &str, url: String, name: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "clearchannel");
        req_data.insert("name", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    /// time in seconds
    pub fn mute_user(sellerkey: &str, url: String, user: &str, time: u64) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "muteuser");
        req_data.insert("user", user);
        let time = time.to_string();
        req_data.insert("time", time.as_str());

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn unmute_user(sellerkey: &str, url: String, user: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "unmuteuser");
        req_data.insert("user", user);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn fetch_all_channels(sellerkey: &str, url: String) -> Result<Vec<Value>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchallchats");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["chats"].as_array().unwrap().to_vec());
        }
        Err(json["message"].to_string())
    }

    pub fn fetch_all_mutes(sellerkey: &str, url: String) -> Result<Vec<Value>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchallmutes");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["mutes"].as_array().unwrap().to_vec());
        }
        Err(json["message"].to_string())
    }
}

pub mod sessions {
    use std::collections::HashMap;
    use serde_json::Value;

    pub fn kill(sellerkey: &str, url: String, session: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "kill");
        req_data.insert("session", session);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn kill_all(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "killall");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn list_all(sellerkey: &str, url: String) -> Result<Vec<Value>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchallsessions");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["sessions"].as_array().unwrap().to_vec());
        }
        Err(json["message"].to_string())
    }
}

pub fn webhook_create(sellerkey: &str, url: String, baseurl: &str, user_agent: &str, authed: Option<bool>) -> Result<String, String> {
    let mut req_data = HashMap::new();
    req_data.insert("sellerkey", sellerkey);
    req_data.insert("type", "addwebhook");
    req_data.insert("baseurl", baseurl);
    req_data.insert("ua", user_agent);
    let authed = authed.unwrap_or(false);
    let authed = if authed { "1" } else { "0" };
    req_data.insert("authed", authed);

    let res = request(req_data, url);
    let resp = res.text().unwrap();
    let json: Value = serde_json::from_str(&resp).unwrap();
    if json["success"].as_bool().unwrap() {
        return Ok(json["message"].to_string());
    }
    Err(json["message"].to_string())
}

pub mod files {
    use std::collections::HashMap;
    use serde_json::Value;

    pub fn upload(sellerkey: &str, url: String, url_to_file: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "upload");
        req_data.insert("url", url_to_file);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete(sellerkey: &str, url: String, file_id: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delfile");
        req_data.insert("fileid", file_id);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn del_all_files(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delallfiles");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn fetch_all_files(sellerkey: &str, url: String) -> Result<Vec<Value>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchallfiles");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["files"].as_array().unwrap().to_vec());
        }
        Err(json["message"].to_string())
    }
}

pub mod variables {
    use std::collections::HashMap;
    use serde_json::Value;

    pub fn create(sellerkey: &str, url: String, name: &str, value: &str, authed: bool) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "addvar");
        req_data.insert("name", name);
        req_data.insert("data", value);
        let authed = if authed { "1" } else { "0" };
        req_data.insert("authed", authed);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn edit(sellerkey: &str, url: String, name: &str, value: &str, ) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "editvar");
        req_data.insert("varid", name);
        req_data.insert("data", value);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn retrieve(sellerkey: &str, url: String, name: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "retrvvar");
        req_data.insert("name", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn fetch_all(sellerkey: &str, url: String) -> Result<Vec<Value>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchallvars");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["vars"].as_array().unwrap().to_vec());
        }
        Err(json["message"].to_string())
    }

    pub fn delete(sellerkey: &str, url: String, name: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delvar");
        req_data.insert("name", name);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete_all(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delallvars");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }
}

pub mod blacklists {
    use std::collections::HashMap;
    use serde_json::Value;

    pub fn add(sellerkey: &str, url: String, ip: Option<&str>, hwid: Option<&str>) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "black");
        if ip.is_some() {
            req_data.insert("ip", ip.unwrap());
        }
        if hwid.is_some() {
            req_data.insert("hwid", hwid.unwrap());
        }

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    /// blacktype can be "ip" or "hwid"
    pub fn delete(sellerkey: &str, url: String, data: &str, blacktype: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delblack");
        req_data.insert("data", data);
        req_data.insert("blacktype", blacktype);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete_all(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delblacks");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn fetch_all(sellerkey: &str, url: String) -> Result<Vec<Value>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchallblacks");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["blacklists"].as_array().unwrap().to_vec());
        }
        Err(json["message"].to_string())
    }

    pub fn add_whitelist(sellerkey: &str, url: String, ip: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "addWhite");
        req_data.insert("ip", ip);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn del_whitelist(sellerkey: &str, url: String, ip: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "delWhite");
        req_data.insert("ip", ip);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }
}

pub mod settings {
    use std::collections::HashMap;
    use serde_json::Value;

    pub fn retrieve(sellerkey: &str, url: String) -> Result<Value, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "getsettings");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json);
        }
        Err(json["message"].to_string())
    }

    pub struct Settings {
        pub enabled: bool,
        pub hwidcheck: bool,
        pub ver: String,
        pub download: String,
        pub webhook: String,
        pub resellerstore: String,
        pub appdisabled: String,
        pub usernametaken: String,
        pub keynotfound: String,
        pub keyused: String,
        pub nosublevel: String,
        pub usernamenotfound: String,
        pub passmismatch: String,
        pub hwidmismatch: String,
        pub noactivesubs: String,
        pub hwidblacked: String,
        pub keypaused: String,
        pub keyexpired: String,
        pub sellixsecret: String,
        pub dayproduct: String,
        pub weekprocuct: String,
        pub monthproduct: String,
        pub lifetimeproduct: String,
    }

    pub fn update(sellerkey: &str, url: String, settings: Settings) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "updatesettings");
        let enabled = settings.enabled.to_string();
        req_data.insert("enabled", enabled.as_str());
        let hwidcheck = settings.hwidcheck.to_string();
        req_data.insert("hwidcheck", hwidcheck.as_str());
        req_data.insert("ver", settings.ver.as_str());
        req_data.insert("download", settings.download.as_str());
        req_data.insert("webhook", settings.webhook.as_str());
        req_data.insert("resellerstore", settings.resellerstore.as_str());
        req_data.insert("appdisabled", settings.appdisabled.as_str());
        req_data.insert("usernametaken", settings.usernametaken.as_str());
        req_data.insert("keynotfound", settings.keynotfound.as_str());
        req_data.insert("keyused", settings.keyused.as_str());
        req_data.insert("nosublevel", settings.nosublevel.as_str());
        req_data.insert("usernamenotfound", settings.usernamenotfound.as_str());
        req_data.insert("passmismatch", settings.passmismatch.as_str());
        req_data.insert("hwidmismatch", settings.hwidmismatch.as_str());
        req_data.insert("noactivesubs", settings.noactivesubs.as_str());
        req_data.insert("hwidblacked", settings.hwidblacked.as_str());
        req_data.insert("keypaused", settings.keypaused.as_str());
        req_data.insert("keyexpired", settings.keyexpired.as_str());
        req_data.insert("sellixsecret", settings.sellixsecret.as_str());
        req_data.insert("dayproduct", settings.dayproduct.as_str());
        req_data.insert("weekprocuct", settings.weekprocuct.as_str());
        req_data.insert("monthproduct", settings.monthproduct.as_str());
        req_data.insert("lifetimeproduct", settings.lifetimeproduct.as_str());

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn reset_hash(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "resethash");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn add_hash(sellerkey: &str, url: String, hash: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "addhash");
        req_data.insert("hash", hash);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn pause(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "pauseapp");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn unpause(sellerkey: &str, url: String) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "unpauseapp");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }
}

pub mod account {
    use std::collections::HashMap;
    use serde_json::Value;

    /// role can be eiether "Manager" or "Reseller", keylevles should be coma separated keys e.g. 1,4,8, perms look at docs https://docs.keyauth.cc/seller/accounts
    pub fn create(sellerkey: &str, url: String, role: &str, pass: &str, keylevels: Option<&str>, email: &str, perms: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "addAccount");
        req_data.insert("role", role);
        req_data.insert("pass", pass);
        req_data.insert("email", email);
        req_data.insert("perms", perms);
        if let Some(keylevels) = keylevels {
            req_data.insert("keylevels", keylevels);
        }

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

    pub fn delete(sellerkey: &str, url: String, user: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "deleteAccount");
        req_data.insert("user", user);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }
}

pub mod web_loader {
    use std::collections::HashMap;
    use serde_json::Value;

    pub fn retrieve_all_buttons(sellerkey: &str, url: String) -> Result<Vec<Value>, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "fetchallbuttons");

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["buttons"].as_array().unwrap().to_vec());
        }
        Err(json["message"].to_string())
    }

    /// dont use spaces in value
    pub fn add_button(sellerkey: &str, url: String, value: &str, text: &str) -> Result<String, String> {
        let mut req_data = HashMap::new();
        req_data.insert("sellerkey", sellerkey);
        req_data.insert("type", "addbutton");
        req_data.insert("value", value);
        req_data.insert("text", text);

        let res = super::request(req_data, url);
        let resp = res.text().unwrap();
        let json: Value = serde_json::from_str(&resp).unwrap();
        if json["success"].as_bool().unwrap() {
            return Ok(json["message"].to_string());
        }
        Err(json["message"].to_string())
    }

     pub fn delete_button(sellerkey: &str, url: String, value: &str) -> Result<String, String> {
         let mut req_data = HashMap::new();
         req_data.insert("sellerkey", sellerkey);
         req_data.insert("type", "delbutton");
         req_data.insert("value", value);

         let res = super::request(req_data, url);
         let resp = res.text().unwrap();
         let json: Value = serde_json::from_str(&resp).unwrap();
         if json["success"].as_bool().unwrap() {
             return Ok(json["message"].to_string());
         }
         Err(json["message"].to_string())
     }
}