use std::{
    ffi::CStr,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    time::Duration
};
use pam::module::PamHandle;

use crypto::*;
use transport::*;

#[derive(Clone)]
pub struct Options {
    pub keyfile: String,
    pub baseurl: String,
    pub timeout: Duration,
    pub username: String,
}

impl Options {
    pub fn parse(pamh: &PamHandle, args: Vec<&CStr>) -> Result<Options, String> {
        let mut options = Options {
            keyfile: String::new(),
            baseurl: String::new(),
            username: String::new(),
            timeout: Duration::from_secs(30),
        };
        for arg in args {
            let option = arg.to_str().map_err(|e| e.to_string())?;
            let split: Vec<&str> = option.split("=").collect();
            if split.len() != 2 {
                return Err(format!("Invalid setting: {}", option))
            }
            let setting = split[0];
            let value = split[1];
            match setting {
                "keyfile" => options.keyfile.push_str(value),
                "baseurl" => options.baseurl.push_str(value),
                "timeout" => options.timeout = match value.parse::<u64>() {
                    Ok(t) => Duration::from_secs(t),
                    Err(e) => {
                        println!("Invalid timeout argument {}: {}", value, e);
                        continue;
                    }
                },
                _ => {
                    println!("Unknown setting: {}", option)
                }
            }
        }
        let user = pamh.get_user(None).map_err(|e| format!("Invalid pam user found: {:?}", e))?;
        options.username.push_str(&user);
        Ok(options)
    }
}

#[derive(Clone)]
pub struct Device {
    pub username: String,
    pub id: String,
    pub other_key: PubKey,
    pub own_key: PrivKey,
}

impl Device {
    pub fn parse(username: &str, device: &str) -> Result<Device, String> {
        let error = |s| Err(format!("Invalid config line: {}={}: {}", username, device, s));

        let split: Vec<&str> = device.split(":").collect();
        if split.len() != 3 {
            return error("not 3 device parameters");
        }

        if split[0].len() != 43 {
            return error("noncompliant device id");
        }

        let id = String::from(split[0]);
        let other_key = decode(split[1])?;
        let own_key = decode(split[2])?;

        Ok(Device {
            username: String::from(username),
            id,
            other_key: PubKey::from_der(&other_key)?,
            own_key: PrivKey::from_der(&own_key)?,
        })
    }

    pub fn fetch_all(keyfile: &str, wanted_user: &str) -> Vec<Device> {
        let file = match File::open(keyfile) {
            Ok(f) => f,
            Err(e) => {
                println!("Could not open keyfile: {}", e);
                return Vec::new()
            }
        };

        let reader = BufReader::new(file);
        let mut devices = Vec::new();
        for l in reader.lines() {
            let line = match l {
                Ok(v) => v,
                Err(e) => {
                    println!("Could not read line: {}", e);
                    continue
                }
            };
            let split: Vec<&str> = line.split("=").collect();
            if split.len() != 2 {
                println!("Invalid config line: {}", line);
                continue;
            }
            let user = split[0];
            let device = split[1];
            if wanted_user.eq(user) {
                devices.push(match Device::parse(user, device) {
                    Ok(d) => d,
                    Err(e) => {
                        println!("{}", e);
                        continue;
                    }
                });
            }
        }
        devices
    }

    pub fn to_config(&self) -> Result<String, String> {
        Ok([&self.username, &[&self.id, &encode(&self.other_key.to_der()?)[..], &encode(&self.own_key.to_der()?)[..]].join(":")[..]].join("="))
    }

    pub fn write(&self, keyfile: &str) -> Result<(), String> {
        let mut file = OpenOptions::new().write(true).append(true).create(true).open(keyfile).map_err(|e| e.to_string())?;
        writeln!(file, "{}", &self.to_config()?).map_err(|e| e.to_string())
    }
}