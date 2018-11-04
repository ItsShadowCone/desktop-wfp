extern crate pam;
extern crate openssl;
extern crate reqwest;
#[macro_use]
extern crate json;
extern crate base64;
extern crate qrcode;
extern crate eventsource;

use qrcode::QrCode;

mod config;
mod crypto;
mod transport;
mod worker;

use config::*;
use crypto::*;
use transport::*;
use worker::*;

use std::{
    env,
    time::{Duration, Instant},
    thread,
    sync::mpsc,
};

fn main() {
    match || -> Result<(), String> {
        let args: Vec<String> = env::args().collect();
        if args.len() != 5 {
            return Err(usage(&args[0][..]));
        }

        let baseurl = &args[1];
        let keyfile = &args[2];
        let username = &args[3];
        let name = &args[4];
        let timeout = Duration::from_secs(30);

        let id = encode(&random(32)?);
        let wrapping_key = SecretKey::from(&random(32)?)?;
        let privkey = PrivKey::generate()?;

        let code = QrCode::new(json::stringify(object!{
            "id" => &id[..],
            "wrappingKey" => encode(&wrapping_key.bytes),
            "name" => &name[..],
            "publicKey" => encode(&privkey.public_key.to_der()?),
        })).map_err(|e| e.to_string())?;

        let string = code.render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .build();
        println!("{}", string);

        let (response, receiver) = mpsc::channel();

        let url = build_url(&baseurl, "i", &id, None)?;
        let thread_response = response.clone();

        let _worker = collect_response(url, timeout, true, move |event: String, data: String| -> Result<Option<Vec<u8>>, String> {
            match &event[..] {
                "put" => {
                    let d = json::parse(&data).map_err(|e| e.to_string())?;
                    if let Some(path) = d["path"].as_str() {
                        let data = &d["data"];

                        let check_response = |public_key: &str, signature: &str| -> Result<Option<Vec<u8>>, String> {
                            let pubkey = decode(public_key)?;
                            let sign = decode(&signature)?;
                            if wrapping_key.verify(&pubkey, &sign) {
                                return Ok(Some(pubkey));
                            } else {
                                return Err(String::from("Bad signature"));
                            }
                        };

                        if path == "/" {
                            if let Some(public_key) = data["p"].as_str() {
                                if let Some(signature) = data["s"].as_str() {
                                    return check_response(public_key, signature);
                                }
                            }

                        }
                    }
                }
                "patch" => {
                    // Should never happen as we don't modify data
                    return Err(format!("Patch received, but we normally don't modify data..."));
                }
                "keep-alive" => (),
                "cancel" => {
                    return Err(format!("Cancel received, exiting due to modified permissions..."));
                }
                "auth_revoked" => (), // Ignore as we're not using auth
                _ => (), // Ignore the else case as well
            }
            Ok(None)
        }, move |res: Result<Vec<u8>, String>| {
            match thread_response.send(res) {
                Ok(_) => (),
                Err(_) => (),
            }
        });

        let (timeout_sender, timeout_receiver) = mpsc::channel();
        let timeout_worker = Worker {
            thread: thread::spawn(move || {
                let elapsed = Instant::now();
                loop {
                    if let Ok(_) = timeout_receiver.try_recv() {
                        return;
                    }
                    if elapsed.elapsed() > timeout {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                match response.send(Err(String::from("Timeout"))) {
                    Ok(_) => (),
                    Err(_) => (),
                };
            }),
            sender: timeout_sender,
            cleanup: None,
        };

        println!("Waiting for qr code scan...");
        let public_key = receiver.recv().map_err(|e| e.to_string())??;

        let device = Device {
            id,
            other_key: PubKey::from_der(&public_key)?,
            own_key: privkey,
            username: username.clone(),
        };

        device.write(keyfile)?;
        println!("Successfully set up device!");
        Ok(())
    }() {
        Ok(_) => (),
        Err(e) => {
            println!("{}", &e);
        }
    }
}

fn usage(program: &str) -> String {
    format!("Usage: {} <baseurl> <keyfile> <username> <device-name>", program)
}