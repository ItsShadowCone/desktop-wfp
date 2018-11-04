extern crate base64;
extern crate eventsource;
extern crate json;
extern crate openssl;
extern crate qrcode;
#[macro_use]
extern crate pam;
extern crate reqwest;

mod config;
mod crypto;
mod transport;
mod worker;

use std::{
    ffi::CStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    thread,
    sync::mpsc,
};

use reqwest::Client as ReqwestClient;

use pam::{
    conv::PamConv,
    module::{PamHandle, PamHooks},
    constants::{PamFlag, PamResultCode, PamResultCode::*, PamMessageStyle, PAM_TEXT_INFO, PAM_ERROR_MSG},
};

use config::*;
use crypto::*;
use transport::*;
use worker::*;

trait Transformable {
    fn encode(&self) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> Self;
}

impl Transformable for u64 {
    fn encode(&self) -> Vec<u8> {
        let b1: u8 = ((self >> 56) & 0xffu64) as u8;
        let b2: u8 = ((self >> 48) & 0xffu64) as u8;
        let b3: u8 = ((self >> 40) & 0xffu64) as u8;
        let b4: u8 = ((self >> 32) & 0xffu64) as u8;
        let b5: u8 = ((self >> 24) & 0xffu64) as u8;
        let b6: u8 = ((self >> 16) & 0xffu64) as u8;
        let b7: u8 = ((self >> 8) & 0xffu64) as u8;
        let b8: u8 = (self & 0xffu64) as u8;
        vec![b1, b2, b3, b4, b5, b6, b7, b8]
    }

    fn decode(bytes: &[u8]) -> Self {
        if bytes.len() != 8 {
            return 0
        }
        (bytes[0] as u64) << 56 + (bytes[1] as u64) << 48 + (bytes[2] as u64) << 40 + (bytes[3] as u64) << 32 + (bytes[4] as u64) << 24 + (bytes[5] as u64) << 16 + (bytes[6] as u64) << 8 + (bytes[7] as u64)
    }
}

struct PamImplementation;
pam_hooks!(PamImplementation);

impl PamHooks for PamImplementation {
    /// This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        let conv = match pamh.get_item::<PamConv>() {
            Ok(c) => c,
            Err(_) => return PAM_AUTH_ERR,
        };

        let print = |style: PamMessageStyle, msg: &str| -> Result<Option<String>, String> {
            conv.send(style, msg).map_err(|e| format!("Pam error: {:?}", e))
        };

        match || -> Result<PamResultCode, String> {
            let options = Options::parse(pamh, args)?;
            let devices = Device::fetch_all(&options.keyfile, &options.username);
            if devices.len() == 0 {
                return Ok(PAM_AUTH_ERR);
            }

            let (response, receiver) = mpsc::channel();

            let mut workers = Vec::new();

            let client = ReqwestClient::new();

            for device in devices {
                print(PAM_TEXT_INFO, &format!("Processing device: {}", device.id))?;

                let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?;
                let timestamp = now.as_secs()*1000 + now.subsec_nanos() as u64 / 1000000;

                let challenge = random(32)?;
                let signature = device.own_key.sign(&challenge)?;

                let message = random(32)?;
                let url = build_url(&options.baseurl, "c", &device.id, Some(&encode(&challenge)))?;

                send_challenge(&client, url.clone(), &signature)?;

                let thread_response = response.clone();

                workers.push(collect_response(url, options.timeout, false, move |event: String, data: String| -> Result<Option<PamResultCode>, String> {
                    match &event[..] {
                        "put" => {
                            let d = json::parse(&data).map_err(|e| e.to_string())?;
                            if let Some(path) = d["path"].as_str() {
                                let data = &d["data"];

                                if path != "/" {
                                    return Err(format!("Put received with strange path: {}", path))
                                }

                                let sig = match data.as_str() {
                                    Some(s) => s,
                                    None => return Err(String::from("Aborted")),
                                };

                                if sig != encode(&signature) {
                                    let response = decode(sig)?;
                                    if device.other_key.verify(&challenge, &response) {
                                        return Ok(Some(PAM_SUCCESS));
                                    } else {
                                        return Err(String::from("Bad signature"));
                                    }
                                }
                            }
                        }
                        "patch" => {
                            // Should never happen as we don't modify data children
                            return Err(format!("Patch received, but we normally don't modify data children..."));
                        }
                        "keep-alive" => (),
                        "cancel" => {
                            return Err(format!("Cancel received, exiting due to modified permissions..."));
                        }
                        "auth_revoked" => (), // Ignore as we're not using auth
                        _ => (), // Ignore the else case as well
                    }
                    Ok(None)
                }, move |res: Result<PamResultCode, String>| {
                    match thread_response.send(res) {
                        Ok(_) => (),
                        Err(_) => (),
                    }
                }));
            }

            let (timeout_sender, timeout_receiver) = mpsc::channel();
            workers.push(Worker {
                thread: thread::spawn(move || {
                    let elapsed = Instant::now();
                    loop {
                        if let Ok(_) = timeout_receiver.try_recv() {
                            return;
                        }
                        if elapsed.elapsed() > options.timeout {
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    match response.send(Ok(PAM_AUTH_ERR)) {
                        Ok(_) => (),
                        Err(_) => (),
                    };
                }),
                sender: timeout_sender,
                cleanup: None,
            });

            receiver.recv().map_err(|e| e.to_string())?
        }() {
            Ok(r) => r,
            Err(e) => {
                print(PAM_ERROR_MSG, &e);
                PAM_AUTH_ERR
            }
        }
    }
}
