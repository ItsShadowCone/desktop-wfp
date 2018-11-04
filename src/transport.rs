use reqwest::{
    Url, Method, Client as ReqwestClient,
};

use eventsource::reqwest::Client as EventSourceClient;

use std::{
    thread,
    sync::mpsc,
    time::Duration,
    marker::Send,
};

use worker::Worker;

use json::stringify;

use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};

pub fn decode(string: &str) -> Result<Vec<u8>, String> {
    decode_config(string, URL_SAFE_NO_PAD).map_err(|e| e.to_string())
}

pub fn encode(bytes: &[u8]) -> String {
    encode_config(bytes, URL_SAFE_NO_PAD)
}

pub fn build_url(base_url: &str, category: &str, id: &str, message: Option<&str>) -> Result<Url, String> {
    let url = {
        if let Some(msg) = message {
            [base_url, category, id, msg, ".json"].join("/")
        } else {
            [base_url, category, id, ".json"].join("/")
        }
    } + "/";
    Url::parse(&url).map_err(|e| e.to_string())
}

pub struct Info {
    pub public_key: String,
    pub signature: String,
}

pub struct PendingCleanup {
    pub client: ReqwestClient,
    pub url: Url,
}

impl PendingCleanup {
    pub fn cleanup(self) -> Result<(), String> {
        cleanup_challenge(self.client, self.url)
    }
}

fn send(client: &ReqwestClient, method: Method, url: Url, body: Option<String>) -> Result<(), String> {
    let mut req = client.request(method, url);
    req.query(&[("print", "silent")]);
    if let Some(b) = body {
        req.body(b);
    }
    let res = req.send().map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Error: {:?}", res.status()));
    }
    Ok(())
}

pub fn send_challenge(client: &ReqwestClient, url: Url, signature: &[u8]) -> Result<(), String> {
    send(client, Method::Put, url, Some(stringify(encode(signature))))
}

pub fn cleanup_challenge(client: ReqwestClient, url: Url) -> Result<(), String> {
    send(&client, Method::Delete, url, None)
}

pub fn collect_response<DC, RC, R>(url: Url, timeout: Duration, do_cleanup: bool, data_callback: DC, response_callback: RC) -> Worker where
    DC: Fn(String, String) -> Result<Option<R>, String> + Send + 'static,
    RC: Fn(Result<R, String>) + Send + 'static {

    let (timeout_sender, timeout_receiver) = mpsc::channel();
    let thread_url = url.clone();

    let cleanup = if do_cleanup {
        Some(PendingCleanup {
            client: ReqwestClient::new(),
            url,
        })
    }  else {
        None
    };

    Worker {
        thread: thread::spawn(move || {
            let client = EventSourceClient::new(thread_url, Some(timeout));
            for result in client {
                if let Ok(_) = timeout_receiver.try_recv() {
                    return response_callback(Err(String::from("Timeout")));
                }

                let event = match result.map_err(|e| e.to_string()) {
                    Ok(e) => e,
                    Err(e) => return response_callback(Err(e)),
                };
                if let Some(evt) = event.event_type {
                    let data = event.data;

                    match data_callback(evt, data) {
                        Ok(Some(r)) => return response_callback(Ok(r)),
                        Ok(None) => (),
                        Err(e) => return response_callback(Err(e)),
                    }
                }
            }
            return response_callback(Err(String::from("Connection closed")));
        }),
        sender: timeout_sender,
        cleanup,
    }
}