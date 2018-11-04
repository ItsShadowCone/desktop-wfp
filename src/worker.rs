use std::{
    thread,
    sync::mpsc,
};

use transport::PendingCleanup;

pub enum Message {
    StopSelf,
}

pub struct Worker {
    pub thread: thread::JoinHandle<()>,
    pub sender: mpsc::Sender<Message>,
    pub cleanup: Option<PendingCleanup>,
}

impl Worker {
    fn send(&self, msg: Message) {
        match self.sender.send(msg) {
            Ok(_) => (),
            Err(_) => (),
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.send(Message::StopSelf);
        if let Some(c) = self.cleanup.take() {
            match c.cleanup() {
                Ok(_) => (),
                Err(e) => println!("Error while cleaning up: {}", e),
            };
        }
    }
}