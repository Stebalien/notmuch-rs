extern crate tempdir;
extern crate notmuch;

use std::fs::{self, File};
use std::io::Write;

static MESSAGE: &'static [u8] = b"\
To: bob@example.com
From: alice@example.com
Subject: My Message

Cool body!";

#[test]
fn it_works() {
    let dir = tempdir::TempDir::new("notmuch")
        .expect("failed to create temporary directory");

    let msg_path = dir.path().join("cur/message");

    fs::create_dir(msg_path.parent().unwrap())
        .expect("failed to maildir directory");

    let mut msg_file = File::create(&msg_path)
        .expect("failed to create message file");

    msg_file.write_all(MESSAGE)
        .expect("failed to write message");

    let db = notmuch::Database::create(dir.path()).unwrap();
    let msg = db.add_message(&msg_path).unwrap();
    assert_eq!(msg.header("from").unwrap(), "alice@example.com");
    let fname = msg.atomic(|m| {
        m.add_tag("test").unwrap();
        // Test lifetime
        m.filename().unwrap()
    }).unwrap();
    assert_eq!(fname, &*msg_path);
    let msg2 = db.atomic(|db| {
        // Test lifetime
        db.add_message(&msg_path).unwrap()
    }).unwrap();
    assert_eq!(msg, msg2);
    assert!((&msg.tags()).find(|&t| t == "test").is_some());
    assert!((&msg2.tags()).find(|&t| t == "test").is_some());
}
