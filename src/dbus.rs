// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: MIT

// Generate selinux dbus busconfig xml information
// https://blog.siphos.be/2014/06/d-bus-and-selinux/

use quick_xml::events::{BytesEnd, BytesStart, Event};
use quick_xml::writer::Writer;
use std::io::Cursor;
use std::str;

// Generate a string which is the xml for a dbus_contexts file.
// Currently, this only outputs the empty boilerplate.  In the long term
// It will support outputting selinux <associate /> tags understood by dbus
#[allow(dead_code)]
pub fn make_dbus_contexts() -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Start(BytesStart::new("busconfig")))
        .unwrap();
    writer
        .write_event(Event::Start(BytesStart::new("selinux")))
        .unwrap();
    // associate tags to map dbus services to SELinux labels go here
    writer
        .write_event(Event::End(BytesEnd::new("selinux")))
        .unwrap();
    writer
        .write_event(Event::End(BytesEnd::new("busconfig")))
        .unwrap();
    let result = writer.into_inner().into_inner(); // Yes, this is the API
    str::from_utf8(&result).unwrap().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_dbus_contexts_empty() {
        let dbus_contexts = make_dbus_contexts();
        assert_eq!(
            dbus_contexts.as_str(),
            "<busconfig><selinux></selinux></busconfig>"
        );
    }
}
