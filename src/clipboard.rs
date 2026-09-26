//! One-shot X11 selection retrieval (ICCCM §2), without clipboard helper programs.
//! https://www.x.org/releases/current/doc/xorg-docs/icccm/icccm.html

use anyhow::{Context, Result, bail, ensure};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ChangeWindowAttributesAux, ConnectionExt, CreateWindowAux, EventMask, PropMode,
    Property, Timestamp, Window, WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

const TIMEOUT: Duration = Duration::from_secs(5);
const PROPERTY_WORDS: u32 = 16 * 1024; // GetProperty lengths/offsets are in 4-byte units.
const TARGETS_LIMIT: usize = 4096 * 4;

x11rb::atom_manager! {
    Atoms: AtomsCookie {
        CLIPBOARD, TARGETS, UTF8_STRING, TEXT, INCR, _CTF_CLIPBOARD_TIME,
    }
}

pub fn read() -> Result<String> {
    let display = std::env::var("DISPLAY")
        .context("ctf paste requires an X11 session: DISPLAY is not set or is not UTF-8")?;
    ensure!(
        !display.is_empty(),
        "ctf paste requires an X11 session: DISPLAY is empty"
    );
    let deadline = Instant::now() + TIMEOUT;
    let (send, receive) = mpsc::sync_channel(1);
    // x11rb's connect/reply/flush calls may block even if events are polled.
    // Bound the *whole* operation, including an unresponsive X server. On this
    // one-shot CLI's timeout, main exits and the OS closes any blocked worker's
    // connection. The worker never writes attachments or other persistent state.
    thread::Builder::new()
        .name("x11-clipboard".into())
        .spawn(move || {
            let result = Session::connect(&display, deadline)
                .and_then(|session| session.read())
                .context("read X11 clipboard");
            let _ = send.send(result);
        })
        .context("start X11 clipboard reader")?;
    receive
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .context("X11 clipboard transfer failed or timed out (5 second limit)")?
}

struct Session {
    connection: RustConnection,
    atoms: Atoms,
    window: Window,
    owner: Window,
    timestamp: Timestamp,
    deadline: Instant,
}

struct Data {
    type_: Atom,
    format: u8,
    bytes: Vec<u8>,
}

impl Session {
    fn connect(display: &str, deadline: Instant) -> Result<Self> {
        let (connection, screen) = x11rb::connect(Some(display))
            .with_context(|| format!("cannot connect to X11 server at DISPLAY={display:?}"))?;
        let atoms = Atoms::new(&connection)?.reply()?;
        let owner = connection
            .get_selection_owner(atoms.CLIPBOARD)?
            .reply()?
            .owner;
        ensure!(owner != x11rb::NONE, "X11 CLIPBOARD has no owner");
        connection
            .change_window_attributes(
                owner,
                &ChangeWindowAttributesAux::new().event_mask(EventMask::STRUCTURE_NOTIFY),
            )?
            .check()
            .context("X11 clipboard owner disappeared")?;
        let window = connection.generate_id()?;
        connection
            .create_window(
                0,
                window,
                connection.setup().roots[screen].root,
                0,
                0,
                1,
                1,
                0,
                WindowClass::INPUT_ONLY,
                0,
                &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
            )?
            .check()?;
        let mut session = Self {
            connection,
            atoms,
            window,
            owner,
            timestamp: 0,
            deadline,
        };
        // Obtain a real server timestamp rather than using CurrentTime. The
        // private requestor window is never mapped and dies with the connection.
        session
            .connection
            .change_property8(
                PropMode::REPLACE,
                window,
                session.atoms._CTF_CLIPBOARD_TIME,
                AtomEnum::STRING,
                &[],
            )?
            .check()?;
        loop {
            if let Event::PropertyNotify(event) = session.event()?
                && event.window == window
                && event.atom == session.atoms._CTF_CLIPBOARD_TIME
                && event.state == Property::NEW_VALUE
            {
                session.timestamp = event.time;
                break;
            }
        }
        Ok(session)
    }

    fn read(&self) -> Result<String> {
        let offered = self
            .selection(self.atoms.TARGETS, TARGETS_LIMIT)?
            .map(|data| parse_targets(&data))
            .transpose()?;
        for target in [
            self.atoms.UTF8_STRING,
            AtomEnum::STRING.into(),
            self.atoms.TEXT,
        ] {
            if offered
                .as_ref()
                .is_some_and(|targets| !targets.contains(&target))
            {
                continue;
            }
            if let Some(data) =
                self.selection(target, crate::attachments::MAX_ATTACHMENT as usize)?
            {
                return text(data, self.atoms.UTF8_STRING);
            }
        }
        bail!("X11 clipboard has no usable textual target (UTF8_STRING, STRING, or TEXT)")
    }

    fn check_deadline(&self) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            "X11 clipboard transfer timed out (5 second limit)"
        );
        Ok(())
    }

    fn event(&self) -> Result<Event> {
        loop {
            self.check_deadline()?;
            match self
                .connection
                .poll_for_event()
                .context("X11 clipboard connection failed")?
            {
                Some(Event::DestroyNotify(event)) if event.window == self.owner => {
                    bail!("X11 clipboard owner disappeared during transfer");
                }
                Some(Event::Error(error)) => bail!("X11 clipboard protocol error: {error:?}"),
                Some(event) => return Ok(event),
                None => thread::sleep(Duration::from_millis(2)),
            }
        }
    }

    fn selection(&self, target: Atom, limit: usize) -> Result<Option<Data>> {
        self.check_deadline()?;
        ensure!(
            self.connection
                .get_selection_owner(self.atoms.CLIPBOARD)?
                .reply()?
                .owner
                == self.owner,
            "X11 clipboard owner disappeared or changed during transfer"
        );
        // Each target is requested once and is its own property on our private
        // window. Late events from a previous conversion cannot match this one.
        self.connection.delete_property(self.window, target)?;
        self.connection.convert_selection(
            self.window,
            self.atoms.CLIPBOARD,
            target,
            target,
            self.timestamp,
        )?;
        self.connection.flush()?;
        loop {
            if let Event::SelectionNotify(event) = self.event()?
                && event.requestor == self.window
                && event.selection == self.atoms.CLIPBOARD
                && event.target == target
                && event.time == self.timestamp
            {
                if event.property == x11rb::NONE {
                    return Ok(None);
                }
                if event.property == target {
                    break;
                }
            }
        }
        let initial = self.property(target, limit, true)?;
        if initial.type_ != self.atoms.INCR {
            self.delete(target)?;
            return Ok(Some(initial));
        }
        let minimum = incr_size(&initial, limit)?;
        // Do not drain events here: deleting INCR may immediately provoke the
        // first chunk. Pre-SelectionNotify PropertyNotify events were ignored
        // while awaiting SelectionNotify, before this deletion/acknowledgement.
        self.delete(target)?;
        let mut result: Option<Data> = None;
        loop {
            match self.event()? {
                Event::PropertyNotify(event)
                    if event.window == self.window
                        && event.atom == target
                        && event.state == Property::NEW_VALUE => {}
                _ => continue,
            }
            let used = result.as_ref().map_or(0, |data| data.bytes.len());
            let chunk = self.property(target, limit - used, false)?;
            let finished = chunk.bytes.is_empty();
            if let Some(data) = &mut result {
                ensure!(
                    data.type_ == chunk.type_ && data.format == chunk.format,
                    "X11 INCR transfer changed property type or format"
                );
                append(&mut data.bytes, &chunk.bytes, limit)?;
            } else {
                result = Some(chunk);
            }
            self.delete(target)?; // Including the final zero-length property.
            if finished {
                let data = result.context("X11 INCR transfer has no data")?;
                ensure!(
                    data.bytes.len() >= minimum,
                    "X11 INCR transfer ended before its advertised minimum size"
                );
                return Ok(Some(data));
            }
        }
    }

    fn delete(&self, property: Atom) -> Result<()> {
        self.connection
            .delete_property(self.window, property)?
            .check()?;
        Ok(())
    }

    fn property(&self, target: Atom, limit: usize, allow_incr: bool) -> Result<Data> {
        let mut data = Data {
            type_: 0,
            format: 0,
            bytes: Vec::new(),
        };
        let mut offset = 0u32;
        let mut total = None;
        loop {
            self.check_deadline()?;
            // Read in bounded pieces; never ask x11rb to allocate an entire
            // owner-controlled property based only on a claimed size.
            let reply = self
                .connection
                .get_property(
                    false,
                    self.window,
                    target,
                    AtomEnum::ANY,
                    offset,
                    PROPERTY_WORDS,
                )?
                .reply()?;
            ensure!(
                reply.type_ != x11rb::NONE,
                "X11 selection property is missing"
            );
            if offset == 0 {
                let valid = if reply.type_ == self.atoms.INCR && allow_incr {
                    reply.format == 32 && reply.value.len() == 4 && reply.bytes_after == 0
                } else if target == self.atoms.TARGETS {
                    reply.type_ == u32::from(AtomEnum::ATOM) && reply.format == 32
                } else {
                    reply.format == 8
                        && (reply.type_ == target && target != self.atoms.TEXT
                            || target == self.atoms.TEXT
                                && (reply.type_ == self.atoms.UTF8_STRING
                                    || reply.type_ == u32::from(AtomEnum::STRING)))
                };
                ensure!(
                    valid,
                    "X11 clipboard returned an unsupported property type or format"
                );
                data.type_ = reply.type_;
                data.format = reply.format;
            }
            ensure!(
                data.type_ == reply.type_ && data.format == reply.format,
                "X11 clipboard property changed during retrieval"
            );
            let length = data
                .bytes
                .len()
                .checked_add(reply.value.len())
                .and_then(|n| n.checked_add(reply.bytes_after as usize))
                .context("X11 clipboard property size overflow")?;
            ensure!(
                length <= limit,
                "X11 clipboard exceeds the permitted size ({limit} bytes)"
            );
            ensure!(
                total.is_none_or(|n| n == length),
                "X11 clipboard property size changed during retrieval"
            );
            total = Some(length);
            append(&mut data.bytes, &reply.value, limit)?;
            if reply.bytes_after == 0 {
                return Ok(data);
            }
            ensure!(
                !reply.value.is_empty() && reply.value.len().is_multiple_of(4),
                "X11 clipboard property retrieval made no aligned progress"
            );
            offset = offset
                .checked_add(u32::try_from(reply.value.len() / 4)?)
                .context("X11 clipboard property offset overflow")?;
        }
    }
}

fn append(output: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<()> {
    ensure!(
        output
            .len()
            .checked_add(bytes.len())
            .is_some_and(|n| n <= limit),
        "X11 clipboard exceeds the permitted size ({limit} bytes)"
    );
    output
        .try_reserve_exact(bytes.len())
        .context("cannot allocate X11 clipboard buffer")?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn incr_size(data: &Data, limit: usize) -> Result<usize> {
    ensure!(
        data.format == 32 && data.bytes.len() == 4,
        "malformed X11 INCR size property"
    );
    let size = u32::from_ne_bytes(data.bytes.as_slice().try_into()?) as usize;
    ensure!(
        size <= limit,
        "X11 clipboard exceeds the permitted size ({limit} bytes)"
    );
    Ok(size)
}

fn parse_targets(data: &Data) -> Result<Vec<Atom>> {
    ensure!(
        data.type_ == u32::from(AtomEnum::ATOM)
            && data.format == 32
            && data.bytes.len().is_multiple_of(4)
            && data.bytes.len() <= TARGETS_LIMIT,
        "malformed X11 TARGETS property"
    );
    // X11 sends 32-bit property values in this client's negotiated byte order.
    Ok(data
        .bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|bytes| u32::from_ne_bytes(*bytes))
        .collect())
}

fn text(data: Data, utf8: Atom) -> Result<String> {
    ensure!(
        data.format == 8,
        "X11 clipboard text must have 8-bit format"
    );
    if data.type_ == u32::from(AtomEnum::STRING) {
        // STRING is ISO-8859-1, not UTF-8. Only ASCII has identical bytes in
        // both encodings; reject other bytes rather than transcode or guess.
        ensure!(
            data.bytes.is_ascii(),
            "X11 STRING contains non-ASCII text; preserving it as UTF-8 would require conversion (copy as UTF8_STRING instead)"
        );
    } else {
        ensure!(
            data.type_ == utf8,
            "X11 clipboard has no supported text encoding"
        );
    }
    String::from_utf8(data.bytes)
        .context("X11 clipboard contains invalid UTF-8; text was not modified")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(type_: Atom, format: u8, bytes: &[u8]) -> Data {
        Data {
            type_,
            format,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn text_is_verbatim_and_encodings_are_explicit() {
        let input = "hello 中文\r\nsecond line\n\0  ";
        assert_eq!(text(data(100, 8, input.as_bytes()), 100).unwrap(), input);
        assert_eq!(text(data(100, 8, b""), 100).unwrap(), "");
        assert_eq!(
            text(data(AtomEnum::STRING.into(), 8, b"a\nb"), 100).unwrap(),
            "a\nb"
        );
        assert!(text(data(AtomEnum::STRING.into(), 8, b"caf\xe9"), 100).is_err());
        assert!(text(data(AtomEnum::STRING.into(), 8, "é".as_bytes()), 100).is_err());
        assert!(text(data(100, 8, b"\xff"), 100).is_err());
        assert!(text(data(100, 16, b"ok"), 100).is_err());
        assert!(text(data(101, 8, b"ok"), 100).is_err());
    }

    #[test]
    fn target_and_incr_headers_are_validated() {
        let bytes = [100u32.to_ne_bytes(), 101u32.to_ne_bytes()].concat();
        assert_eq!(
            parse_targets(&data(AtomEnum::ATOM.into(), 32, &bytes)).unwrap(),
            [100, 101]
        );
        assert!(parse_targets(&data(100, 32, &bytes)).is_err());
        assert!(parse_targets(&data(AtomEnum::ATOM.into(), 8, &bytes)).is_err());
        assert!(parse_targets(&data(AtomEnum::ATOM.into(), 32, &[1])).is_err());
        assert_eq!(
            incr_size(&data(100, 32, &4u32.to_ne_bytes()), 4).unwrap(),
            4
        );
        assert_eq!(
            incr_size(&data(100, 32, &0u32.to_ne_bytes()), 4).unwrap(),
            0
        );
        assert!(incr_size(&data(100, 32, &u32::MAX.to_ne_bytes()), 4).is_err());
        assert!(incr_size(&data(100, 8, &4u32.to_ne_bytes()), 4).is_err());
        assert!(incr_size(&data(100, 32, &[]), 4).is_err());
    }

    #[test]
    fn accumulation_limits_do_not_truncate_or_overflow() {
        let mut bytes = Vec::new();
        append(&mut bytes, b"abc", 4).unwrap();
        append(&mut bytes, b"d", 4).unwrap();
        append(&mut bytes, b"", 4).unwrap();
        assert!(append(&mut bytes, b"e", 4).is_err());
        assert_eq!(bytes, b"abcd");
        assert!(append(&mut bytes, b"", 3).is_err());
    }
}
