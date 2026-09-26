//! Native test owner only; not linked into ctf. Run against Xvfb or an explicitly
//! selected X11 display. It claims CLIPBOARD for the duration of each test case.
use anyhow::{Result, ensure};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use x11rb::connection::Connection;
use x11rb::protocol::{Event, xproto::*};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    Utf8,
    String,
    Text,
    NoTargets,
    Incr,
    LoseSelectionIncr,
    IncrTargets,
    StaleEvents,
    RefuseUtf8,
    Unsupported,
    WrongFormat,
    BadIncrHeader,
    Oversized,
    ChangeType,
    Truncated,
    Disappear,
    DisappearIncr,
    Stall,
    StallIncr,
}

pub struct Owner {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
}

impl Owner {
    pub fn new(bytes: &[u8], mode: Mode) -> Result<Self> {
        let (connection, screen) = x11rb::connect(None)?;
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
                &CreateWindowAux::new(),
            )?
            .check()?;
        let atom = |name: &[u8]| -> Result<Atom> {
            Ok(connection.intern_atom(false, name)?.reply()?.atom)
        };
        let clipboard = atom(b"CLIPBOARD")?;
        let utf8 = atom(b"UTF8_STRING")?;
        let targets = atom(b"TARGETS")?;
        let text = atom(b"TEXT")?;
        let incr = atom(b"INCR")?;
        connection
            .set_selection_owner(window, clipboard, x11rb::CURRENT_TIME)?
            .check()?;
        ensure!(
            connection.get_selection_owner(clipboard)?.reply()?.owner == window,
            "test owner did not acquire CLIPBOARD"
        );
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let bytes = bytes.to_vec();
        let worker = thread::spawn(move || {
            let mut transfer: Option<Transfer> = None;
            while !worker_stop.load(Ordering::Relaxed) {
                match connection.poll_for_event()? {
                    Some(Event::SelectionRequest(request)) => {
                        if matches!(mode, Mode::Stall) {
                            continue;
                        }
                        let mut notify = SelectionNotifyEvent {
                            response_type: SELECTION_NOTIFY_EVENT,
                            sequence: 0,
                            time: request.time,
                            requestor: request.requestor,
                            selection: request.selection,
                            target: request.target,
                            property: request.property,
                        };
                        if request.target == targets {
                            if matches!(mode, Mode::NoTargets) {
                                notify.property = x11rb::NONE;
                            } else {
                                let offered = match mode {
                                    Mode::String => vec![u32::from(AtomEnum::STRING)],
                                    Mode::Text => vec![text],
                                    Mode::Unsupported => vec![u32::from(AtomEnum::PIXMAP)],
                                    _ => vec![u32::from(AtomEnum::STRING), utf8], // UTF8 must win, regardless of list order.
                                };
                                if matches!(mode, Mode::IncrTargets) {
                                    transfer = Some(Transfer::start(
                                        &connection,
                                        &request,
                                        incr,
                                        AtomEnum::ATOM.into(),
                                        32,
                                        offered.iter().flat_map(|a| a.to_ne_bytes()).collect(),
                                        mode,
                                    )?);
                                } else {
                                    connection
                                        .change_property32(
                                            PropMode::REPLACE,
                                            request.requestor,
                                            request.property,
                                            AtomEnum::ATOM,
                                            &offered,
                                        )?
                                        .check()?;
                                }
                            }
                        } else if request.target == utf8 && matches!(mode, Mode::RefuseUtf8) {
                            notify.property = x11rb::NONE;
                        } else if request.target == utf8
                            || request.target == u32::from(AtomEnum::STRING)
                            || request.target == text
                        {
                            if matches!(mode, Mode::Disappear) {
                                return Ok(());
                            }
                            let type_ = if matches!(mode, Mode::String | Mode::RefuseUtf8) {
                                AtomEnum::STRING.into()
                            } else {
                                utf8
                            };
                            if matches!(mode, Mode::WrongFormat) {
                                connection
                                    .change_property32(
                                        PropMode::REPLACE,
                                        request.requestor,
                                        request.property,
                                        type_,
                                        &[65],
                                    )?
                                    .check()?;
                            } else if matches!(mode, Mode::BadIncrHeader) {
                                connection
                                    .change_property8(
                                        PropMode::REPLACE,
                                        request.requestor,
                                        request.property,
                                        incr,
                                        &[4],
                                    )?
                                    .check()?;
                            } else if matches!(mode, Mode::Oversized) {
                                connection
                                    .change_property32(
                                        PropMode::REPLACE,
                                        request.requestor,
                                        request.property,
                                        incr,
                                        &[1024 * 1024 * 1024 + 1],
                                    )?
                                    .check()?;
                            } else if matches!(
                                mode,
                                Mode::Incr
                                    | Mode::LoseSelectionIncr
                                    | Mode::ChangeType
                                    | Mode::Truncated
                                    | Mode::DisappearIncr
                                    | Mode::StallIncr
                            ) {
                                transfer = Some(Transfer::start(
                                    &connection,
                                    &request,
                                    incr,
                                    type_,
                                    8,
                                    bytes.clone(),
                                    mode,
                                )?);
                            } else {
                                connection
                                    .change_property8(
                                        PropMode::REPLACE,
                                        request.requestor,
                                        request.property,
                                        type_,
                                        &bytes,
                                    )?
                                    .check()?;
                            }
                        } else {
                            notify.property = x11rb::NONE;
                        }
                        if matches!(mode, Mode::StaleEvents) {
                            let mut stale = notify;
                            stale.target = targets; // Previous conversion, not this one.
                            stale.time = request.time.wrapping_sub(1);
                            connection.send_event(
                                false,
                                request.requestor,
                                EventMask::NO_EVENT,
                                stale,
                            )?;
                            connection.change_property8(
                                PropMode::REPLACE,
                                request.requestor,
                                AtomEnum::WM_NAME,
                                AtomEnum::STRING,
                                b"unrelated",
                            )?;
                        }
                        connection.send_event(
                            false,
                            request.requestor,
                            EventMask::NO_EVENT,
                            notify,
                        )?;
                        connection.flush()?;
                    }
                    Some(Event::PropertyNotify(event)) if event.state == Property::DELETE => {
                        if let Some(pending) = &mut transfer
                            && pending.window == event.window
                            && pending.property == event.atom
                        {
                            if matches!(mode, Mode::DisappearIncr) && pending.offset > 0 {
                                return Ok(());
                            }
                            if matches!(mode, Mode::StallIncr) {
                                continue;
                            }
                            if matches!(mode, Mode::LoseSelectionIncr) && pending.offset == 0 {
                                // ICCCM: losing selection ownership must not abort an
                                // already-started transfer while its owner still lives.
                                connection
                                    .set_selection_owner(
                                        x11rb::NONE,
                                        clipboard,
                                        x11rb::CURRENT_TIME,
                                    )?
                                    .check()?;
                            }
                            if pending.next(&connection)? {
                                transfer = None;
                            }
                        }
                    }
                    Some(Event::DestroyNotify(_)) => transfer = None,
                    _ => thread::sleep(Duration::from_millis(1)),
                }
            }
            Ok(())
        });
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !std::thread::panicking() {
                result
                    .expect("X11 test owner panicked")
                    .expect("X11 test owner failed");
            }
        }
    }
}

struct Transfer {
    window: Window,
    property: Atom,
    type_: Atom,
    format: u8,
    bytes: Vec<u8>,
    offset: usize,
    final_sent: bool,
    mode: Mode,
}

impl Transfer {
    fn start(
        connection: &RustConnection,
        request: &SelectionRequestEvent,
        incr: Atom,
        type_: Atom,
        format: u8,
        bytes: Vec<u8>,
        mode: Mode,
    ) -> Result<Self> {
        connection
            .change_window_attributes(
                request.requestor,
                &ChangeWindowAttributesAux::new()
                    .event_mask(EventMask::PROPERTY_CHANGE | EventMask::STRUCTURE_NOTIFY),
            )?
            .check()?;
        let minimum = bytes.len() as u32 + u32::from(matches!(mode, Mode::Truncated));
        connection
            .change_property32(
                PropMode::REPLACE,
                request.requestor,
                request.property,
                incr,
                &[minimum],
            )?
            .check()?;
        Ok(Self {
            window: request.requestor,
            property: request.property,
            type_,
            format,
            bytes,
            offset: 0,
            final_sent: false,
            mode,
        })
    }

    fn next(&mut self, connection: &RustConnection) -> Result<bool> {
        if self.final_sent {
            return Ok(true);
        }
        // Exceeds a single GetProperty read; also splits UTF-8 characters.
        let chunk_size = if self.format == 32 { 4 } else { 70_001 };
        let end = (self.offset + chunk_size).min(self.bytes.len());
        let bytes = &self.bytes[self.offset..end];
        let type_ = if matches!(self.mode, Mode::ChangeType) && self.offset > 0 {
            AtomEnum::STRING.into()
        } else {
            self.type_
        };
        connection
            .change_property(
                PropMode::REPLACE,
                self.window,
                self.property,
                type_,
                self.format,
                (bytes.len() / (self.format as usize / 8)) as u32,
                bytes,
            )?
            .check()?;
        self.final_sent = bytes.is_empty();
        self.offset = end;
        Ok(false)
    }
}
