// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R32w and R41's session half: every order of control lines a helper can
//! send, driven over a socket pair into `serve_control` itself, with and
//! without a fetch phase. Each cell's answer is written out as a literal.

use super::super::super::control::{CONTROL_BOUNDS, ControlBounds, serve_control};
use super::rig;
use crate::preview_sandbox::Refusal;
use crate::preview_sandbox::control_msg::{SetupStatus, SetupStep};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

/// Over the 10 s hang-guard floor and past every bound a cell waits on.
const GUARD: Duration = Duration::from_secs(45);

/// A line the scripted helper can send.
#[derive(Clone, Copy, Debug)]
enum Line {
    FetchStart,
    FetchDone,
    FetchRefused,
    Run,
    SetupDone,
    SetupRefused,
}

impl Line {
    fn wire(self) -> &'static str {
        match self {
            Self::FetchStart => "{\"fetch_start\":true}",
            Self::FetchDone => "{\"fetch_done\":true}",
            Self::FetchRefused => "{\"fetch_done\":true,\"refused\":\"npm-ci\"}",
            Self::Run => "{\"run\":true}",
            Self::SetupDone => "{\"setup_done\":true}",
            Self::SetupRefused => "{\"setup_refused\":true,\"step\":\"binding\",\"denied\":false}",
        }
    }
}

/// What follows a prefix: one more line, or the helper's close.
const FOLLOWERS: [Option<Line>; 7] = [
    Some(Line::FetchStart),
    Some(Line::FetchDone),
    Some(Line::FetchRefused),
    Some(Line::Run),
    Some(Line::SetupDone),
    Some(Line::SetupRefused),
    None,
];

fn far() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(60)
}

/// One session: the helper writes `raw` (whole lines or not), shuts its
/// write side as the real helper does once it has reported, and reads until
/// the gateway closes. Writes after the gateway gave up are ignored: the
/// answer is the gateway's.
async fn session(
    fetching: bool,
    raw: &[u8],
    bounds: ControlBounds,
    deadline: tokio::time::Instant,
) -> Result<SetupStatus, Refusal> {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let fetch = fetching.then_some(&rig.proxy);
    let served = serve_control(gateway, fetch, deadline, bounds);
    let script = async {
        let (mut read, mut write) = helper.into_split();
        let _ = write.write_all(raw).await;
        let _ = write.shutdown().await;
        let mut rest = Vec::new();
        let _ = read.read_to_end(&mut rest).await;
    };
    let (served, ()) = tokio::time::timeout(GUARD, async { tokio::join!(served, script) })
        .await
        .expect("the session did not end within the guard");
    served
}

fn lines(sent: &[Line]) -> Vec<u8> {
    sent.iter()
        .flat_map(|line| format!("{}\n", line.wire()).into_bytes())
        .collect()
}

fn step(text: &str) -> Result<SetupStatus, Refusal> {
    Err(Refusal::Step(text.to_owned()))
}

const NO_STATUS: &str = "the sandbox helper sent no valid status";
const CLOSED: &str = "the sandbox's control line ended with the connection";

fn other_than(what: &str) -> Result<SetupStatus, Refusal> {
    step(&format!("the sandbox sent something other than {what}"))
}

const REFUSED: SetupStatus = SetupStatus::Refused {
    step: SetupStep::Binding,
    denied: false,
};

/// The prefixes every follower is tried after.
fn prefixes() -> [Vec<Line>; 4] {
    use Line::{FetchDone, FetchStart, Run};
    [
        vec![],
        vec![FetchStart],
        vec![FetchStart, FetchDone],
        vec![FetchStart, FetchDone, Run],
    ]
}

/// R32w, kills "the order is not enforced", "the mode is ignored" and "the
/// status may come before the run's acknowledgement": the whole table,
/// without a fetch phase (the first line is the status, so the prefix's
/// first line decides) and with one (rows in prefix order, columns in
/// FOLLOWERS order).
#[tokio::test(flavor = "current_thread")]
async fn r32w_every_line_order_gets_its_listed_answer() {
    let ns = || step(NO_STATUS);
    let non_fetching = [
        [
            ns(),
            ns(),
            ns(),
            ns(),
            Ok(SetupStatus::Done),
            Ok(REFUSED),
            ns(),
        ],
        [ns(), ns(), ns(), ns(), ns(), ns(), ns()],
        [ns(), ns(), ns(), ns(), ns(), ns(), ns()],
        [ns(), ns(), ns(), ns(), ns(), ns(), ns()],
    ];
    let start = || other_than("fetch_start");
    let done = || other_than("fetch_done");
    let ack = || other_than("the run's acknowledgement");
    let closed = || step(CLOSED);
    let fetching = [
        [
            closed(),
            start(),
            start(),
            start(),
            ns(),
            Ok(REFUSED),
            closed(),
        ],
        [
            done(),
            closed(),
            step("the fetch's npm ci"),
            done(),
            done(),
            done(),
            closed(),
        ],
        [ack(), ack(), ack(), ns(), ack(), ack(), closed()],
        [
            ns(),
            ns(),
            ns(),
            ns(),
            Ok(SetupStatus::Done),
            Ok(REFUSED),
            ns(),
        ],
    ];
    for (mode, table) in [(false, non_fetching), (true, fetching)] {
        for (prefix, row) in prefixes().iter().zip(table) {
            for (follower, want) in FOLLOWERS.into_iter().zip(row) {
                let mut sent = prefix.clone();
                sent.extend(follower);
                let got = session(mode, &lines(&sent), CONTROL_BOUNDS, far()).await;
                assert_eq!(got, want, "fetching {mode}, lines {sent:?}");
            }
        }
    }
}

/// R41's session half, kills "a malformed status is taken", "a second status
/// is taken" and "the status stands without the end of the connection":
/// without a fetch phase and after a fetch's run line alike.
#[tokio::test(flavor = "current_thread")]
async fn r41_only_one_well_formed_status_then_the_end_is_accepted() {
    use Line::{FetchDone, FetchStart, Run, SetupDone};
    let after_fetch = lines(&[FetchStart, FetchDone, Run]);
    for (fetching, before) in [(false, Vec::new()), (true, after_fetch)] {
        for tail in [
            "not json\n",
            "{\"setup_done\":false}\n",
            "{\"setup_done\":true,\"why\":\"x\"}\n",
            "{\"setup_done\":true}\n{\"setup_done\":true}\n",
            "{\"setup_done\":true}\nx",
            "{\"setup_done\":tr",
        ] {
            let mut raw = before.clone();
            raw.extend_from_slice(tail.as_bytes());
            let got = session(fetching, &raw, CONTROL_BOUNDS, far()).await;
            assert_eq!(got, step(NO_STATUS), "fetching {fetching}, tail {tail:?}");
        }
        let mut raw = before.clone();
        raw.extend(lines(&[SetupDone]));
        let got = session(fetching, &raw, CONTROL_BOUNDS, far()).await;
        assert_eq!(
            got,
            Ok(SetupStatus::Done),
            "fetching {fetching}: the plain status"
        );
    }
}

/// R41, kills "a fetching session's first-line refusal is taken without the
/// end of the connection": that refusal goes straight to the end check, and
/// stands only as every status does: the connection ends right after it. A
/// byte after it, or the connection held open past the frame bound, is no
/// status.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn r41_a_fetching_first_line_refusal_stands_only_at_the_end() {
    let refused = lines(&[Line::SetupRefused]);
    let plain = session(true, &refused, CONTROL_BOUNDS, far()).await;
    assert_eq!(plain, Ok(REFUSED), "the refusal, then the end");

    let mut trailing = refused.clone();
    trailing.push(b'x');
    let got = session(true, &trailing, CONTROL_BOUNDS, far()).await;
    assert_eq!(got, step(NO_STATUS), "a byte after the refusal");

    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let began = tokio::time::Instant::now();
    let served = serve_control(gateway, Some(&rig.proxy), far(), CONTROL_BOUNDS);
    let script = async {
        let (mut read, mut write) = helper.into_split();
        let _ = write.write_all(&refused).await;
        // The write side stays open until the gateway has closed its end.
        let mut rest = Vec::new();
        let _ = read.read_to_end(&mut rest).await;
        drop(write);
    };
    let (got, ()) = tokio::time::timeout(GUARD, async { tokio::join!(served, script) })
        .await
        .expect("the session did not end within the guard");
    assert_eq!(
        got,
        step(NO_STATUS),
        "the refusal with the connection held open"
    );
    assert_eq!(
        began.elapsed(),
        CONTROL_BOUNDS.frame,
        "refused at the frame bound"
    );
}

/// R41, kills "the end of the connection is waited for without a bound": a
/// helper that sends its status and then holds the connection open is refused
/// once the frame bound has passed, not taken as started.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn r41_a_status_with_the_connection_held_open_is_refused_at_the_frame_bound() {
    let (mut helper, gateway) = UnixStream::pair().expect("pair");
    helper
        .write_all(b"{\"setup_done\":true}\n")
        .await
        .expect("write");
    let began = tokio::time::Instant::now();
    let served = serve_control(gateway, None, far(), CONTROL_BOUNDS);
    let got = tokio::time::timeout(GUARD, served)
        .await
        .expect("the session did not end within the guard");
    assert_eq!(got, step(NO_STATUS));
    assert_eq!(began.elapsed(), Duration::from_secs(5), "the frame bound");
    drop(helper);
}

/// R41, kills "the status wait outlives the preview's deadline": a helper that
/// connects and stays silent is answered at exactly the deadline, sooner here
/// than the setup bound.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn r41_a_silent_helper_is_refused_at_exactly_the_deadline() {
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let began = tokio::time::Instant::now();
    let deadline = began + Duration::from_secs(10);
    let served = serve_control(gateway, None, deadline, CONTROL_BOUNDS);
    let got = tokio::time::timeout(GUARD, served)
        .await
        .expect("the session did not end within the guard");
    assert_eq!(
        got,
        step("the preview's deadline passed before the sandbox's status")
    );
    assert_eq!(began.elapsed(), Duration::from_secs(10), "the deadline");
    drop(helper);
}

/// The helper's end of a pair, driven one line at a time.
struct Scripted {
    from_gateway: tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    to_gateway: tokio::net::unix::OwnedWriteHalf,
}

impl Scripted {
    fn new(end: UnixStream) -> Self {
        let (from, to) = end.into_split();
        Self {
            from_gateway: tokio::io::BufReader::new(from),
            to_gateway: to,
        }
    }

    /// Say `said`, and when the gateway answers it (the credential, then
    /// `expired`), take that answer before going on.
    async fn say(&mut self, said: Line) {
        use tokio::io::AsyncBufReadExt as _;
        let text = format!("{}\n", said.wire());
        self.to_gateway
            .write_all(text.as_bytes())
            .await
            .expect("say");
        if matches!(said, Line::FetchStart | Line::FetchDone) {
            let mut answer = String::new();
            let got = self.from_gateway.read_line(&mut answer).await;
            got.expect("the gateway answers");
        }
    }
}

/// R41 after a fetch: the status read after the run line is bounded by the
/// deadline alone, so a helper silent there ends at exactly the deadline.
/// The setup bound here (5 s) is well inside the 20 s deadline, so a read
/// that fell back to it would refuse early and fail this row.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn r41_a_helper_silent_after_its_run_line_is_refused_at_the_deadline() {
    let rig = rig().await;
    let (helper, gateway) = UnixStream::pair().expect("pair");
    let began = tokio::time::Instant::now();
    let deadline = began + Duration::from_secs(20);
    let short_setup = ControlBounds {
        setup: Duration::from_secs(5),
        ..CONTROL_BOUNDS
    };
    let served = serve_control(gateway, Some(&rig.proxy), deadline, short_setup);
    let script = async {
        let mut scripted = Scripted::new(helper);
        for said in [Line::FetchStart, Line::FetchDone, Line::Run] {
            scripted.say(said).await;
        }
        // Silent from here, its side open, until the gateway gives up.
        let mut tail = Vec::new();
        let _ = scripted.from_gateway.read_to_end(&mut tail).await;
    };
    let (got, ()) = tokio::time::timeout(GUARD, async { tokio::join!(served, script) })
        .await
        .expect("the session did not end within the guard");
    assert_eq!(
        got,
        step("the preview's deadline passed before the sandbox's status")
    );
    assert_eq!(began.elapsed(), Duration::from_secs(20), "the deadline");
}

/// R41, kills "the gateway closes its side before it has the status's end"
/// (m-early-write-drop): the helper takes the gateway's close as its cue to go
/// on, so after `setup_done` the gateway's side stays open until the helper
/// has shut its own; only then does the helper see the end.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn r41_the_gateway_stays_open_until_the_helper_has_shut_its_side() {
    for fetching in [false, true] {
        let rig = rig().await;
        let (helper, gateway) = UnixStream::pair().expect("pair");
        let served = serve_control(
            gateway,
            fetching.then_some(&rig.proxy),
            far(),
            CONTROL_BOUNDS,
        );
        let script = async {
            let mut scripted = Scripted::new(helper);
            if fetching {
                for said in [Line::FetchStart, Line::FetchDone, Line::Run] {
                    scripted.say(said).await;
                }
            }
            scripted.say(Line::SetupDone).await;
            // Reported, still open: the gateway waits for this side's end (up
            // to its 5 s frame bound), so nothing ends here within 1 s.
            let mut one = [0_u8; 1];
            let peek = scripted.from_gateway.read(&mut one);
            let early = tokio::time::timeout(Duration::from_secs(1), peek).await;
            assert!(
                early.is_err(),
                "fetching {fetching}: the gateway ended its side first: {early:?}"
            );
            scripted.to_gateway.shutdown().await.expect("shut");
            let mut tail = Vec::new();
            let ended = scripted.from_gateway.read_to_end(&mut tail).await;
            assert_eq!(ended.expect("the gateway's end"), 0, "fetching {fetching}");
        };
        let (got, ()) = tokio::time::timeout(GUARD, async { tokio::join!(served, script) })
            .await
            .expect("the session did not end within the guard");
        assert_eq!(got, Ok(SetupStatus::Done), "fetching {fetching}");
    }
}
