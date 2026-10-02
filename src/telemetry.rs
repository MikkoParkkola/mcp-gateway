//! Daily install heartbeat.
//!
//! At most one POST per 24 hours. The JSON body is `project`, `event`,
//! `version`, `runtime`, and `install_id`. Failure is ignored. Importing this
//! module does no I/O.

use std::fs;
#[cfg(test)]
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PROJECT: &str = "mcp-gateway";
const EVENT: &str = "heartbeat";
const DEFAULT_ENDPOINT: &str = "https://telemetry.revaluator.ai/v1/heartbeat";
const OPT_OUT_ENV: &str = "MCP_GATEWAY_NO_TELEMETRY";
const ENDPOINT_ENV: &str = "MCP_GATEWAY_TELEMETRY_ENDPOINT";
const MAX_BODY: usize = 2048;
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

const CI_ENVS: &[&str] = &[
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "CIRCLECI",
    "TRAVIS",
    "BUILDKITE",
    "DRONE",
    "JENKINS_URL",
    "TEAMCITY_VERSION",
    "BITBUCKET_BUILD_NUMBER",
    "APPVEYOR",
    "CODEBUILD_BUILD_ID",
];

#[derive(serde::Serialize)]
struct Body<'a> {
    project: &'a str,
    event: &'a str,
    version: &'a str,
    runtime: String,
    #[serde(skip_serializing_if = "str::is_empty")]
    install_id: &'a str,
}

enum Proxy {
    System,
    #[allow(dead_code)]
    Direct,
}

/// Sends the daily heartbeat and returns immediately.
///
/// Under `cargo test` this returns before any file or network I/O. A released
/// binary claims the daily slot before the POST, so a failed send still counts
/// as the day's attempt.
pub fn heartbeat_in_background(version: &str) {
    if cfg!(test) || !allowed(version, ci_from_env(), opt_out_from_env()) {
        return;
    }
    let url = resolve_endpoint(std::env::var(ENDPOINT_ENV).ok().as_deref());
    if url.is_empty() {
        return;
    }
    let Some(dir) = state_dir() else {
        return;
    };
    let Some(body) = claim(&dir, version, SystemTime::now()) else {
        return;
    };
    std::thread::spawn(move || post(&url, &body, Proxy::System));
}

fn state_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config/mcp-gateway/telemetry"))
}

fn allowed(version: &str, ci: bool, opt_out: bool) -> bool {
    !version.is_empty() && version != "dev" && !ci && !opt_out
}

fn env_set(value: Option<&str>) -> bool {
    matches!(value, Some(value) if !value.is_empty() && value != "0" && value != "false")
}

fn ci_from_env() -> bool {
    CI_ENVS
        .iter()
        .any(|name| env_set(std::env::var(name).ok().as_deref()))
}

fn opt_out_from_env() -> bool {
    env_set(std::env::var("DO_NOT_TRACK").ok().as_deref())
        || env_set(std::env::var("NO_TELEMETRY").ok().as_deref())
        || env_set(std::env::var(OPT_OUT_ENV).ok().as_deref())
}

fn resolve_endpoint(override_value: Option<&str>) -> String {
    match override_value {
        Some(value) if value.starts_with("https://") || value.starts_with("http://") => {
            value.to_string()
        }
        Some(value) if !value.is_empty() => String::new(),
        _ => DEFAULT_ENDPOINT.to_string(),
    }
}

fn claim(dir: &Path, version: &str, now: SystemTime) -> Option<Vec<u8>> {
    if !due(dir, now) {
        return None;
    }
    let _ = mark_sent(dir, now);
    let id = install_id(dir);
    build_body(version, &id)
}

fn due(dir: &Path, now: SystemTime) -> bool {
    let Ok(text) = fs::read_to_string(dir.join("heartbeat")) else {
        return true;
    };
    let Some(last) = parse_rfc3339(text.trim()) else {
        return true;
    };
    now.duration_since(last).unwrap_or(Duration::ZERO) >= DAY
}

fn mark_sent(dir: &Path, now: SystemTime) -> std::io::Result<()> {
    ensure_dir(dir)?;
    let dest = dir.join("heartbeat");
    let tmp = dir.join("heartbeat.tmp");
    write_private(&tmp, format_rfc3339(now).as_bytes())?;
    fs::rename(tmp, dest)
}

fn install_id(dir: &Path) -> String {
    let path = dir.join("install-id");
    if let Ok(text) = fs::read_to_string(&path) {
        let existing = text.trim();
        if !existing.is_empty() {
            return existing.to_string();
        }
    }
    use rand::RngExt;
    let bytes: [u8; 16] = rand::rng().random();
    let id = hex_encode(&bytes);
    if ensure_dir(dir).is_ok() {
        let _ = write_private(&path, id.as_bytes());
    }
    id
}

fn build_body(version: &str, install_id: &str) -> Option<Vec<u8>> {
    let body = Body {
        project: PROJECT,
        event: EVENT,
        version,
        runtime: format!("{}/{}/rust", std::env::consts::OS, std::env::consts::ARCH),
        install_id,
    };
    let bytes = serde_json::to_vec(&body).ok()?;
    if bytes.len() > MAX_BODY {
        return None;
    }
    Some(bytes)
}

fn post(url: &str, body: &[u8], proxy: Proxy) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return,
    };
    runtime.block_on(async {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .http1_only()
            .user_agent("heartbeat");
        if matches!(proxy, Proxy::Direct) {
            builder = builder.no_proxy();
        }
        let Ok(client) = builder.build() else {
            return;
        };
        let _ = client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await;
    });
}

fn ensure_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn format_rfc3339(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let tod = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let text = text.trim();
    let text = match text.find('.') {
        Some(dot) if text.ends_with('Z') => &text[..dot],
        _ => text,
    };
    if text.len() != 20 || !text.as_bytes().ends_with(b"Z") {
        return None;
    }
    let bytes = text.as_bytes();
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let year: i64 = text[0..4].parse().ok()?;
    let month: u64 = text[5..7].parse().ok()?;
    let day: u64 = text[8..10].parse().ok()?;
    let hour: u64 = text[11..13].parse().ok()?;
    let minute: u64 = text[14..16].parse().ok()?;
    let second: u64 = text[17..19].parse().ok()?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    if days < 0 {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_secs(
        days as u64 * 86_400 + hour * 3600 + minute * 60 + second,
    ))
}

fn days_from_civil(year: i64, month: u64, day: u64) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > 31 {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = u64::try_from(year - era * 400).ok()?;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + i64::try_from(doe).ok()? - 719_468)
}

fn civil_from_days(mut z: i64) -> (i64, u64, u64) {
    z += 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = u64::try_from(z - era * 146_097).unwrap_or(0);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let mut year = i64::try_from(yoe).unwrap_or(0) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gw-heartbeat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn dev_ci_and_opt_out_are_not_allowed() {
        assert!(!allowed("", false, false));
        assert!(!allowed("dev", false, false));
        assert!(!allowed("3.5.1", true, false));
        assert!(!allowed("3.5.1", false, true));
        assert!(allowed("3.5.1", false, false));
        assert!(!env_set(Some("")));
        assert!(!env_set(Some("0")));
        assert!(!env_set(Some("false")));
        assert!(env_set(Some("1")));
        assert!(env_set(Some("yes")));
    }

    #[test]
    fn endpoint_override_replaces_only_http_urls() {
        assert_eq!(resolve_endpoint(None), DEFAULT_ENDPOINT);
        assert_eq!(resolve_endpoint(Some("")), DEFAULT_ENDPOINT);
        assert_eq!(resolve_endpoint(Some("ftp://example.test")), "");
        assert_eq!(
            resolve_endpoint(Some("http://127.0.0.1:9/v1/heartbeat")),
            "http://127.0.0.1:9/v1/heartbeat"
        );
    }

    #[test]
    fn stamp_round_trip_and_daily_cap() {
        assert_eq!(
            format_rfc3339(parse_rfc3339("1970-01-01T00:00:00Z").unwrap()),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(
            format_rfc3339(parse_rfc3339("2026-10-02T12:34:56Z").unwrap()),
            "2026-10-02T12:34:56Z"
        );
        let dir = scratch();
        let now = parse_rfc3339("2026-10-02T12:00:00Z").unwrap();
        let body = claim(&dir, "3.5.1", now).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut keys = parsed
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(
            keys,
            ["event", "install_id", "project", "runtime", "version"]
        );
        assert_eq!(parsed["project"], PROJECT);
        assert_eq!(parsed["event"], EVENT);
        assert_eq!(parsed["version"], "3.5.1");
        assert!(parsed["install_id"].as_str().unwrap().len() == 32);
        assert!(parsed.get("hostname").is_none());
        assert_eq!(
            fs::read_to_string(dir.join("heartbeat")).unwrap(),
            "2026-10-02T12:00:00Z"
        );
        let mode = fs::metadata(dir.join("install-id")).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(mode.mode() & 0o777, 0o600);
        }
        let _ = mode;
        assert!(claim(&dir, "3.5.1", now + Duration::from_secs(60)).is_none());
        let next = claim(&dir, "3.5.1", now + DAY).unwrap();
        assert!(next.starts_with(b"{"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn background_entry_does_not_touch_the_network_during_tests() {
        heartbeat_in_background("3.5.1");
    }

    #[test]
    fn post_reaches_a_local_server() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || read_body(listener));
        let body = build_body("3.5.1", "0123456789abcdef0123456789abcdef").unwrap();
        post(
            &format!("http://127.0.0.1:{port}/v1/heartbeat"),
            &body,
            Proxy::Direct,
        );
        let got = handle.join().unwrap();
        assert_eq!(got, body);
    }

    fn read_body(listener: std::net::TcpListener) -> Vec<u8> {
        listener.set_nonblocking(true).unwrap();
        let start = std::time::Instant::now();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > Duration::from_secs(5) {
                        return Vec::new();
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => return Vec::new(),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 2048];
        let body = loop {
            match stream.read(&mut tmp) {
                Ok(0) => break Vec::new(),
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&buf[..end]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                if name.eq_ignore_ascii_case("content-length") {
                                    value.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        let start_body = end + 4;
                        if buf.len() >= start_body + length {
                            break buf[start_body..start_body + length].to_vec();
                        }
                    }
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if start.elapsed() > Duration::from_secs(3) {
                        break Vec::new();
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break Vec::new(),
            }
        };
        let _ = stream.write_all(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        body
    }
}
