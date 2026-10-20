//! Throwaway: MIK-8408 keep_replayed_digest per-step cost on an N-step
//! keyed chain replay (relay on). Never commit.
use std::time::Instant;

use serde_json::{Value, json};

use super::relay_plan_replay::{ALPHA, BETA, rig, task_call};
use super::support::*;
use crate::gateway::server::signing_allocation_tests::alloc_meter::{
    isolate, measure_async_process_wide,
};

fn prose(bytes: usize) -> String {
    let unit = "The orchard ledger records seven rows of late pears and the grafting dates. ";
    unit.repeat(bytes / unit.len() + 1)[..bytes].to_owned()
}

fn chain_of(n: usize) -> Value {
    let steps: Vec<Value> = (0..n)
        .map(|i| json!({"tool": format!("{}:{TOOL}", if i % 2 == 0 { ALPHA } else { BETA }), "arguments": {}}))
        .collect();
    json!({"chain": steps})
}

#[test]
fn zz_replay_ab() {
    let path = {
        let m = module_path!();
        let m = m.split_once("::").map_or(m, |(_c, rest)| rest);
        format!("{m}::zz_replay_ab")
    };
    let out = std::env::temp_dir().join("probe8408replay.txt");
    if isolate(&path) {
        println!(
            "{}",
            std::fs::read_to_string(&out).expect("child wrote the probe file")
        );
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt");
    let mut lines = Vec::new();
    rt.block_on(async {
        for (label, size, m) in [("1KiB", 1024usize, 20u64), ("64KiB", 64 * 1024, 10), ("384KiB", 384 * 1024, 5), ("960KiB", 960 * 1024, 4)] {
            for n in [1usize, 4, 16] {
                let text = prose(size / n);
                let rig = rig(&text, &text, None).await;
                assert!(rig.state.meta_mcp.relay_active(), "premise: relay on");
                let args = chain_of(n);
                let key = format!("k{label}{n}");
                let created = post(&rig.state, "key-a", task_call(1, &key, "gateway_execute", &args)).await;
                let task = task_id(&created);
                let settled = poll_until_terminal(&rig.state, "key-a", &task).await;
                assert_eq!(status_of(&settled), "completed", "settled: {settled}");
                let joined = rig.state.task_executor.drain(std::time::Duration::from_secs(30)).await;
                assert!(joined.is_clean(), "worker finished: {joined:?}");
                let first = get_task(&rig.state, "key-a", &task).await;
                assert!(first.get("error").is_none(), "warm re-read: {first}");
                let entry = (0..16u64).any(|r| rig.relay.task_replay_digests(&task, r).is_some());
                let stored_size = first["result"].to_string().len();
                let mut bad = 0u64;
                let (mut calls, mut bytes, mut us) = (Vec::new(), Vec::new(), Vec::new());
                for i in 0..m {
                    let _ = i;
                    let t = Instant::now();
                    let (v, meter) = measure_async_process_wide(|| get_task(&rig.state, "key-a", &task)).await;
                    us.push(t.elapsed().as_micros() as u64);
                    let size = v["result"].to_string().len();
                    if v.get("error").is_some() || size != stored_size {
                        bad += 1;
                        if bad == 1 {
                            lines.push(format!("PROBEBAD {label} n={n} size={size} stored={stored_size} body={v}"));
                        }
                    }
                    calls.push(meter.calls);
                    bytes.push(meter.bytes);
                }
                for v in [&mut calls, &mut bytes, &mut us] {
                    v.sort_unstable();
                }
                let med = |v: &Vec<u64>| v[v.len() / 2];
                lines.push(format!(
                    "PROBEREPLAY {label} n={n} m={m} ok={}/{m} stored_size={stored_size} entry={entry} answer_bytes={} calls_median={} bytes_median={} us_median={} us_min={}",
                    m - bad, first.to_string().len(), med(&calls), med(&bytes), med(&us), us[0]
                ));
            }
        }
    });
    std::fs::write(&out, lines.join("\n")).expect("write probe file");
}
