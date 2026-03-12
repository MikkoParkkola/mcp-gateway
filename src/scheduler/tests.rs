use super::*;
use chrono::TimeZone;

// Helper: build a UTC datetime at a specific minute
fn at(year: i32, month: u32, day: u32, hour: u32, min: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, min, 0)
        .single()
        .expect("valid date")
}

// ── CronField::parse ─────────────────────────────────────────────────────

#[test]
fn cron_field_any_matches_all() {
    let f = CronField::parse("*", 0, 59).unwrap();
    for v in [0, 30, 59] {
        assert!(f.matches(v), "Any should match {v}");
    }
}

#[test]
fn cron_field_exact_matches_only_that_value() {
    let f = CronField::parse("5", 0, 59).unwrap();
    assert!(f.matches(5));
    assert!(!f.matches(4));
    assert!(!f.matches(6));
}

#[test]
fn cron_field_step_matches_multiples() {
    let f = CronField::parse("*/15", 0, 59).unwrap();
    assert!(f.matches(0));
    assert!(f.matches(15));
    assert!(f.matches(30));
    assert!(f.matches(45));
    assert!(!f.matches(1));
    assert!(!f.matches(14));
}

#[test]
fn cron_field_range_matches_inclusive_bounds() {
    let f = CronField::parse("9-17", 0, 23).unwrap();
    assert!(f.matches(9));
    assert!(f.matches(13));
    assert!(f.matches(17));
    assert!(!f.matches(8));
    assert!(!f.matches(18));
}

#[test]
fn cron_field_list_matches_members() {
    let f = CronField::parse("1,2,5", 0, 59).unwrap();
    assert!(f.matches(1));
    assert!(f.matches(2));
    assert!(f.matches(5));
    assert!(!f.matches(3));
    assert!(!f.matches(0));
}

#[test]
fn cron_field_step_zero_is_error() {
    assert!(CronField::parse("*/0", 0, 59).is_err());
}

#[test]
fn cron_field_out_of_range_is_error() {
    assert!(CronField::parse("60", 0, 59).is_err());
    assert!(CronField::parse("13", 1, 12).is_err());
}

#[test]
fn cron_field_range_inverted_is_error() {
    assert!(CronField::parse("17-9", 0, 23).is_err());
}

// ── CronExpression::parse ────────────────────────────────────────────────

#[test]
fn cron_expression_requires_five_fields() {
    assert!(CronExpression::parse("* * * *").is_err());
    assert!(CronExpression::parse("* * * * * *").is_err());
    assert!(CronExpression::parse("0 * * * *").is_ok());
}

#[test]
fn cron_expression_wildcard_matches_any_time() {
    let expr = CronExpression::parse("* * * * *").unwrap();
    assert!(expr.matches(&at(2025, 1, 1, 0, 0)));
    assert!(expr.matches(&at(2025, 12, 31, 23, 59)));
}

#[test]
fn cron_expression_hourly_matches_on_hour() {
    let expr = CronExpression::parse("0 * * * *").unwrap();
    assert!(expr.matches(&at(2025, 6, 15, 10, 0)));
    assert!(!expr.matches(&at(2025, 6, 15, 10, 1)));
    assert!(!expr.matches(&at(2025, 6, 15, 10, 30)));
}

#[test]
fn cron_expression_daily_at_nine_matches_correctly() {
    let expr = CronExpression::parse("0 9 * * *").unwrap();
    assert!(expr.matches(&at(2025, 3, 1, 9, 0)));
    assert!(!expr.matches(&at(2025, 3, 1, 8, 0)));
    assert!(!expr.matches(&at(2025, 3, 1, 9, 1)));
}

#[test]
fn cron_expression_every_15_minutes() {
    let expr = CronExpression::parse("*/15 * * * *").unwrap();
    assert!(expr.matches(&at(2025, 1, 1, 0, 0)));
    assert!(expr.matches(&at(2025, 1, 1, 6, 15)));
    assert!(expr.matches(&at(2025, 1, 1, 12, 30)));
    assert!(expr.matches(&at(2025, 1, 1, 18, 45)));
    assert!(!expr.matches(&at(2025, 1, 1, 0, 7)));
    assert!(!expr.matches(&at(2025, 1, 1, 0, 16)));
}

#[test]
fn cron_expression_first_of_month() {
    let expr = CronExpression::parse("0 0 1 * *").unwrap();
    assert!(expr.matches(&at(2025, 1, 1, 0, 0)));
    assert!(expr.matches(&at(2025, 7, 1, 0, 0)));
    assert!(!expr.matches(&at(2025, 1, 2, 0, 0)));
    assert!(!expr.matches(&at(2025, 1, 1, 0, 1)));
}

#[test]
fn cron_expression_weekday_monday() {
    // 2025-03-10 is a Monday; chrono weekday Mon=num_days_from_sunday=1
    let expr = CronExpression::parse("0 9 * * 1").unwrap();
    let monday = at(2025, 3, 10, 9, 0);
    let tuesday = at(2025, 3, 11, 9, 0);
    assert!(expr.matches(&monday));
    assert!(!expr.matches(&tuesday));
}

#[test]
fn cron_expression_specific_month_range() {
    let expr = CronExpression::parse("0 0 * 6-8 *").unwrap();
    assert!(expr.matches(&at(2025, 6, 15, 0, 0)));
    assert!(expr.matches(&at(2025, 7, 4, 0, 0)));
    assert!(expr.matches(&at(2025, 8, 31, 0, 0)));
    assert!(!expr.matches(&at(2025, 5, 31, 0, 0)));
    assert!(!expr.matches(&at(2025, 9, 1, 0, 0)));
}

// ── ScheduleEntry ────────────────────────────────────────────────────────

#[test]
fn schedule_entry_from_config_parses_correctly() {
    let cfg = JobConfig {
        name: "test-job".to_string(),
        cron: "0 * * * *".to_string(),
        action: ActionConfig::RunPlaybook {
            playbook: "my-playbook".to_string(),
        },
        enabled: true,
    };
    let entry = ScheduleEntry::from_config(cfg).unwrap();
    assert_eq!(entry.name, "test-job");
    assert!(entry.enabled);
}

#[test]
fn schedule_entry_tracking_starts_never() {
    let cfg = JobConfig {
        name: "j".to_string(),
        cron: "* * * * *".to_string(),
        action: ActionConfig::RunPlaybook {
            playbook: "p".to_string(),
        },
        enabled: true,
    };
    let entry = ScheduleEntry::from_config(cfg).unwrap();
    let snap = entry.snapshot();
    assert_eq!(snap.run_count, 0);
    assert_eq!(snap.last_status, JobStatus::Never);
    assert!(snap.last_run.is_none());
}

#[test]
fn schedule_entry_records_success() {
    let cfg = JobConfig {
        name: "j".to_string(),
        cron: "* * * * *".to_string(),
        action: ActionConfig::RunPlaybook {
            playbook: "p".to_string(),
        },
        enabled: true,
    };
    let entry = ScheduleEntry::from_config(cfg).unwrap();
    let t = Utc::now();
    entry.record_success(t);
    let snap = entry.snapshot();
    assert_eq!(snap.run_count, 1);
    assert_eq!(snap.last_status, JobStatus::Ok);
    assert!(snap.last_run.is_some());
}

#[test]
fn schedule_entry_records_failure() {
    let cfg = JobConfig {
        name: "j".to_string(),
        cron: "* * * * *".to_string(),
        action: ActionConfig::RunPlaybook {
            playbook: "p".to_string(),
        },
        enabled: true,
    };
    let entry = ScheduleEntry::from_config(cfg).unwrap();
    let t = Utc::now();
    entry.record_failure(t, "timeout");
    let snap = entry.snapshot();
    assert_eq!(snap.run_count, 1);
    assert_eq!(snap.last_status, JobStatus::Error("timeout".to_string()));
}

#[test]
fn schedule_entry_disabled_is_never_due() {
    let cfg = JobConfig {
        name: "j".to_string(),
        cron: "* * * * *".to_string(),
        action: ActionConfig::RunPlaybook {
            playbook: "p".to_string(),
        },
        enabled: false,
    };
    let entry = ScheduleEntry::from_config(cfg).unwrap();
    assert!(!entry.is_due(&Utc::now()));
}

// ── CronScheduler ────────────────────────────────────────────────────────

#[test]
fn scheduler_from_empty_config_is_empty() {
    let cfg = SchedulerConfig {
        enabled: true,
        jobs: vec![],
    };
    let sched = CronScheduler::from_config(cfg).unwrap();
    assert!(sched.is_empty());
    assert_eq!(sched.len(), 0);
}

#[test]
fn scheduler_rejects_duplicate_names() {
    let cfg = SchedulerConfig {
        enabled: true,
        jobs: vec![
            JobConfig {
                name: "dup".to_string(),
                cron: "* * * * *".to_string(),
                action: ActionConfig::RunPlaybook {
                    playbook: "p".to_string(),
                },
                enabled: true,
            },
            JobConfig {
                name: "dup".to_string(),
                cron: "0 * * * *".to_string(),
                action: ActionConfig::RunPlaybook {
                    playbook: "q".to_string(),
                },
                enabled: true,
            },
        ],
    };
    assert!(CronScheduler::from_config(cfg).is_err());
}

#[test]
fn scheduler_tick_fires_due_entries() {
    let cfg = SchedulerConfig {
        enabled: true,
        jobs: vec![
            JobConfig {
                name: "hourly".to_string(),
                cron: "0 * * * *".to_string(), // fires at minute 0
                action: ActionConfig::RunPlaybook {
                    playbook: "p".to_string(),
                },
                enabled: true,
            },
            JobConfig {
                name: "minutely".to_string(),
                cron: "* * * * *".to_string(), // fires every minute
                action: ActionConfig::RunPlaybook {
                    playbook: "q".to_string(),
                },
                enabled: true,
            },
        ],
    };
    let sched = CronScheduler::from_config(cfg).unwrap();

    // At minute :00 both should fire
    let at_zero = at(2025, 6, 1, 10, 0);
    let mut fired_zero: Vec<String> = Vec::new();
    sched.tick(&at_zero, |e| fired_zero.push(e.name.clone()));
    assert_eq!(fired_zero.len(), 2);

    // At minute :30 only minutely fires
    let at_thirty = at(2025, 6, 1, 10, 30);
    let mut fired_thirty: Vec<String> = Vec::new();
    sched.tick(&at_thirty, |e| fired_thirty.push(e.name.clone()));
    assert_eq!(fired_thirty.len(), 1);
    assert_eq!(fired_thirty[0], "minutely");
}

#[test]
fn scheduler_record_success_updates_snapshot() {
    let cfg = SchedulerConfig {
        enabled: true,
        jobs: vec![JobConfig {
            name: "job1".to_string(),
            cron: "0 * * * *".to_string(),
            action: ActionConfig::RunPlaybook {
                playbook: "p".to_string(),
            },
            enabled: true,
        }],
    };
    let sched = CronScheduler::from_config(cfg).unwrap();
    let t = Utc::now();
    sched.record_success("job1", t);
    let snap = sched.snapshot_by_name("job1").unwrap();
    assert_eq!(snap.run_count, 1);
    assert_eq!(snap.last_status, JobStatus::Ok);
}

#[test]
fn scheduler_record_failure_updates_snapshot() {
    let cfg = SchedulerConfig {
        enabled: true,
        jobs: vec![JobConfig {
            name: "job2".to_string(),
            cron: "0 * * * *".to_string(),
            action: ActionConfig::RunPlaybook {
                playbook: "p".to_string(),
            },
            enabled: true,
        }],
    };
    let sched = CronScheduler::from_config(cfg).unwrap();
    let t = Utc::now();
    sched.record_failure("job2", t, "connection refused");
    let snap = sched.snapshot_by_name("job2").unwrap();
    assert_eq!(snap.last_status, JobStatus::Error("connection refused".to_string()));
}

#[test]
fn find_next_match_advances_one_minute() {
    let expr = CronExpression::parse("*/5 * * * *").unwrap();
    let base = at(2025, 1, 1, 0, 0);
    // Next after 00:00 (which matches) should be 00:05
    let next = find_next_match(&expr, &base, 60).unwrap();
    assert_eq!(next.minute(), 5);
}

#[test]
fn find_next_match_respects_horizon() {
    // A cron that never matches (impossible date like day 31 in Feb)
    let expr = CronExpression::parse("0 0 31 2 *").unwrap();
    let base = at(2025, 2, 1, 0, 0);
    // Horizon of 30 days = 43200 minutes; Feb has no day 31 → None
    let next = find_next_match(&expr, &base, 43200);
    assert!(next.is_none());
}

#[test]
fn scheduler_precompute_sets_next_run() {
    let cfg = SchedulerConfig {
        enabled: true,
        jobs: vec![JobConfig {
            name: "every5".to_string(),
            cron: "*/5 * * * *".to_string(),
            action: ActionConfig::RunPlaybook {
                playbook: "p".to_string(),
            },
            enabled: true,
        }],
    };
    let sched = CronScheduler::from_config(cfg).unwrap();
    let now = at(2025, 6, 1, 12, 3);
    sched.precompute_next_runs(&now);
    let snap = sched.snapshot_by_name("every5").unwrap();
    // Next match after 12:03 with */5 is 12:05
    let next = snap.next_run.expect("next_run should be set");
    assert_eq!(next.minute(), 5);
    assert_eq!(next.hour(), 12);
}

// ── ActionConfig -> ScheduleAction conversion ────────────────────────────

#[test]
fn action_config_run_playbook_converts() {
    let cfg = ActionConfig::RunPlaybook {
        playbook: "weekly-report".to_string(),
    };
    let action = ScheduleAction::from(cfg);
    assert!(matches!(action, ScheduleAction::RunPlaybook(ref s) if s == "weekly-report"));
}

#[test]
fn action_config_invoke_tool_converts() {
    let mut args = HashMap::new();
    args.insert("key".to_string(), serde_json::json!("value"));
    let cfg = ActionConfig::InvokeTool {
        server: "my-server".to_string(),
        tool: "my-tool".to_string(),
        arguments: args.clone(),
    };
    let action = ScheduleAction::from(cfg);
    match action {
        ScheduleAction::InvokeTool {
            server,
            tool,
            arguments,
        } => {
            assert_eq!(server, "my-server");
            assert_eq!(tool, "my-tool");
            assert_eq!(arguments["key"], serde_json::json!("value"));
        }
        _ => panic!("expected InvokeTool"),
    }
}

// ── Serde round-trip ─────────────────────────────────────────────────────

#[test]
fn scheduler_config_deserializes_from_yaml() {
    let yaml = r#"
enabled: true
jobs:
  - name: daily-sync
    cron: "0 3 * * *"
    action:
      type: run_playbook
      playbook: sync-data
  - name: hourly-check
    cron: "0 * * * *"
    action:
      type: invoke_tool
      server: monitoring
      tool: health_check
      arguments: {}
"#;
    let cfg: SchedulerConfig = serde_yaml::from_str(yaml).expect("valid yaml");
    assert!(cfg.enabled);
    assert_eq!(cfg.jobs.len(), 2);
    assert_eq!(cfg.jobs[0].name, "daily-sync");
    assert_eq!(cfg.jobs[1].name, "hourly-check");
}
