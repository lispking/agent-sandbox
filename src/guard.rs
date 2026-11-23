//! 门面：把五层拼成一次调用。
//!
//! 到这里之前，用这套东西需要手写五步：查 Grant、判定、写审计、跑执行器、
//! 再写一条结果。任何一处漏写都不会立刻报错——这正是"接进去之后才疼"的来源。
//!
//! 这里把它压成一次 `act()` 调用，并且只做一件额外的事：
//! **在执行前后各写一条审计记录**。因为真正危险的不是"被拒绝"，而是
//! **"判了允许、执行到一半进程没了、没人知道到底做没做"**。
//!
//! 两条记录用 `effect` 列区分：第一条是判定（allow/ask/deny），
//! 第二条是结果（ok/fail）。这不是最漂亮的格式（理想情况应该有一个 phase 列），
//! 但它让已经上线的日志格式保持不变——代价写在 README 的局限里。

use crate::audit::{self, AuditLog, Event};
use crate::profile::Grant;
use crate::runner::{run_bounded, Budget, RunResult};
use crate::{Action, Decision};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const OK: &str = "ok";
const FAIL: &str = "fail";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub truncated: bool,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActResult {
    pub decision: String,
    pub ran: bool,
    /// 这次调用命中了一次已完成的记录，没有真的执行
    pub replayed: bool,
    pub outcome: Option<Outcome>,
}

impl ActResult {
    fn key(session: &str, step: u32, action: &Action) -> String {
        format!("{}#{}#{}", session, step, action.encode())
    }
}

pub struct Guard {
    grant: Grant,
    log: AuditLog,
    budget: Budget,
    /// 同一次 (session, step, action) 只执行一次。
    /// 键里必须带 step：同一个动作在不同步骤是两次独立的事。
    seen: BTreeMap<String, ActResult>,
}

impl Guard {
    pub fn open(
        audit_path: impl Into<PathBuf>,
        grant: Grant,
        budget: Budget,
    ) -> std::io::Result<Self> {
        let log = AuditLog::open(audit_path, grant.policy_hash())?;
        Ok(Guard {
            grant,
            log,
            budget,
            seen: BTreeMap::new(),
        })
    }

    /// 一次动作的完整生命周期。`exec` 只在判定为 allow 且没重放过时调用。
    pub fn act<F>(
        &mut self,
        session: &str,
        step: u32,
        action: &Action,
        exec: F,
    ) -> std::io::Result<ActResult>
    where
        F: FnOnce(&Budget) -> std::io::Result<RunResult>,
    {
        let key = ActResult::key(session, step, action);
        if let Some(done) = self.seen.get(&key) {
            let mut r = done.clone();
            r.replayed = true;
            return Ok(r);
        }

        let decision = self.grant.check(action);
        let kind = match &decision {
            Decision::Allow => "allow",
            Decision::Ask(_) => "ask",
            Decision::Deny(_) => "deny",
        };
        let reason = match &decision {
            Decision::Allow => "命中能力集".to_string(),
            Decision::Ask(r) | Decision::Deny(r) => r.clone(),
        };

        // 第一条：意图。这条写下去之后崩溃，就会留下「幽灵执行」的痕迹。
        self.log.append(
            Event::new(session, step, "guard", &action.encode(), kind)
                .rule(&format!("intent: {}", reason))
                .risk(&format!("{:?}", self.grant.reversibility(action))),
        )?;

        let result = match decision {
            Decision::Allow => {
                let outcome = match exec(&self.budget) {
                    Ok(run) => Some(self.record_outcome(session, step, action, &run, OK)?),
                    Err(e) => {
                        self.log.append(
                            Event::new(session, step, "guard", &action.encode(), FAIL)
                                .rule(&format!("exec error: {}", e)),
                        )?;
                        Some(Outcome {
                            exit_code: None,
                            duration_ms: 0,
                            truncated: false,
                            timed_out: false,
                        })
                    }
                };
                ActResult {
                    decision: kind.to_string(),
                    ran: true,
                    replayed: false,
                    outcome,
                }
            }
            _ => ActResult {
                decision: kind.to_string(),
                ran: false,
                replayed: false,
                outcome: None,
            },
        };

        self.seen.insert(key, result.clone());
        Ok(result)
    }

    fn record_outcome(
        &mut self,
        session: &str,
        step: u32,
        action: &Action,
        run: &RunResult,
        effect: &str,
    ) -> std::io::Result<Outcome> {
        let outcome = Outcome {
            exit_code: run.exit_code,
            duration_ms: run.duration_ms,
            truncated: run.truncated,
            timed_out: run.timed_out,
        };
        self.log.append(
            Event::new(session, step, "guard", &action.encode(), effect)
                .rule(&format!(
                    "outcome: exit={:?} timed_out={} truncated={}",
                    run.exit_code, run.timed_out, run.truncated
                ))
                .risk(&format!("{}ms", run.duration_ms)),
        )?;
        Ok(outcome)
    }

    pub fn policy_hash(&self) -> &str {
        self.grant.policy_hash()
    }

    pub fn seq(&self) -> u64 {
        self.log.seq()
    }
}

/// 幽灵执行：有「允许」的意图记录，但没有对应的结果记录。
///
/// 这不是 bug 检测，是**事实检测**：它只说明「这条动作可能执行了，也可能没执行」，
/// 至于到底做没做，只能靠业务侧的幂等键或外部系统去核对。
pub fn ghosts(path: impl AsRef<Path>) -> std::io::Result<Vec<(String, u32, String)>> {
    let content = std::fs::read_to_string(path.as_ref())?;
    // (session, step, action) -> 有过结果记录吗
    let mut intents: BTreeMap<(String, u32, String), bool> = BTreeMap::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 14 {
            continue;
        }
        let key = (
            parts[2].to_string(),
            parts[3].parse::<u32>().unwrap_or(0),
            parts[5].to_string(),
        );
        match parts[6] {
            OK | FAIL => {
                if let Some(flag) = intents.get_mut(&key) {
                    *flag = true;
                }
            }
            "allow" => {
                intents.entry(key).or_insert(false);
            }
            _ => {}
        }
    }

    Ok(intents
        .into_iter()
        .filter(|(_, done)| !done)
        .map(|((session, step, action), _)| (session, step, action))
        .collect())
}

/// 顺带提供一个「这层的健康度」判断：幽灵越多，说明执行窗口越长或崩溃越多。
pub fn ghost_report(path: impl AsRef<Path>) -> std::io::Result<String> {
    let g = ghosts(path)?;
    if g.is_empty() {
        Ok("无幽灵执行记录".to_string())
    } else {
        Ok(format!("{} 条待核对：{:?}", g.len(), g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit;
    use crate::profile::Profile;
    use crate::Caps;
    use std::path::PathBuf;

    fn temp(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("agent-sandbox-guard-{}-{}.tsv", std::process::id(), tag));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn grant() -> Grant {
        let caps = Caps {
            read_roots: vec![PathBuf::from("/tmp/ws")],
            write_roots: vec![PathBuf::from("/tmp/ws")],
            exec_allow: vec!["git".into()],
            danger_args: vec!["push".into()],
            net_allow: vec![],
        };
        Grant::issue(&Profile::new("test", caps))
    }

    fn guard(path: &PathBuf) -> Guard {
        Guard::open(path, grant(), Budget { timeout_ms: 2_000, max_output_bytes: 4096 }).unwrap()
    }

    #[test]
    fn allowed_action_runs_and_records_two_lines() {
        let path = temp("allow");
        let mut g = guard(&path);
        let r = g
            .act("s1", 1, &Action::Read("/tmp/ws/a.txt".into()), |_b| {
                Ok(RunResult {
                    exit_code: Some(0),
                    stdout: "ok".into(),
                    stderr: String::new(),
                    truncated: false,
                    timed_out: false,
                    duration_ms: 7,
                })
            })
            .unwrap();

        assert_eq!(r.decision, "allow");
        assert!(r.ran);
        assert_eq!(r.outcome.as_ref().unwrap().duration_ms, 7);

        // 意图 + 结果 = 两条记录
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
        assert_eq!(audit::verify(&path).unwrap(), 2);
        assert!(ghosts(&path).unwrap().is_empty());
    }

    #[test]
    fn denied_action_does_not_execute() {
        let path = temp("deny");
        let mut g = guard(&path);
        let mut called = false;
        let r = g
            .act("s1", 1, &Action::Read("/etc/passwd".into()), |_b| {
                called = true;
                Ok(RunResult {
                    exit_code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                    truncated: false,
                    timed_out: false,
                    duration_ms: 1,
                })
            })
            .unwrap();

        assert_eq!(r.decision, "deny");
        assert!(!r.ran);
        assert!(!called, "被拒绝的动作绝不能执行");
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
    }

    #[test]
    fn ask_does_not_execute_either() {
        let path = temp("ask");
        let mut g = guard(&path);
        let r = g
            .act(
                "s1",
                1,
                &Action::Exec {
                    program: "git".into(),
                    args: vec!["push".into(), "origin".into(), "main".into()],
                },
                |_b| panic!("Ask 不应该被执行"),
            )
            .unwrap();
        assert_eq!(r.decision, "ask");
        assert!(!r.ran);
    }

    #[test]
    fn replay_does_not_run_twice() {
        let path = temp("replay");
        let mut g = guard(&path);
        let action = Action::Read("/tmp/ws/a.txt".into());
        let mut count = 0;

        for _ in 0..2 {
            let r = g
                .act("s1", 1, &action, |_b| {
                    count += 1;
                    Ok(RunResult {
                        exit_code: Some(0),
                        stdout: String::new(),
                        stderr: String::new(),
                        truncated: false,
                        timed_out: false,
                        duration_ms: 1,
                    })
                })
                .unwrap();
            if count == 2 {
                assert!(r.replayed);
            }
        }

        assert_eq!(count, 1, "同一步的同一动作只应执行一次");
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }

    #[test]
    fn same_action_different_step_runs_again() {
        let path = temp("step");
        let mut g = guard(&path);
        let action = Action::Read("/tmp/ws/a.txt".into());
        let mut count = 0;
        for step in [1, 2] {
            g.act("s1", step, &action, |_b| {
                count += 1;
                Ok(RunResult {
                    exit_code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                    truncated: false,
                    timed_out: false,
                    duration_ms: 1,
                })
            })
            .unwrap();
        }
        assert_eq!(count, 2, "不同步骤是两次独立的事");
    }

    #[test]
    fn exec_error_still_records_outcome() {
        let path = temp("err");
        let mut g = guard(&path);
        let r = g
            .act("s1", 1, &Action::Read("/tmp/ws/a.txt".into()), |_b| {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "spawn failed"))
            })
            .unwrap();
        assert!(r.ran);
        assert_eq!(r.outcome.as_ref().unwrap().exit_code, None);
        // 即便执行失败，也要有结果记录：否则会变成幽灵
        assert!(ghosts(&path).unwrap().is_empty());
    }

    #[test]
    fn ghost_is_detected_when_only_intent_exists() {
        let path = temp("ghost");
        // 手工造一条「只有意图、没有结果」的记录，模拟执行中进程被杀
        {
            let mut log = AuditLog::open(&path, "p1").unwrap();
            log.append(Event::new("s9", 3, "guard", "read /tmp/ws/a.txt", "allow"))
                .unwrap();
        }
        let g = ghosts(&path).unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].0, "s9");
        assert_eq!(g[0].1, 3);
        assert!(ghost_report(&path).unwrap().contains("1 条待核对"));
    }

    #[test]
    fn seq_continues_after_reopen() {
        let path = temp("reopen");
        {
            let mut g = guard(&path);
            g.act("s1", 1, &Action::Read("/tmp/ws/a.txt".into()), |_b| {
                Ok(RunResult {
                    exit_code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                    truncated: false,
                    timed_out: false,
                    duration_ms: 1,
                })
            })
            .unwrap();
        }
        let g2 = guard(&path);
        assert_eq!(g2.seq(), 2, "重新打开后序号应当续上");
        assert_eq!(audit::verify(&path).unwrap(), 2);
    }
}
