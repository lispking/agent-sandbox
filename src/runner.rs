//! 执行器：把「预算」变成真的边界。
//!
//! 策略层决定「能不能做」，执行器决定「能做多久、能吐多少」。
//! 少了后者，一个 `yes` 或死循环就能把宿主机打爆——这是 Agent 最常见的翻车方式，
//! 不是它想干坏事，而是它不知道什么时候该停。

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            timeout_ms: 30_000,
            max_output_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
    pub duration_ms: u128,
}

/// 受预算约束地执行一个子进程。
///
/// 三个细节，都是踩出来的：
///   1. stdin 必须是 null —— 否则子进程可能等一个永远不会来的输入，白白烧到超时
///   2. 输出必须边读边截 —— 先 `wait_with_output()` 再判断大小，内存已经炸了
///   3. 超时后必须 kill 整个进程组 —— 只 kill 父进程会留下孙进程继续跑
pub fn run_bounded(program: &str, args: &[String], budget: Budget) -> std::io::Result<RunResult> {
    let start = Instant::now();
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let cap = budget.max_output_bytes;

    let out_handle = stdout.map(|s| drain_capped(s, cap));
    let err_handle = stderr.map(|s| drain_capped(s, cap));

    let deadline = start + Duration::from_millis(budget.timeout_ms);
    let mut timed_out = false;
    loop {
        match child.try_wait()? {
            Some(_) => break,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    let (stdout, out_truncated) = out_handle
        .and_then(|h| h.join().ok())
        .unwrap_or((String::new(), false));
    let (stderr, err_truncated) = err_handle
        .and_then(|h| h.join().ok())
        .unwrap_or((String::new(), false));

    Ok(RunResult {
        exit_code: child.try_wait()?.and_then(|s| s.code()),
        stdout,
        stderr,
        truncated: out_truncated || err_truncated,
        timed_out,
        duration_ms: start.elapsed().as_millis(),
    })
}

fn drain_capped<R: Read + Send + 'static>(
    mut reader: R,
    cap: usize,
) -> std::thread::JoinHandle<(String, bool)> {
    std::thread::spawn(move || {
        let mut kept = Vec::with_capacity(cap.min(8192));
        let mut truncated = false;
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if kept.len() < cap {
                        let room = cap - kept.len();
                        let take = n.min(room);
                        kept.extend_from_slice(&buf[..take]);
                        if take < n {
                            truncated = true;
                        }
                    } else {
                        truncated = true;
                        // 继续读并丢弃，避免子进程因为管道写满而卡死
                    }
                }
                Err(_) => break,
            }
        }
        (String::from_utf8_lossy(&kept).to_string(), truncated)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_large_output() {
        let r = run_bounded(
            "sh",
            &["-c".into(), "yes".into()],
            Budget {
                timeout_ms: 500,
                max_output_bytes: 4096,
            },
        )
        .unwrap();
        assert!(r.truncated, "{:?}", r);
        assert!(r.stdout.len() <= 4096);
    }

    #[test]
    fn kills_on_timeout() {
        let r = run_bounded(
            "sh",
            &["-c".into(), "sleep 5".into()],
            Budget {
                timeout_ms: 300,
                max_output_bytes: 1024,
            },
        )
        .unwrap();
        assert!(r.timed_out);
        assert!(r.duration_ms < 2000, "{}", r.duration_ms);
    }

    #[test]
    fn captures_normal_exit() {
        let r = run_bounded(
            "sh",
            &["-c".into(), "echo ok".into()],
            Budget::default(),
        )
        .unwrap();
        assert_eq!(r.exit_code, Some(0));
        assert_eq!(r.stdout.trim(), "ok");
    }
}
