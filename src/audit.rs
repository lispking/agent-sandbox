//! 链式审计日志：让「这份日志没被动过」变成一个可以被验证的断言。
//!
//! 普通的日志有两个致命问题：
//!   1. 只记成功操作 → 出事时看到的是「什么都没做」
//!   2. 谁都能改 → 出事后第一件事往往就是改日志
//!
//! 这里用最朴素的办法解决第二个：每条记录带前一条的哈希，改任何一条，
//! 它后面整条链都对不上。
//!
//! 格式（TSV，字段内的制表符与换行在写入时被替换成空格）：
//!   seq ts_ms session step actor action effect rule policy_hash risk duration_ms exit_code prev_hash hash
//!
//! 为什么不用 JSON：校验器要能重算哈希，就必须能精确还原「当时写下的字节」。
//! 定长字段顺序 + 一行一条，让校验器只有几十行，也不会因为序列化实现差异而误报。

use crate::sha256::sha256_hex;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// 链的起点。第一条记录的 prev_hash 是它，代表「之前什么都没有」。
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 调用方提供的原始事件。seq / prev_hash / hash 由日志自己填，
/// 因为它们属于「链」，不属于「事件」。
#[derive(Debug, Clone)]
pub struct Event {
    pub session: String,
    pub step: u32,
    pub actor: String,
    /// 必须已经归一化：记模型给的原始字符串等于没记，
    /// `/tmp/ws/../../etc/passwd` 和 `/etc/passwd` 在复盘时对不上。
    pub action: String,
    pub effect: String,
    pub rule: String,
    pub risk: String,
    pub duration_ms: u128,
    pub exit_code: Option<i32>,
}

impl Event {
    pub fn new(session: &str, step: u32, actor: &str, action: &str, effect: &str) -> Self {
        Event {
            session: session.into(),
            step,
            actor: actor.into(),
            action: action.into(),
            effect: effect.into(),
            rule: String::new(),
            risk: String::new(),
            duration_ms: 0,
            exit_code: None,
        }
    }

    pub fn rule(mut self, rule: &str) -> Self {
        self.rule = rule.into();
        self
    }

    pub fn risk(mut self, risk: &str) -> Self {
        self.risk = risk.into();
        self
    }
}

#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub seq: u64,
    pub ts_ms: u128,
    pub session: String,
    pub step: u32,
    pub actor: String,
    pub action: String,
    pub effect: String,
    pub rule: String,
    pub policy_hash: String,
    pub risk: String,
    pub duration_ms: u128,
    pub exit_code: Option<i32>,
    pub prev_hash: String,
    pub hash: String,
}

fn sanitize(s: &str) -> String {
    s.replace(['\t', '\n', '\r'], " ")
}

impl AuditRecord {
    fn fields(&self) -> Vec<String> {
        vec![
            self.seq.to_string(),
            self.ts_ms.to_string(),
            sanitize(&self.session),
            self.step.to_string(),
            sanitize(&self.actor),
            sanitize(&self.action),
            sanitize(&self.effect),
            sanitize(&self.rule),
            sanitize(&self.policy_hash),
            sanitize(&self.risk),
            self.duration_ms.to_string(),
            self.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "-".into()),
            sanitize(&self.prev_hash),
        ]
    }

    /// 本条记录的哈希：对「除 hash 之外的全部字段」按写入顺序拼接后取 SHA-256。
    /// 校验器只要能把这一行按同样的方式切开，就能独立重算出同一个值。
    fn compute_hash(&self) -> String {
        sha256_hex(self.fields().join("\t").as_bytes())
    }

    pub fn line(&self) -> String {
        format!("{}\t{}\n", self.fields().join("\t"), self.hash)
    }

    pub fn to_tsv(&self) -> String {
        self.line().trim_end().to_string()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Tamper {
    /// 这一行不是 14 个字段，说明被手工编辑过或写入被截断
    Malformed { line: usize },
    /// 内容与哈希对不上：有人改了字段
    HashMismatch { line: usize },
    /// 前后接不上：有人删了中间一条，或者插了一条
    ChainBroken { line: usize },
    /// 序号不递增：有人重排或复用
    SeqNotMonotonic { line: usize },
    Io(String),
}

impl std::fmt::Display for Tamper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tamper::Malformed { line } => write!(f, "第 {} 行字段数不对", line),
            Tamper::HashMismatch { line } => write!(f, "第 {} 行内容与哈希不符", line),
            Tamper::ChainBroken { line } => write!(f, "第 {} 行与前一条接不上", line),
            Tamper::SeqNotMonotonic { line } => write!(f, "第 {} 行序号不递增", line),
            Tamper::Io(e) => write!(f, "读取失败: {}", e),
        }
    }
}

pub struct AuditLog {
    path: PathBuf,
    seq: u64,
    last_hash: String,
    policy_hash: String,
}

impl AuditLog {
    /// 打开（或创建）一份日志，并从最后一行恢复链的状态。
    /// 「恢复」这一步不能省：进程重启后如果从 GENESIS 重新接，链就断了。
    pub fn open(path: impl Into<PathBuf>, policy_hash: &str) -> std::io::Result<Self> {
        let path = path.into();
        let mut seq = 0;
        let mut last_hash = GENESIS.to_string();

        if let Ok(content) = fs::read_to_string(&path) {
            if let Some(line) = content.lines().last() {
                let parts: Vec<&str> = line.split('\t').collect();
                if parts.len() == 14 {
                    seq = parts[0].parse().unwrap_or(0);
                    last_hash = parts[13].to_string();
                }
            }
        }

        Ok(AuditLog {
            path,
            seq,
            last_hash,
            policy_hash: policy_hash.to_string(),
        })
    }

    pub fn append(&mut self, ev: Event) -> std::io::Result<AuditRecord> {
        self.seq += 1;
        let mut rec = AuditRecord {
            seq: self.seq,
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            session: ev.session,
            step: ev.step,
            actor: ev.actor,
            action: ev.action,
            effect: ev.effect,
            rule: ev.rule,
            policy_hash: self.policy_hash.clone(),
            risk: ev.risk,
            duration_ms: ev.duration_ms,
            exit_code: ev.exit_code,
            prev_hash: self.last_hash.clone(),
            hash: String::new(),
        };
        rec.hash = rec.compute_hash();
        self.last_hash = rec.hash.clone();

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(rec.line().as_bytes())?;

        Ok(rec)
    }

    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

/// 独立校验整份日志。返回有效记录数，或者第一处被篡改的位置。
///
/// 关键点：这个函数只依赖「文件里的字节」，不依赖写日志的进程。
/// 所以它可以被一个审计方的脚本单独跑，而不是「让被告自己出证」。
pub fn verify(path: impl AsRef<Path>) -> Result<usize, Tamper> {
    let content = fs::read_to_string(path.as_ref()).map_err(|e| Tamper::Io(e.to_string()))?;
    let mut prev = GENESIS.to_string();
    let mut last_seq = 0u64;
    let mut count = 0;

    for (idx, line) in content.lines().enumerate() {
        let n = idx + 1;
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 14 {
            return Err(Tamper::Malformed { line: n });
        }

        let recomputed = sha256_hex(parts[..13].join("\t").as_bytes());
        if recomputed != parts[13] {
            return Err(Tamper::HashMismatch { line: n });
        }

        let seq: u64 = parts[0].parse().map_err(|_| Tamper::Malformed { line: n })?;
        if seq <= last_seq {
            return Err(Tamper::SeqNotMonotonic { line: n });
        }
        if parts[12] != prev {
            return Err(Tamper::ChainBroken { line: n });
        }

        prev = parts[13].to_string();
        last_seq = seq;
        count += 1;
    }

    Ok(count)
}

/// 按「归一化后的目标」统计被拒绝次数。
///
/// 这是策反检测最便宜的信号：一个正常任务是「偶尔被拒」，
/// 而一个被注入的 Agent 会对着同一个目标反复尝试不同的写法。
pub fn denied_targets(path: impl AsRef<Path>) -> std::io::Result<BTreeMap<String, usize>> {
    let content = fs::read_to_string(path)?;
    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 14 {
            continue;
        }
        if parts[6] == "deny" {
            *out.entry(parts[5].to_string()).or_insert(0) += 1;
        }
    }
    Ok(out)
}

/// 阈值告警：被拒次数达到 min 次的目标。
pub fn suspicious(
    path: impl AsRef<Path>,
    min: usize,
) -> std::io::Result<Vec<(String, usize)>> {
    let mut out: Vec<(String, usize)> = denied_targets(path)?
        .into_iter()
        .filter(|(_, c)| *c >= min)
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("agent-sandbox-audit-{}-{}.tsv", std::process::id(), tag));
        let _ = fs::remove_file(&p);
        p
    }

    fn three_events(log: &mut AuditLog) {
        log.append(Event::new("s1", 1, "planner", "read /tmp/ws/a.txt", "allow").rule("in root"))
            .unwrap();
        log.append(Event::new("s1", 2, "planner", "read /etc/passwd", "deny").rule("读路径越界"))
            .unwrap();
        log.append(Event::new("s1", 3, "planner", "read /etc/passwd", "deny").rule("读路径越界"))
            .unwrap();
    }

    #[test]
    fn seq_and_chain_are_monotonic() {
        let path = temp_path("chain");
        let mut log = AuditLog::open(&path, "policy-abc").unwrap();
        three_events(&mut log);
        assert_eq!(log.seq(), 3);

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains(GENESIS), "第一条应接在 GENESIS 上");
        assert_eq!(verify(&path).unwrap(), 3);
    }

    #[test]
    fn reopens_and_continues_the_chain() {
        let path = temp_path("reopen");
        {
            let mut log = AuditLog::open(&path, "policy-abc").unwrap();
            three_events(&mut log);
        }
        // 进程重启后从最后一条恢复，而不是从 GENESIS 重来
        let mut log = AuditLog::open(&path, "policy-abc").unwrap();
        log.append(Event::new("s1", 4, "planner", "exec cargo test", "allow"))
            .unwrap();
        assert_eq!(verify(&path).unwrap(), 4);
    }

    #[test]
    fn tampering_one_field_is_detected() {
        let path = temp_path("tamper");
        let mut log = AuditLog::open(&path, "policy-abc").unwrap();
        three_events(&mut log);

        // 把第二条的 deny 改成 allow（最典型的「事后美化」）
        let content = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
        lines[1] = lines[1].replace("\tdeny\t", "\tallow\t");
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        assert_eq!(verify(&path), Err(Tamper::HashMismatch { line: 2 }));
    }

    #[test]
    fn deleting_a_line_breaks_the_chain() {
        let path = temp_path("delete");
        let mut log = AuditLog::open(&path, "policy-abc").unwrap();
        three_events(&mut log);

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // 删掉中间那条，剩下两条各自都是「自洽」的，但接不上
        fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();

        match verify(&path) {
            Err(Tamper::SeqNotMonotonic { line: 2 }) | Err(Tamper::ChainBroken { line: 2 }) => {}
            other => panic!("应当发现断链，实际: {:?}", other),
        }
    }

    #[test]
    fn denied_targets_counts_normalized_goal() {
        let path = temp_path("denied");
        let mut log = AuditLog::open(&path, "policy-abc").unwrap();
        three_events(&mut log);
        log.append(Event::new("s1", 4, "planner", "read /root/.ssh/id_rsa", "deny"))
            .unwrap();
        log.append(Event::new("s1", 5, "planner", "read /root/.ssh/id_rsa", "deny"))
            .unwrap();

        let counts = denied_targets(&path).unwrap();
        assert_eq!(counts.get("read /etc/passwd"), Some(&2));
        assert_eq!(counts.get("read /root/.ssh/id_rsa"), Some(&2));

        let hits = suspicious(&path, 2).unwrap();
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|(_, c)| *c >= 2));
    }

    #[test]
    fn policy_hash_is_recorded_per_record() {
        let path = temp_path("policy");
        let mut log = AuditLog::open(&path, "policy-v1-hash").unwrap();
        log.append(Event::new("s1", 1, "planner", "read a", "allow"))
            .unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("policy-v1-hash"));
    }
}
