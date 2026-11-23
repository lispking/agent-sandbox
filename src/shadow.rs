//! 策略灰度：把同一批历史动作，分别交给两版能力集判一遍，看谁变了。
//!
//! 这解决的是「改规则之后会不会误伤」这个问题——它没法靠单元测试回答，
//! 因为单元测试里的动作是人挑的，而真实流量里的动作是模型生成的。
//! 唯一靠谱的办法是拿昨天的真实动作跑新策略，对比判定差异。
//!
//! 前提是日志可回放：审计记录里的动作必须是可逆编码（见 `Action::encode`）。

use crate::{Action, Caps, Decision};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shift {
    /// 原来放行，现在不放行 —— 最可能是误伤，要逐条看
    Tightened,
    /// 原来不放行，现在放行 —— 最可能是放宽，要确认是谁要的
    Loosened,
    /// 都在「不放行」这一侧，只是 deny 与 ask 之间挪了位置
    Reclassified,
    Unchanged,
}

impl Shift {
    pub fn label(&self) -> &'static str {
        match self {
            Shift::Tightened => "误伤候选",
            Shift::Loosened => "放宽",
            Shift::Reclassified => "改判",
            Shift::Unchanged => "不变",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Change {
    pub action: String,
    pub old: &'static str,
    pub new: &'static str,
    pub shift: Shift,
}

#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub tightened: usize,
    pub loosened: usize,
    pub reclassified: usize,
    pub unchanged: usize,
}

impl Summary {
    /// 能不能直接上：只放宽而不误伤，风险可控；
    /// 有误伤就必须先看那几条，否则上线等于把正常任务打回去。
    pub fn verdict(&self) -> &'static str {
        if self.tightened == 0 {
            "可以先影子跑，观察一轮"
        } else {
            "有误伤候选，先逐条确认再上线"
        }
    }
}

fn kind(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Ask(_) => "ask",
        Decision::Deny(_) => "deny",
    }
}

fn shift_of(old: &Decision, new: &Decision) -> Shift {
    let (o, n) = (kind(old), kind(new));
    match (o, n) {
        ("allow", "allow") | ("ask", "deny") | ("deny", "ask") | ("deny", "deny") | ("ask", "ask") => {
            if o == n { Shift::Unchanged } else { Shift::Reclassified }
        }
        ("allow", _) => Shift::Tightened,
        (_, "allow") => Shift::Loosened,
        _ => Shift::Unchanged,
    }
}

/// 对比两版能力集对同一批动作的判定。只返回「判定变了」的那些。
pub fn diff(old: &Caps, new: &Caps, encoded: &[String]) -> (Vec<Change>, Summary) {
    let mut changes = Vec::new();
    let mut summary = Summary::default();

    for raw in encoded {
        let Some(action) = Action::decode(raw) else {
            continue; // 解不出来的历史记录跳过，而不是当成一条「变更」
        };
        let (d_old, d_new) = (old.check(&action), new.check(&action));
        let shift = shift_of(&d_old, &d_new);
        match shift {
            Shift::Unchanged => summary.unchanged += 1,
            Shift::Tightened => summary.tightened += 1,
            Shift::Loosened => summary.loosened += 1,
            Shift::Reclassified => summary.reclassified += 1,
        }
        if shift != Shift::Unchanged {
            changes.push(Change {
                action: raw.clone(),
                old: kind(&d_old),
                new: kind(&d_new),
                shift,
            });
        }
    }

    (changes, summary)
}

/// 直接从审计日志里取出动作列做对比——这才是真实用法：
/// 用昨天的真实动作，跑今天的新策略。
pub fn diff_from_audit(
    old: &Caps,
    new: &Caps,
    audit_path: impl AsRef<std::path::Path>,
) -> std::io::Result<(Vec<Change>, Summary)> {
    let content = std::fs::read_to_string(audit_path)?;
    let mut actions = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 14 {
            continue;
        }
        // 同一目标在日志里可能出现很多次，去重后再跑，输出才好读
        actions.push(parts[5].to_string());
    }
    actions.sort();
    actions.dedup();
    Ok(diff(old, new, &actions))
}

/// 按动作种类聚合差异，用来判断这次改动主要影响哪一类操作。
pub fn group_by_prefix(changes: &[Change]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for c in changes {
        let head = c.action.split(' ').next().unwrap_or("?").to_string();
        *out.entry(head).or_insert(0) += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn v1() -> Caps {
        let mut c = Caps::workspace("/tmp/ws", "/tmp/ws");
        c.read_roots = vec![PathBuf::from("/tmp/ws")];
        c.write_roots = vec![PathBuf::from("/tmp/ws")];
        c
    }

    #[test]
    fn encode_decode_roundtrip_with_spaces() {
        // 这是最容易翻车的形状：参数里带空格
        let a = Action::Exec {
            program: "sh".into(),
            args: vec!["-c".into(), "echo hello world".into()],
        };
        let encoded = a.encode();
        assert_eq!(Action::decode(&encoded), Some(a));
    }

    #[test]
    fn encode_decode_roundtrip_with_backslash_and_newline() {
        let a = Action::Exec {
            program: "printf".into(),
            args: vec!["a\\b".into(), "line1\nline2".into(), "tab\there".into()],
        };
        let encoded = a.encode();
        assert_eq!(Action::decode(&encoded), Some(a));
    }

    #[test]
    fn display_is_not_reversible_but_encode_is() {
        // Display 给人看：空格原样输出，切回去参数就碎了
        let a = Action::Exec {
            program: "sh".into(),
            args: vec!["-c".into(), "rm -rf /tmp/x".into()],
        };
        let shown = a.to_string();
        let naive = Action::decode(&shown).unwrap();
        assert_ne!(naive, a, "原样输出必然丢信息");

        assert_eq!(Action::decode(&a.encode()), Some(a));
    }

    #[test]
    fn tightened_when_a_root_is_removed() {
        let old = v1();
        let mut new = v1();
        new.write_roots.clear(); // 收紧了
        let actions = vec![Action::Write("/tmp/ws/out.txt".into()).encode()];

        let (changes, summary) = diff(&old, &new, &actions);
        assert_eq!(summary.tightened, 1);
        assert_eq!(changes[0].shift, Shift::Tightened);
        assert_eq!((changes[0].old, changes[0].new), ("allow", "deny"));
    }

    #[test]
    fn loosened_when_a_program_is_added() {
        let old = v1();
        let mut new = v1();
        new.exec_allow.push("curl".into()); // 放宽
        let actions = vec![Action::Exec {
            program: "curl".into(),
            args: vec!["https://api.example/x".into()],
        }
        .encode()];

        let (changes, summary) = diff(&old, &new, &actions);
        assert_eq!(summary.loosened, 1);
        assert_eq!(changes[0].shift, Shift::Loosened);
        assert_eq!((changes[0].old, changes[0].new), ("deny", "allow"));
    }

    #[test]
    fn unchanged_actions_are_not_reported() {
        let old = v1();
        let new = v1();
        let actions = vec![Action::Read("/tmp/ws/a.txt".into()).encode()];
        let (changes, summary) = diff(&old, &new, &actions);
        assert!(changes.is_empty());
        assert_eq!(summary.unchanged, 1);
        assert_eq!(summary.verdict(), "可以先影子跑，观察一轮");
    }

    #[test]
    fn deny_to_ask_is_reclassified_not_tightened() {
        let mut old = v1();
        old.write_roots.clear(); // 旧策略：删除一律越界拒绝
        let new = v1(); // 新策略：删除落在工作区内 → 先问
        let a = Action::Delete("/tmp/ws/target".into());

        let (changes, summary) = diff(&old, &new, &vec![a.encode()]);
        // deny → ask：判定变了，但没有一步跨到「允许」，所以既不算误伤也不算放宽
        assert_eq!(summary.reclassified, 1);
        assert_eq!(summary.tightened, 0);
        assert_eq!(summary.loosened, 0);
        assert_eq!(changes[0].shift, Shift::Reclassified);
    }

    #[test]
    fn reads_from_audit_file_and_dedups() {
        use crate::audit::{AuditLog, Event};
        let mut path = std::env::temp_dir();
        path.push(format!("agent-sandbox-shadow-{}.tsv", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut log = AuditLog::open(&path, "p1").unwrap();
        for i in 0..3 {
            log.append(Event::new("s1", i, "planner", &Action::Read("/tmp/ws/a".into()).encode(), "allow"))
                .unwrap();
        }
        log.append(Event::new("s1", 9, "planner", &Action::Write("/tmp/ws/b".into()).encode(), "allow"))
            .unwrap();

        let mut new = v1();
        new.write_roots.clear();
        let (changes, summary) = diff_from_audit(&v1(), &new, &path).unwrap();

        // 三次相同的读被去重，只留 write 那一条收紧
        assert_eq!(summary.tightened, 1);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].action.starts_with("write"));

        let groups = group_by_prefix(&changes);
        assert_eq!(groups.get("write"), Some(&1));
    }
}
