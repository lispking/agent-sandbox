//! 能力集从哪来：任务类型 → 能力模板 → 授权凭证（Grant）。
//!
//! 前三层解决的是「拿到的权限怎么用」，这里解决「权限本身该给多少」。
//!
//! 三条规则，都在这一层强制：
//!   1. **Agent 不能发权限。** 它拿到的是一张只读的 Grant，没有任何写入能力集的接口。
//!   2. **默认拒绝。** 没有登记的任务类型直接拒，不做「猜一个差不多的模板」。
//!   3. **单调收窄。** 子任务只能在父任务的能力范围内派生；申请更大范围时**报错，
//!      而不是静默取交集**——静默取交集会让调用方长期以为「我明明申请了」。
//!
//! 还有一个设计决定：profile 不需要在审计里新加字段，因为**它的身份就是它的策略哈希**。
//! 审计记录里已有的 `policy_hash` 一列，天然回答了「这条动作用的是哪个 profile」。

use crate::sha256::sha256_hex;
use crate::{Action, Caps, Decision, Reversibility};

/// 一个任务类型对应的能力模板。它由业务侧登记，不由 Agent 生成。
#[derive(Debug, Clone)]
pub struct Profile {
    pub id: String,
    pub caps: Caps,
}

impl Profile {
    pub fn new(id: &str, caps: Caps) -> Self {
        Profile {
            id: id.to_string(),
            caps,
        }
    }

    /// profile 的哈希包含 id：两个能力完全相同但用途不同的模板，
    /// 必须是两个不同的版本号，否则审计里分不清「谁给的权限」。
    pub fn policy_hash(&self) -> String {
        sha256_hex(format!("{}\n{:?}", self.id, self.caps).as_bytes())
    }
}

/// 越权申请。带上具体条目，而不是一句「不允许」——
/// 调用方要能直接把多出来的那几条（比如 `/etc`）删掉再重试。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub field: &'static str,
    pub extra: Vec<String>,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} 超出父任务授权: {}",
            self.field,
            self.extra.join(", ")
        )
    }
}

/// 判断 child 是否是 parent 的子集。返回第一处越权。
pub fn subset_violation(parent: &Caps, child: &Caps) -> Option<Violation> {
    // 路径类：child 的根必须落在 parent 的某个根之内
    let path_outside = |parent_roots: &[std::path::PathBuf], child_roots: &[std::path::PathBuf]| {
        child_roots
            .iter()
            .filter(|c| {
                let real = crate::resolve(c);
                !parent_roots.iter().any(|p| real.starts_with(crate::resolve(p)))
            })
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
    };

    let read_extra = path_outside(&parent.read_roots, &child.read_roots);
    if !read_extra.is_empty() {
        return Some(Violation {
            field: "read_roots",
            extra: read_extra,
        });
    }

    let write_extra = path_outside(&parent.write_roots, &child.write_roots);
    if !write_extra.is_empty() {
        return Some(Violation {
            field: "write_roots",
            extra: write_extra,
        });
    }

    let exec_extra: Vec<String> = child
        .exec_allow
        .iter()
        .filter(|c| !parent.exec_allow.contains(c))
        .cloned()
        .collect();
    if !exec_extra.is_empty() {
        return Some(Violation {
            field: "exec_allow",
            extra: exec_extra,
        });
    }

    let net_extra: Vec<String> = child
        .net_allow
        .iter()
        .filter(|c| !parent.net_allow.contains(c))
        .cloned()
        .collect();
    if !net_extra.is_empty() {
        return Some(Violation {
            field: "net_allow",
            extra: net_extra,
        });
    }

    // danger_args 是「需要审批的参数」，越多越严。
    // 所以子任务可以加，但不能把父任务的删掉（删掉等于放宽）。
    let danger_missing: Vec<String> = parent
        .danger_args
        .iter()
        .filter(|p| !child.danger_args.contains(p))
        .cloned()
        .collect();
    if !danger_missing.is_empty() {
        return Some(Violation {
            field: "danger_args",
            extra: danger_missing,
        });
    }

    None
}

/// 发出的授权凭证。只读：没有任何方法能改里面的能力集。
#[derive(Debug, Clone)]
pub struct Grant {
    profile_id: String,
    caps: Caps,
    policy_hash: String,
}

impl Grant {
    pub fn issue(profile: &Profile) -> Grant {
        Grant {
            profile_id: profile.id.clone(),
            caps: profile.caps.clone(),
            policy_hash: profile.policy_hash(),
        }
    }

    /// 派生子任务的凭证。只能在自身范围内收窄，越权直接报错。
    pub fn narrow(&self, child: &Profile) -> Result<Grant, Violation> {
        match subset_violation(&self.caps, &child.caps) {
            Some(v) => Err(v),
            None => Ok(Grant::issue(child)),
        }
    }

    pub fn check(&self, action: &Action) -> Decision {
        self.caps.check(action)
    }

    pub fn reversibility(&self, action: &Action) -> Reversibility {
        self.caps.reversibility(action)
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// 写审计时用这个，而不是 profile_id：
    /// 审计里已有 `policy_hash` 一列，不需要为新概念加新字段。
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    pub fn caps(&self) -> &Caps {
        &self.caps
    }
}

/// 任务类型到能力模板的登记表。没有登记的，一律拒。
#[derive(Debug, Default)]
pub struct Registry {
    profiles: Vec<Profile>,
}

impl Registry {
    pub fn new(profiles: Vec<Profile>) -> Self {
        Registry { profiles }
    }

    pub fn resolve(&self, task_kind: &str) -> Result<&Profile, String> {
        self.profiles
            .iter()
            .find(|p| p.id == task_kind)
            .ok_or_else(|| format!("未登记的任务类型: {}", task_kind))
    }

    pub fn ids(&self) -> Vec<&str> {
        self.profiles.iter().map(|p| p.id.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn readonly(roots: &[&str]) -> Caps {
        Caps {
            read_roots: roots.iter().map(PathBuf::from).collect(),
            ..Default::default()
        }
    }

    fn parent_caps() -> Caps {
        Caps {
            read_roots: vec![PathBuf::from("/srv")],
            write_roots: vec![PathBuf::from("/srv/ws")],
            exec_allow: vec!["git".into(), "cargo".into()],
            danger_args: vec!["push".into()],
            net_allow: vec!["api.internal".into()],
        }
    }

    #[test]
    fn grant_behaves_like_its_caps() {
        let g = Grant::issue(&Profile::new("doc", readonly(&["/srv/docs"])));
        assert!(g.check(&Action::Read("/srv/docs/a.md".into())).is_allowed());
        assert!(!g.check(&Action::Read("/etc/passwd".into())).is_allowed());
    }

    #[test]
    fn profile_hash_distinguishes_purpose() {
        // 能力完全一样，但用途不同 → 必须是两个版本号
        let a = Profile::new("refund", readonly(&["/srv/orders"]));
        let b = Profile::new("docs", readonly(&["/srv/orders"]));
        assert_ne!(a.policy_hash(), b.policy_hash());
    }

    #[test]
    fn narrow_to_subset_is_allowed() {
        let parent = Grant::issue(&Profile::new("root", parent_caps()));
        let child = Profile::new(
            "refund",
            Caps {
                read_roots: vec![PathBuf::from("/srv/orders")],
                write_roots: vec![PathBuf::from("/srv/ws/refund")],
                exec_allow: vec!["git".into()],
                danger_args: vec!["push".into()],
                net_allow: vec![],
            },
        );
        let g = parent.narrow(&child).expect("子集应当允许");

        // 收窄是真的生效：父能写的目录，子不能写
        assert!(g.check(&Action::Write("/srv/ws/other.txt".into())).is_denied());
        assert!(g.check(&Action::Read("/srv/orders/1.json".into())).is_allowed());
    }

    #[test]
    fn narrow_to_superset_is_rejected_with_details() {
        let parent = Grant::issue(&Profile::new("refund", readonly(&["/srv/orders"])));
        let child = Profile::new("refund+", readonly(&["/srv/orders", "/etc"]));

        match parent.narrow(&child) {
            Err(v) => {
                assert_eq!(v.field, "read_roots");
                assert_eq!(v.extra, vec!["/etc".to_string()]);
            }
            Ok(_) => panic!("越权必须失败，不能静默取交集"),
        }
    }

    #[test]
    fn child_cannot_drop_parents_danger_args() {
        let parent = Grant::issue(&Profile::new("root", parent_caps()));
        let child = Profile::new(
            "loose",
            Caps {
                danger_args: vec![], // 把「push 需要审批」删掉了
                ..parent_caps()
            },
        );
        let err = parent.narrow(&child).unwrap_err();
        assert_eq!(err.field, "danger_args");
        assert_eq!(err.extra, vec!["push".to_string()]);
    }

    #[test]
    fn widening_net_or_exec_is_rejected() {
        let parent = Grant::issue(&Profile::new("root", parent_caps()));

        let more_exec = Profile::new(
            "exec+",
            Caps {
                exec_allow: vec!["git".into(), "cargo".into(), "curl".into()],
                ..parent_caps()
            },
        );
        assert_eq!(parent.narrow(&more_exec).unwrap_err().field, "exec_allow");

        let more_net = Profile::new(
            "net+",
            Caps {
                net_allow: vec!["api.internal".into(), "evil.example".into()],
                ..parent_caps()
            },
        );
        assert_eq!(parent.narrow(&more_net).unwrap_err().field, "net_allow");
    }

    #[test]
    fn unknown_task_kind_is_denied() {
        let reg = Registry::new(vec![Profile::new("docs", readonly(&["/srv/docs"]))]);
        assert!(reg.resolve("docs").is_ok());
        let err = reg.resolve("whatever").unwrap_err();
        assert!(err.contains("未登记"));
    }

    #[test]
    fn grant_hash_is_recorded_for_audit() {
        // profile 的身份就是策略哈希，所以审计不需要新字段
        let g = Grant::issue(&Profile::new("refund", readonly(&["/srv/orders"])));
        assert_eq!(g.policy_hash().len(), 64);
        assert_ne!(g.policy_hash(), g.profile_id());
    }
}
