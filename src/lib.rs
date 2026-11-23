//! agent-sandbox: 一个极小的 Agent 动作闸门。
//!
//! 设计取向只有一个：把「环境隔离」降级成第二道防线，把「动作审批」提到第一位。
//! 因为环境隔离一旦被绕过就是全盘失守，而动作审批被绕过时，下一次动作仍然会被拦。
//!
//! 本 crate 只做三件事，都是纯逻辑，可在任意平台跑：
//!   1. 把工具调用归一化成 `Action`（路径必须先归一化，否则 `..` 和软链接直接逃逸）
//!   2. 用能力集（capability set）判定 `Allow / Ask / Deny`
//!   3. 给每个动作算一个「可逆性分级」，不可逆的一律 `Ask`

use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Agent 能发起的最小动作集合。凡是不能表达成这几类的调用，都应该被拒绝——
/// 因为无法分类的动作，也无法审计。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Read(PathBuf),
    Write(PathBuf),
    /// 删除单独领出来，不是因为它危险，而是因为它**不可逆**
    Delete(PathBuf),
    Exec { program: String, args: Vec<String> },
    Net { host: String },
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Read(p) => write!(f, "read {}", p.display()),
            Action::Write(p) => write!(f, "write {}", p.display()),
            Action::Delete(p) => write!(f, "delete {}", p.display()),
            Action::Exec { program, args } => {
                write!(f, "exec {} {}", program, args.join(" "))
            }
            Action::Net { host } => write!(f, "net {}", host),
        }
    }
}

impl Action {
    /// 可逆编码：给机器回放用。
    ///
    /// 和 `Display` 分开是有原因的：`Display` 是给人看的，只要读得懂就行；
    /// 回放要求「编码后再解码得到等价动作」。两者混用，就会出现
    /// 「日志能看懂，但拿去跑灰度对比时参数被空格切碎」这种问题。
    pub fn encode(&self) -> String {
        match self {
            Action::Read(p) => format!("read {}", esc(&p.to_string_lossy())),
            Action::Write(p) => format!("write {}", esc(&p.to_string_lossy())),
            Action::Delete(p) => format!("delete {}", esc(&p.to_string_lossy())),
            Action::Exec { program, args } => {
                let mut s = format!("exec {}", esc(program));
                for a in args {
                    s.push(' ');
                    s.push_str(&esc(a));
                }
                s
            }
            Action::Net { host } => format!("net {}", esc(host)),
        }
    }

    pub fn decode(input: &str) -> Option<Action> {
        let (kind, rest) = input.split_once(' ')?;
        match kind {
            "read" => Some(Action::Read(PathBuf::from(unesc(rest)))),
            "write" => Some(Action::Write(PathBuf::from(unesc(rest)))),
            "delete" => Some(Action::Delete(PathBuf::from(unesc(rest)))),
            "net" => Some(Action::Net { host: unesc(rest) }),
            "exec" => {
                let mut it = rest.split(' ').map(unesc);
                let program = it.next()?;
                Some(Action::Exec {
                    program,
                    args: it.collect(),
                })
            }
            _ => None,
        }
    }
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ' ' => out.push_str("\\s"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

fn unesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push(' '),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// 三态，而不是布尔。布尔会逼着实现者把「拿不准」硬塞进 allow 或 deny，
/// 而实际系统里绝大多数事故发生在「拿不准但放行了」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Ask(String),
    Deny(String),
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// 和 `is_allowed` 互为补集，但故意不含 `Ask`：
    /// 「拒绝」和「需要人确认」是两件事，混用会让排查时分不清是谁拦的。
    pub fn is_denied(&self) -> bool {
        matches!(self, Decision::Deny(_))
    }
}

/// 可逆性分级：决定出现异常时该不该自动重试、该不该通知人。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reversibility {
    /// 只读，随便失败
    Reversible,
    /// 可覆盖写，靠快照/版本能回去
    Bounded { restore_cost: u32 },
    /// 不可逆：删除、外部副作用
    Irreversible,
}

/// 能力集。默认全空 = 默认拒绝，不是默认放行。
#[derive(Debug, Clone, Default)]
pub struct Caps {
    pub read_roots: Vec<PathBuf>,
    pub write_roots: Vec<PathBuf>,
    /// 执行白名单：只有这里列出的程序允许运行
    pub exec_allow: Vec<String>,
    /// 危险参数。命中不直接拒绝，而是要求人工确认——因为 `git push` 和 `git push --force` 是两件事
    pub danger_args: Vec<String>,
    /// 出站白名单。空 = 禁止一切出站
    pub net_allow: Vec<String>,
}

impl Caps {
    pub fn readonly(root: impl Into<PathBuf>) -> Self {
        Caps {
            read_roots: vec![root.into()],
            ..Default::default()
        }
    }

    pub fn workspace(read: impl Into<PathBuf>, write: impl Into<PathBuf>) -> Self {
        Caps {
            read_roots: vec![read.into()],
            write_roots: vec![write.into()],
            exec_allow: vec![
                "cargo".into(),
                "rustc".into(),
                "git".into(),
                "rg".into(),
            ],
            danger_args: vec![
                "--force".into(),
                "push".into(),
                "clean".into(),
                "reset".into(),
                "-rf".into(),
                "-fr".into(),
            ],
            net_allow: vec![],
        }
    }

    /// 判定一个动作。注意入参是 `&Action`，返回值永远带理由——
    /// 「为什么被拒」必须能从日志里读出来，否则排障时只能猜。
    pub fn check(&self, action: &Action) -> Decision {
        match action {
            Action::Read(p) => {
                let real = resolve(p);
                if within(&real, &self.read_roots) {
                    Decision::Allow
                } else {
                    Decision::Deny(format!("读路径越界: {}", real.display()))
                }
            }
            Action::Write(p) => {
                let real = resolve(p);
                if within(&real, &self.write_roots) {
                    Decision::Allow
                } else {
                    Decision::Deny(format!("写路径越界: {}", real.display()))
                }
            }
            Action::Delete(p) => {
                let real = resolve(p);
                if !within(&real, &self.write_roots) {
                    Decision::Deny(format!("删除越界: {}", real.display()))
                } else {
                    Decision::Ask(format!("删除不可逆: {}", real.display()))
                }
            }
            Action::Exec { program, args } => {
                if !self.exec_allow.iter().any(|p| p == program) {
                    return Decision::Deny(format!("不在执行白名单: {}", program));
                }
                // 解释器和包管理器是「合规的后门」：白名单里放了它，等于放了任意代码。
                if is_interpreter(program) {
                    return Decision::Ask(format!("{} 等价于执行任意代码", program));
                }
                if let Some(hit) = args
                    .iter()
                    .find(|a| self.danger_args.iter().any(|d| a.contains(d.as_str())))
                {
                    return Decision::Ask(format!("命中危险参数: {}", hit));
                }
                Decision::Allow
            }
            Action::Net { host } => {
                if self.net_allow.iter().any(|h| h == host) {
                    Decision::Allow
                } else {
                    Decision::Deny(format!("出站未授权: {}", host))
                }
            }
        }
    }

    pub fn reversibility(&self, action: &Action) -> Reversibility {
        match action {
            Action::Read(_) | Action::Net { .. } => Reversibility::Reversible,
            Action::Write(_) => Reversibility::Bounded { restore_cost: 1 },
            Action::Delete(_) => Reversibility::Irreversible,
            Action::Exec { program, args } => {
                if is_interpreter(program)
                    || args
                        .iter()
                        .any(|a| read_like_side_effect(program, a))
                {
                    Reversibility::Irreversible
                } else {
                    Reversibility::Bounded { restore_cost: 1 }
                }
            }
        }
    }
}

fn is_interpreter(program: &str) -> bool {
    matches!(
        program,
        "bash" | "sh" | "zsh" | "python" | "python3" | "node" | "ruby" | "perl"
    )
}

/// 判断某个程序+参数是否隐含外部副作用（出网、推远端、装依赖）。
/// 这张表注定不全——所以策略判定的默认值必须是 deny。
fn read_like_side_effect(program: &str, arg: &str) -> bool {
    let _ = program;
    matches!(arg, "push" | "install" | "publish" | "deploy")
}

/// 归一化路径。
///
/// 这一步是整个策略层唯一不能省的地方：`Path::starts_with` 是纯词法比较，
/// 不经归一化，`../../.ssh/id_rsa` 和一条指向家目录的软链接都能直接通过。
pub fn resolve(input: &Path) -> PathBuf {
    let abs = if input.is_absolute() {
        input.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(input)
    };

    // 找到最深的已存在祖先，canonicalize 它（解除软链接），再把剩余部分词法折叠回来
    let mut existing = abs.clone();
    let mut tail: Vec<String> = Vec::new();
    loop {
        if fs::symlink_metadata(&existing).is_ok() {
            break;
        }
        match existing.file_name() {
            Some(name) => {
                tail.push(name.to_string_lossy().to_string());
                match existing.parent() {
                    Some(parent) => existing = parent.to_path_buf(),
                    None => break,
                }
            }
            None => break,
        }
        if existing.as_os_str() == "/" {
            break;
        }
    }

    let mut base = fs::canonicalize(&existing).unwrap_or(existing);
    for seg in tail.iter().rev() {
        for c in Path::new(seg).components() {
            match c {
                Component::ParentDir => {
                    base.pop();
                }
                Component::CurDir => {}
                Component::Normal(n) => base.push(n),
                _ => {}
            }
        }
    }
    base
}

fn within(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| {
        let real_root = resolve(root);
        path.starts_with(&real_root)
    })
}

pub mod audit;
pub mod profile;
pub mod runner;
pub mod shadow;
pub mod sha256;

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> Caps {
        let mut c = Caps::workspace("/tmp/ws", "/tmp/ws");
        c.read_roots = vec![PathBuf::from("/tmp/ws")];
        c.write_roots = vec![PathBuf::from("/tmp/ws")];
        c
    }

    #[test]
    fn read_inside_root_is_allowed() {
        assert!(caps().check(&Action::Read("/tmp/ws/a.txt".into())).is_allowed());
    }

    #[test]
    fn read_outside_root_is_denied() {
        let d = caps().check(&Action::Read("/etc/passwd".into()));
        assert!(matches!(d, Decision::Deny(_)), "got {:?}", d);
    }

    #[test]
    fn dotdot_escape_is_denied() {
        // 词法比较的话这里会通过，归一化之后不会
        let d = caps().check(&Action::Read("/tmp/ws/../../../etc/passwd".into()));
        assert!(matches!(d, Decision::Deny(_)), "got {:?}", d);
    }

    #[test]
    fn write_to_readonly_root_is_denied() {
        let mut c = caps();
        c.write_roots.clear();
        let d = c.check(&Action::Write("/tmp/ws/a.txt".into()));
        assert!(matches!(d, Decision::Deny(_)), "got {:?}", d);
    }

    #[test]
    fn delete_always_needs_approval() {
        let d = caps().check(&Action::Delete("/tmp/ws/a.txt".into()));
        assert!(matches!(d, Decision::Ask(_)), "got {:?}", d);
    }

    #[test]
    fn exec_not_in_allowlist_is_denied() {
        let d = caps().check(&Action::Exec {
            program: "curl".into(),
            args: vec!["https://evil.example".into()],
        });
        assert!(matches!(d, Decision::Deny(_)), "got {:?}", d);
    }

    #[test]
    fn interpreter_is_ask_not_allow() {
        // 真实事故的形状：有人为了「跑测试方便」把 bash 加进了白名单，
        // 于是「允许执行 bash」等于「允许执行任意代码」。这种情况必须是 Ask，不能是 Allow。
        let mut c = caps();
        c.exec_allow.push("bash".into());
        let d = c.check(&Action::Exec {
            program: "bash".into(),
            args: vec!["-c".into(), "rm -rf /".into()],
        });
        assert!(matches!(d, Decision::Ask(_)), "got {:?}", d);
    }

    #[test]
    fn interpreter_not_in_allowlist_is_denied() {
        let d = caps().check(&Action::Exec {
            program: "bash".into(),
            args: vec!["-c".into(), "rm -rf /".into()],
        });
        assert!(matches!(d, Decision::Deny(_)), "got {:?}", d);
    }

    #[test]
    fn force_push_needs_approval() {
        let d = caps().check(&Action::Exec {
            program: "git".into(),
            args: vec!["push".into(), "--force".into(), "origin".into(), "main".into()],
        });
        assert!(matches!(d, Decision::Ask(_)), "got {:?}", d);
    }

    #[test]
    fn net_denied_by_default() {
        let d = caps().check(&Action::Net { host: "api.openai.com".into() });
        assert!(matches!(d, Decision::Deny(_)), "got {:?}", d);
    }

    #[test]
    fn net_allowlisted_is_allowed() {
        let mut c = caps();
        c.net_allow.push("api.openai.com".into());
        assert!(c
            .check(&Action::Net { host: "api.openai.com".into() })
            .is_allowed());
    }

    #[test]
    fn reversibility_grading() {
        let c = caps();
        assert_eq!(c.reversibility(&Action::Read("/tmp/ws/a".into())), Reversibility::Reversible);
        assert_eq!(c.reversibility(&Action::Delete("/tmp/ws/a".into())), Reversibility::Irreversible);
    }
}
