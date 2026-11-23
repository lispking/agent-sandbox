//! 人工确认（Ask）的队列化：让「等人」不把 Agent 循环绑死。
//!
//! 前面几层里 `Ask` 只是三态之一，实现上是「把决定交给人」。这一层补的是那个
//! 「交」字——交到哪里、交多久、交多少次。
//!
//! 四个决定，都是为了让 Ask 不变成新的瓶颈：
//!   1. **不弹窗，进队列。** 弹窗把 Agent 循环和一个在线的人绑死，无人值守时直接卡死。
//!   2. **同一目标去重。** 一次任务里同一个动作问一遍就够，问三遍只会让人开始瞎点。
//!   3. **决策可复用，但有窗口。** 批准过的目标在短时间内不再问；
//!      窗口必须绑定具体目标和 profile，不能泛化成「以后这类都放行」。
//!   4. **超时按拒绝处理。** 没有 TTL 的 Ask 等于把「没人处理」当成「默认允许」。

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: u64,
    pub action: String,
    pub reason: String,
    pub created_at_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: String,
    pub approved: bool,
    pub by: String,
    pub at_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submit {
    /// 新进队列，等一个人
    Enqueued(u64),
    /// 同一个目标已经在队列里，返回它的 id，不重复问
    Deduped(u64),
    /// 窗口内已经有人批过（或拒过），直接复用
    Reused { approved: bool, by: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metrics {
    pub submitted: usize,
    pub enqueued: usize,
    pub deduped: usize,
    pub reused: usize,
    /// 超时降级为拒绝的条数。这个数上升，说明人跟不上了
    pub expired: usize,
    pub top_targets: Vec<(String, usize)>,
}

/// 需要人工确认的队列。所有时间都由调用方传入，方便测试，也方便回放。
#[derive(Debug)]
pub struct Queue {
    ttl_ms: u128,
    reuse_window_ms: u128,
    next_id: u64,
    pending: Vec<Request>,
    decided: BTreeMap<String, Decision>,
    metrics: Metrics,
    ask_counts: BTreeMap<String, usize>,
}

impl Queue {
    pub fn new(ttl_ms: u128, reuse_window_ms: u128) -> Self {
        Queue {
            ttl_ms,
            reuse_window_ms,
            next_id: 0,
            pending: Vec::new(),
            decided: BTreeMap::new(),
            metrics: Metrics::default(),
            ask_counts: BTreeMap::new(),
        }
    }

    /// 提交一次确认请求。同一个目标在窗口内被批过就直接复用；
    /// 已经在队列里就返回原 id，而不是再排一条。
    pub fn submit(&mut self, action: &str, reason: &str, now_ms: u128) -> Submit {
        self.metrics.submitted += 1;
        *self.ask_counts.entry(action.to_string()).or_insert(0) += 1;

        if let Some(d) = self.decided.get(action) {
            if now_ms.saturating_sub(d.at_ms) <= self.reuse_window_ms {
                self.metrics.reused += 1;
                return Submit::Reused {
                    approved: d.approved,
                    by: d.by.clone(),
                };
            }
        }

        if let Some(existing) = self.pending.iter().find(|r| r.action == action) {
            self.metrics.deduped += 1;
            return Submit::Deduped(existing.id);
        }

        self.next_id += 1;
        let id = self.next_id;
        self.pending.push(Request {
            id,
            action: action.to_string(),
            reason: reason.to_string(),
            created_at_ms: now_ms,
        });
        self.metrics.enqueued += 1;
        Submit::Enqueued(id)
    }

    pub fn approve(&mut self, id: u64, by: &str, now_ms: u128) -> Option<Decision> {
        self.decide(id, true, by, now_ms)
    }

    pub fn deny(&mut self, id: u64, by: &str, now_ms: u128) -> Option<Decision> {
        self.decide(id, false, by, now_ms)
    }

    fn decide(&mut self, id: u64, approved: bool, by: &str, now_ms: u128) -> Option<Decision> {
        let idx = self.pending.iter().position(|r| r.id == id)?;
        let req = self.pending.remove(idx);
        let d = Decision {
            action: req.action.clone(),
            approved,
            by: by.to_string(),
            at_ms: now_ms,
        };
        self.decided.insert(req.action, d.clone());
        Some(d)
    }

    /// 超时清理：返回被降级的请求。到期默认「不许」，
    /// 而不是「先放着」——放着等于不说话就放行。
    pub fn expire(&mut self, now_ms: u128) -> Vec<Request> {
        let (expired, keep): (Vec<_>, Vec<_>) = self
            .pending
            .drain(..)
            .partition(|r| now_ms.saturating_sub(r.created_at_ms) > self.ttl_ms);
        self.pending = keep;
        self.metrics.expired += expired.len();
        expired
    }

    pub fn pending(&self) -> &[Request] {
        &self.pending
    }

    pub fn metrics(&self) -> Metrics {
        let mut top: Vec<(String, usize)> = self
            .ask_counts
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        // 被问得最多的排在前面：它就是最该被规则或模板吸收的那一类
        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        Metrics {
            top_targets: top,
            ..self.metrics.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q() -> Queue {
        // TTL 60s，复用窗口 5 分钟
        Queue::new(60_000, 300_000)
    }

    #[test]
    fn enqueues_and_assigns_increasing_ids() {
        let mut queue = q();
        assert_eq!(queue.submit("write /a", "不可逆", 0), Submit::Enqueued(1));
        assert_eq!(queue.submit("write /b", "不可逆", 0), Submit::Enqueued(2));
        assert_eq!(queue.pending().len(), 2);
    }

    #[test]
    fn same_target_is_deduped_not_asked_twice() {
        let mut queue = q();
        queue.submit("write /a", "不可逆", 0);
        // 同一次任务里 Agent 反复尝试同一件事：只保留一条待办
        assert_eq!(queue.submit("write /a", "不可逆", 100), Submit::Deduped(1));
        assert_eq!(queue.pending().len(), 1);
        assert_eq!(queue.metrics().deduped, 1);
    }

    #[test]
    fn approval_is_reused_within_window() {
        let mut queue = q();
        let id = match queue.submit("delete /tmp/x", "删除", 0) {
            Submit::Enqueued(id) => id,
            other => panic!("{:?}", other),
        };
        queue.approve(id, "king", 1_000);

        // 4 分钟后同一个目标：不再问人
        match queue.submit("delete /tmp/x", "删除", 241_000) {
            Submit::Reused { approved, by } => {
                assert!(approved);
                assert_eq!(by, "king");
            }
            other => panic!("应当复用：{:?}", other),
        }
    }

    #[test]
    fn approval_expires_after_window() {
        let mut queue = q();
        let id = match queue.submit("delete /tmp/x", "删除", 0) {
            Submit::Enqueued(id) => id,
            other => panic!("{:?}", other),
        };
        queue.approve(id, "king", 0);

        // 6 分钟后：窗口过期，要重新问
        assert!(matches!(
            queue.submit("delete /tmp/x", "删除", 360_000),
            Submit::Enqueued(_)
        ));
    }

    #[test]
    fn denial_is_reused_too() {
        let mut queue = q();
        let id = match queue.submit("read /etc/shadow", "越界", 0) {
            Submit::Enqueued(id) => id,
            other => panic!("{:?}", other),
        };
        queue.deny(id, "king", 10);
        match queue.submit("read /etc/shadow", "越界", 20) {
            Submit::Reused { approved, .. } => assert!(!approved),
            other => panic!("拒绝也应当复用：{:?}", other),
        }
    }

    #[test]
    fn timeout_downgrades_to_deny() {
        let mut queue = q();
        queue.submit("write /a", "不可逆", 0);
        queue.submit("write /b", "不可逆", 59_000);

        // 61 秒后：第一条超时，第二条还在窗口内
        let expired = queue.expire(61_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].action, "write /a");
        assert_eq!(queue.pending().len(), 1);
        assert_eq!(queue.metrics().expired, 1);
    }

    #[test]
    fn metrics_rank_the_noisiest_target() {
        let mut queue = q();
        // 每次提交后立即超时清理：否则第二次会被去重，不会真正形成新的待办
        for (i, _) in (0..3).enumerate() {
            let at = i as u128 * 100_000;
            queue.submit("exec curl /x", "出站", at);
            queue.expire(at + 61_000);
        }
        queue.submit("read /a", "越界", 900_000);

        let m = queue.metrics();
        assert_eq!(m.submitted, 4);
        assert_eq!(m.expired, 3);
        assert_eq!(m.top_targets[0], ("exec curl /x".to_string(), 3));
    }

    #[test]
    fn reused_decision_does_not_touch_pending() {
        let mut queue = q();
        let id = match queue.submit("write /a", "不可逆", 0) {
            Submit::Enqueued(id) => id,
            other => panic!("{:?}", other),
        };
        queue.approve(id, "king", 0);
        assert!(queue.pending().is_empty());

        queue.submit("write /a", "不可逆", 1_000);
        assert!(queue.pending().is_empty(), "复用不应当再生成待办");
    }
}
