// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

//! File content hashes from the process tracer (`--content-hash`).
//!
//! The tracer emits one `FILE_CONTENT` event per phase of a file's life
//! (`read`, `before_write`, `after_write`, `renamed`, `deleted`), keyed by the
//! file's (dev, inode). This module folds them into one audit row per inode
//! (`audit_type = "file_content"`, upserted as new phases arrive) and turns
//! those rows into a per-path report that follows atomic replaces (write a
//! temp file, rename it over the target), including chains of them.
//!
//! Inode numbers are reused quickly (ext4 hands a freed number to the next
//! new file), so each inode has numbered "lives": after the inode was deleted
//! or replaced, a new read or first write starts a new life and a new row.

use crate::model::{AuditEventRow, ViewResult};
use crate::view::{CanonicalEvent, MaterializedView};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

pub const FILE_CONTENT_AUDIT_TYPE: &str = "file_content";
/// One row counting tracer events lost before they reached user space. If it
/// exists, the content report may be incomplete.
pub const FILE_CONTENT_LOST_AUDIT_TYPE: &str = "file_content_lost";

/// Exact measurement made in the kernel before the first write.
const SOURCE_KERNEL: &str = "kernel_ima";
/// User-space fallback when the kernel could not measure the open (O_RDWR):
/// usable, but the agent could have written first.
const SOURCE_LATE: &str = "userspace_late";

/// One measurement of a file's content.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContentHash {
    pub sha256: Option<String>,
    /// ok, created, too_large, rdwr, path_gone, inode_mismatch, ...
    pub status: Option<String>,
    /// kernel_ima, userspace, or userspace_late
    pub source: Option<String>,
    pub timestamp_ms: u64,
}

impl ContentHash {
    fn digest(&self) -> Option<&str> {
        self.sha256.as_deref()
    }
}

/// Everything known about one life of one inode the agent touched.
#[derive(Debug, Clone, Default)]
pub(crate) struct FileContentState {
    dev: u64,
    ino: u64,
    life: u32,
    path: Option<String>,
    /// First read-only open (user space).
    read: Option<ContentHash>,
    /// First writable open, as reported by the kernel (may carry no digest).
    before_write: Option<ContentHash>,
    /// User-space fallback for a writable open the kernel could not measure.
    before_late: Option<ContentHash>,
    /// Latest measurement after a write.
    after_write: Option<ContentHash>,
    after_writes: u64,
    created: bool,
    deleted: bool,
    renamed_from: Option<String>,
    replaced_ino: Option<u64>,
    /// Row key of the inode life this one replaced at its path.
    replaced_key: Option<String>,
    /// Row key of the inode life that replaced this one.
    replaced_by_key: Option<String>,
    first_seen_ms: u64,
    last_seen_ms: u64,
    pid: Option<u32>,
    comm: Option<String>,
}

fn inode_key(dev: u64, ino: u64) -> String {
    format!("{dev}:{ino}")
}

impl FileContentState {
    fn fresh(dev: u64, ino: u64, life: u32, timestamp_ms: u64) -> Self {
        Self {
            dev,
            ino,
            life,
            first_seen_ms: timestamp_ms,
            last_seen_ms: timestamp_ms,
            ..Default::default()
        }
    }

    fn row_key(&self) -> String {
        format!("{}:{}:{}", self.dev, self.ino, self.life)
    }

    /// The inode was deleted or replaced: anything new is a different file.
    fn ended(&self) -> bool {
        self.deleted || self.replaced_by_key.is_some()
    }

    fn has_history(&self) -> bool {
        self.read.is_some() || self.before_write.is_some() || self.after_write.is_some()
    }

    fn written(&self) -> bool {
        self.before_write.is_some() || self.before_late.is_some()
    }

    /// Content before the agent's first modification, best source first:
    /// the exact in-kernel hash, then the hash taken at the first read-only
    /// open (it precedes the write), then the late user-space fallback.
    fn before(&self) -> Option<&ContentHash> {
        let exact = self
            .before_write
            .as_ref()
            .filter(|h| h.source.as_deref() == Some(SOURCE_KERNEL) && h.digest().is_some());
        exact
            .or(self.read.as_ref().filter(|h| h.digest().is_some()))
            .or(self.before_late.as_ref().filter(|h| h.digest().is_some()))
    }

    /// Content after the agent's last write. A file that was only read is
    /// unchanged, so its "after" is what was read.
    fn after(&self) -> Option<&ContentHash> {
        if self.ended() {
            return None;
        }
        if let Some(after) = self.after_write.as_ref().filter(|h| h.digest().is_some()) {
            return Some(after);
        }
        if !self.written() && !self.created {
            return self.read.as_ref().filter(|h| h.digest().is_some());
        }
        None
    }

    fn outcome(&self) -> &'static str {
        if self.replaced_by_key.is_some() {
            "replaced"
        } else if self.deleted {
            "deleted"
        } else if self.replaced_ino.is_some() {
            "atomic_replace"
        } else if self.created {
            "created"
        } else if self.written() {
            match (
                self.before().and_then(ContentHash::digest),
                self.after().and_then(ContentHash::digest),
            ) {
                (Some(before), Some(after)) if before == after => "unchanged",
                (Some(_), Some(_)) => "modified",
                _ => "written",
            }
        } else if self.read.is_some() {
            "read"
        } else {
            "observed"
        }
    }

    fn audit_row(&self, confidence: Option<f32>) -> AuditEventRow {
        let outcome = self.outcome();
        let path = self.path.clone().unwrap_or_default();
        let before = self.before();
        let after = self.after();
        AuditEventRow {
            id: format!("file-content-{}-{}-{}", self.dev, self.ino, self.life),
            timestamp_ms: self.first_seen_ms,
            audit_type: FILE_CONTENT_AUDIT_TYPE.to_string(),
            pid: self.pid,
            comm: self.comm.clone(),
            subject: self.comm.clone(),
            action: Some(outcome.to_string()),
            target: self.path.clone(),
            status: Some("observed".to_string()),
            summary: Some(format!("{outcome}: {path}")),
            details: json!({
                "row_key": self.row_key(),
                "path": self.path,
                "dev": self.dev,
                "ino": self.ino,
                "life": self.life,
                "outcome": outcome,
                "before_sha256": before.and_then(ContentHash::digest),
                "before_source": before.and_then(|h| h.source.as_deref()),
                "after_sha256": after.and_then(ContentHash::digest),
                "after_source": after.and_then(|h| h.source.as_deref()),
                "read": self.read,
                "before_write": self.before_write,
                "before_late": self.before_late,
                "after_write": self.after_write,
                "after_writes": self.after_writes,
                "created": self.created,
                "deleted": self.deleted,
                "renamed_from": self.renamed_from,
                "replaced_ino": self.replaced_ino,
                "replaced_key": self.replaced_key,
                "replaced_by_key": self.replaced_by_key,
                "first_seen_ms": self.first_seen_ms,
                "last_seen_ms": self.last_seen_ms,
            }),
            view_source: "view".to_string(),
            confidence,
        }
    }
}

fn str_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

impl MaterializedView {
    pub(crate) fn ingest_file_content(&mut self, event: &CanonicalEvent) -> ViewResult<()> {
        let attrs = &event.attributes;
        let name = attrs.get("event").and_then(Value::as_str).unwrap_or("");
        if name.ends_with("_LOST") {
            let count = attrs.get("count").and_then(Value::as_u64).unwrap_or(0);
            if count == 0 {
                return Ok(());
            }
            self.content_events_lost += count;
            let total = self.content_events_lost;
            return self.emit_audit_event(AuditEventRow {
                id: "file-content-lost".to_string(),
                timestamp_ms: event.timestamp_ms,
                audit_type: FILE_CONTENT_LOST_AUDIT_TYPE.to_string(),
                pid: None,
                comm: Some("process".to_string()),
                subject: None,
                action: Some("lost".to_string()),
                target: None,
                status: Some("warning".to_string()),
                summary: Some(format!("{total} tracer events lost (ring buffer full)")),
                details: json!({ "lost": total }),
                view_source: "view".to_string(),
                confidence: event.confidence,
            });
        }
        let (Some(dev), Some(ino)) = (
            attrs.get("dev").and_then(Value::as_u64),
            attrs.get("ino").and_then(Value::as_u64),
        ) else {
            return Ok(());
        };
        let phase = attrs.get("phase").and_then(Value::as_str).unwrap_or("");
        if !matches!(
            phase,
            "read" | "before_write" | "after_write" | "renamed" | "deleted"
        ) {
            return Ok(()); // e.g. link_removed: the inode lives on
        }
        let ts = event.timestamp_ms;
        let hash = ContentHash {
            sha256: str_field(attrs, "sha256"),
            status: str_field(attrs, "hash_status"),
            source: str_field(attrs, "hash_source"),
            timestamp_ms: ts,
        };
        let key = inode_key(dev, ino);
        // Resolve the victim of a rename before borrowing this inode's state.
        let replaced_ino = attrs.get("replaced_ino").and_then(Value::as_u64);
        let exchange = attrs
            .get("exchange")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let victim_key = replaced_ino
            .filter(|_| phase == "renamed")
            .and_then(|old| self.file_contents.get(&inode_key(dev, old)))
            .map(FileContentState::row_key);

        let state = self
            .file_contents
            .entry(key)
            .or_insert_with(|| FileContentState::fresh(dev, ino, 0, ts));
        let reused = match phase {
            "read" | "before_write" => state.ended(),
            _ => false,
        } || (phase == "before_write"
            && hash.status.as_deref() == Some("created")
            && state.has_history());
        if reused {
            *state = FileContentState::fresh(dev, ino, state.life + 1, ts);
        }
        state.first_seen_ms = state.first_seen_ms.min(ts);
        state.last_seen_ms = state.last_seen_ms.max(ts);
        let renamed_from = str_field(attrs, "renamed_from");
        if let Some(path) = str_field(attrs, "filepath") {
            state.path = Some(path);
        }
        if event.pid.is_some_and(|pid| pid > 0) {
            state.pid = event.pid;
            state.comm = event.comm.clone();
        }

        match phase {
            "read" => {
                if state.read.is_none() {
                    state.read = Some(hash);
                }
            }
            "before_write" => {
                if hash.status.as_deref() == Some("created") {
                    state.created = true;
                }
                if hash.source.as_deref() == Some(SOURCE_LATE) {
                    if state.before_late.is_none() {
                        state.before_late = Some(hash);
                    }
                } else if state.before_write.is_none() {
                    state.before_write = Some(hash);
                }
            }
            "after_write" => {
                state.after_write = Some(hash);
                state.after_writes += 1;
            }
            "renamed" => {
                state.deleted = false;
                if renamed_from.is_some() {
                    state.renamed_from = renamed_from.clone();
                }
                if !exchange && replaced_ino.is_some() {
                    state.replaced_ino = replaced_ino;
                    state.replaced_key = victim_key;
                }
            }
            "deleted" => state.deleted = true,
            _ => unreachable!(),
        }
        let new_key = state.row_key();
        let row = state.audit_row(event.confidence);
        self.emit_audit_event(row)?;

        // Update the inode that used to live at the target path.
        if phase == "renamed"
            && let Some(old) = replaced_ino
            && let Some(old_state) = self.file_contents.get_mut(&inode_key(dev, old))
        {
            if exchange {
                // The two files swapped names.
                if renamed_from.is_some() {
                    old_state.path = renamed_from;
                }
            } else {
                old_state.replaced_by_key = Some(new_key);
            }
            old_state.last_seen_ms = old_state.last_seen_ms.max(ts);
            let row = old_state.audit_row(event.confidence);
            self.emit_audit_event(row)?;
        }
        Ok(())
    }
}

/// One line of `agentsight report files`: a path with its content before the
/// agent touched it and after the agent's last write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileContentReportRow {
    pub path: String,
    /// read, modified, unchanged, created, deleted, written, ...
    pub outcome: String,
    /// in_place, atomic_replace, read_only, created, deleted
    pub method: String,
    pub before_sha256: Option<String>,
    pub before_source: Option<String>,
    pub after_sha256: Option<String>,
    pub after_source: Option<String>,
    /// "dev:ino:life" of the inodes involved, oldest first
    pub inodes: Vec<String>,
    pub renamed_from: Option<String>,
    pub comm: Option<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone)]
struct RowView {
    key: String,
    path: String,
    outcome: String,
    before: Option<String>,
    before_source: Option<String>,
    after: Option<String>,
    after_source: Option<String>,
    renamed_from: Option<String>,
    replaced_ino: Option<u64>,
    replaced_key: Option<String>,
    comm: Option<String>,
    first_seen_ms: u64,
    last_seen_ms: u64,
}

fn row_view(row: &AuditEventRow) -> Option<RowView> {
    let d = &row.details;
    let key = str_field(d, "row_key")?;
    Some(RowView {
        key,
        path: str_field(d, "path").unwrap_or_else(|| "?".to_string()),
        outcome: str_field(d, "outcome").unwrap_or_else(|| "observed".to_string()),
        before: str_field(d, "before_sha256"),
        before_source: str_field(d, "before_source"),
        after: str_field(d, "after_sha256"),
        after_source: str_field(d, "after_source"),
        renamed_from: str_field(d, "renamed_from"),
        replaced_ino: d.get("replaced_ino").and_then(Value::as_u64),
        replaced_key: str_field(d, "replaced_key"),
        comm: row.comm.clone(),
        first_seen_ms: d
            .get("first_seen_ms")
            .and_then(Value::as_u64)
            .unwrap_or(row.timestamp_ms),
        last_seen_ms: d
            .get("last_seen_ms")
            .and_then(Value::as_u64)
            .unwrap_or(row.timestamp_ms),
    })
}

fn method_for(outcome: &str) -> &'static str {
    match outcome {
        "read" => "read_only",
        "created" => "created",
        "deleted" => "deleted",
        "atomic_replace" => "atomic_replace",
        _ => "in_place",
    }
}

fn standalone(view: &RowView) -> FileContentReportRow {
    FileContentReportRow {
        path: view.path.clone(),
        outcome: view.outcome.clone(),
        method: method_for(&view.outcome).to_string(),
        before_sha256: view.before.clone(),
        before_source: view.before_source.clone(),
        after_sha256: view.after.clone(),
        after_source: view.after_source.clone(),
        inodes: vec![view.key.clone()],
        renamed_from: view.renamed_from.clone(),
        comm: view.comm.clone(),
        first_seen_ms: view.first_seen_ms,
        last_seen_ms: view.last_seen_ms,
    }
}

/// Fold per-inode `file_content` audit rows into per-path report rows.
///
/// A sequence of atomic replaces of one path (original <- tmp1 <- tmp2 ...)
/// is one row: "before" from the original inode, "after" from the last one.
pub fn file_content_report(rows: &[AuditEventRow]) -> Vec<FileContentReportRow> {
    let views: BTreeMap<String, RowView> = rows
        .iter()
        .filter(|row| row.audit_type == FILE_CONTENT_AUDIT_TYPE)
        .filter_map(row_view)
        .map(|view| (view.key.clone(), view))
        .collect();
    // Rows that are an earlier link of some replace chain.
    let superseded: HashSet<&str> = views
        .values()
        .filter_map(|v| v.replaced_key.as_deref())
        .filter(|key| views.contains_key(*key))
        .collect();
    let mut out = Vec::new();

    for view in views.values() {
        if superseded.contains(view.key.as_str()) {
            continue; // reported as part of the chain's final row
        }
        if view.replaced_ino.is_none() {
            out.push(standalone(view));
            continue;
        }
        // Final inode of a replace chain: walk back to the original.
        let mut chain = vec![view];
        let mut seen = HashSet::from([view.key.as_str()]);
        while let Some(prev) = chain
            .last()
            .and_then(|v| v.replaced_key.as_deref())
            .and_then(|key| views.get(key))
        {
            if !seen.insert(prev.key.as_str()) {
                break;
            }
            chain.push(prev);
        }
        chain.reverse();
        let origin = chain[0];
        let has_origin = origin.replaced_ino.is_none();
        let (before, before_source) = if has_origin {
            (origin.before.clone(), origin.before_source.clone())
        } else {
            (None, None) // the replaced file was never observed
        };
        let outcome = match (&before, &view.after) {
            (Some(b), Some(a)) if a == b => "unchanged",
            (Some(_), Some(_)) => "modified",
            (None, Some(_)) => "replaced",
            _ => "written",
        };
        out.push(FileContentReportRow {
            path: view.path.clone(),
            outcome: outcome.to_string(),
            method: "atomic_replace".to_string(),
            before_sha256: before,
            before_source,
            after_sha256: view.after.clone(),
            after_source: view.after_source.clone(),
            inodes: chain.iter().map(|v| v.key.clone()).collect(),
            renamed_from: view.renamed_from.clone(),
            comm: view.comm.clone(),
            first_seen_ms: chain.iter().map(|v| v.first_seen_ms).min().unwrap_or(0),
            last_seen_ms: view.last_seen_ms,
        });
    }
    out.sort_by(|a, b| {
        a.first_seen_ms
            .cmp(&b.first_seen_ms)
            .then_with(|| a.path.cmp(&b.path))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

    const A: &str = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
    const B: &str = "6052eef1a76d3ff777269e8a1720524953b74c4d96e4689679c8982699a32beb";
    const C: &str = "560cfb16a87e0e938208c0a072d5f837ffdf842feed4de3c34fd6069a30d3522";

    fn content_event(ts: u64, data: Value) -> Event {
        let mut data = data;
        data["event"] = json!("FILE_CONTENT");
        Event::new_with_timestamp(ts, "process".to_string(), 42, "claude".to_string(), data)
    }

    fn report(view: &MaterializedView) -> Vec<FileContentReportRow> {
        file_content_report(&view.audit_rows(Some(FILE_CONTENT_AUDIT_TYPE), 1000))
    }

    /// JSON lines exactly as printed by bpf/process (captured from
    /// bpf/tests/test_process_ext_content.c), through the SQLite sink and back.
    #[test]
    fn tracer_output_survives_sqlite_round_trip() {
        const LINES: &[&str] = &[
            r#"{"timestamp":1,"event":"FILE_CONTENT","comm":"agent","pid":7,"phase":"before_write","filepath":"/w/notes.md","dev":266338304,"dev_maj_min":"254:0","ino":1008688,"size":6,"sha256":"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03","hash_source":"kernel_ima","hash_status":"ok"}"#,
            r#"{"timestamp":2,"event":"FILE_CONTENT","comm":"agent","pid":7,"phase":"after_write","filepath":"/w/notes.md","dev":266338304,"dev_maj_min":"254:0","ino":1008688,"size":11,"sha256":"6052eef1a76d3ff777269e8a1720524953b74c4d96e4689679c8982699a32beb","hash_source":"userspace","hash_status":"ok"}"#,
            r#"{"timestamp":3,"event":"FILE_CONTENT","comm":"agent","pid":7,"phase":"before_write","filepath":"/w/.notes.md.tmp","dev":266338304,"dev_maj_min":"254:0","ino":1008700,"size":6,"hash_source":"kernel_ima","hash_status":"created"}"#,
            r#"{"timestamp":4,"event":"FILE_CONTENT","comm":"agent","pid":7,"phase":"renamed","filepath":"/w/notes.md","dev":266338304,"dev_maj_min":"254:0","ino":1008700,"size":6,"renamed_from":"/w/.notes.md.tmp","replaced_ino":1008688}"#,
            r#"{"timestamp":5,"event":"FILE_CONTENT","comm":"agent","pid":7,"phase":"after_write","filepath":"/w/notes.md","dev":266338304,"dev_maj_min":"254:0","ino":1008700,"size":6,"sha256":"560cfb16a87e0e938208c0a072d5f837ffdf842feed4de3c34fd6069a30d3522","hash_source":"userspace","hash_status":"ok"}"#,
        ];
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("session.db");
        let mut view = MaterializedView::new();
        view.add_sink(Box::new(
            crate::sinks::sqlite::SqliteStore::open(&db).unwrap(),
        ));
        for line in LINES {
            let data: Value = serde_json::from_str(line).unwrap();
            let ts = data["timestamp"].as_u64().unwrap();
            view.ingest_event(&content_event(ts, data)).unwrap();
        }
        drop(view);

        let loaded = crate::sources::sqlite::load_view(&db).unwrap();
        let report = report(&loaded);
        assert_eq!(report.len(), 1, "{report:?}");
        // In-place edit (A -> B) followed by an atomic replace (-> C):
        // before is the kernel hash of the original inode, after is C.
        assert_eq!(report[0].path, "/w/notes.md");
        assert_eq!(report[0].method, "atomic_replace");
        assert_eq!(report[0].before_sha256.as_deref(), Some(A));
        assert_eq!(report[0].before_source.as_deref(), Some("kernel_ima"));
        assert_eq!(report[0].after_sha256.as_deref(), Some(C));
        assert_eq!(report[0].outcome, "modified");
    }

    #[test]
    fn in_place_edit_keeps_kernel_before_and_latest_after() {
        let mut view = MaterializedView::new();
        let events = [
            json!({"phase": "read", "filepath": "/w/a.txt", "dev": 8, "ino": 1,
                   "sha256": A, "hash_source": "userspace", "hash_status": "ok"}),
            json!({"phase": "before_write", "filepath": "/w/a.txt", "dev": 8, "ino": 1,
                   "sha256": A, "hash_source": "kernel_ima", "hash_status": "ok"}),
            json!({"phase": "after_write", "filepath": "/w/a.txt", "dev": 8, "ino": 1,
                   "sha256": B, "hash_source": "userspace", "hash_status": "ok"}),
            json!({"phase": "after_write", "filepath": "/w/a.txt", "dev": 8, "ino": 1,
                   "sha256": C, "hash_source": "userspace", "hash_status": "ok"}),
        ];
        for (i, data) in events.into_iter().enumerate() {
            view.ingest_event(&content_event(1000 + i as u64, data))
                .unwrap();
        }
        let rows = view.audit_rows(Some(FILE_CONTENT_AUDIT_TYPE), 10);
        assert_eq!(rows.len(), 1, "one upserted row per inode");
        assert_eq!(rows[0].details["after_writes"], 2);

        let report = report(&view);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].outcome, "modified");
        assert_eq!(report[0].method, "in_place");
        assert_eq!(report[0].before_sha256.as_deref(), Some(A));
        assert_eq!(report[0].before_source.as_deref(), Some("kernel_ima"));
        assert_eq!(report[0].after_sha256.as_deref(), Some(C));
    }

    #[test]
    fn read_only_file_is_unchanged() {
        let mut view = MaterializedView::new();
        view.ingest_event(&content_event(
            1,
            json!({"phase": "read", "filepath": "/w/r.txt", "dev": 8, "ino": 2,
                   "sha256": A, "hash_source": "userspace", "hash_status": "ok"}),
        ))
        .unwrap();
        let report = report(&view);
        assert_eq!(report[0].outcome, "read");
        assert_eq!(report[0].method, "read_only");
        assert_eq!(report[0].before_sha256.as_deref(), Some(A));
        assert_eq!(report[0].after_sha256.as_deref(), Some(A));
    }

    #[test]
    fn atomic_replace_merges_old_and_new_inode() {
        let mut view = MaterializedView::new();
        let events = [
            json!({"phase": "read", "filepath": "/w/notes.md", "dev": 8, "ino": 10,
                   "sha256": A, "hash_source": "userspace", "hash_status": "ok"}),
            json!({"phase": "before_write", "filepath": "/w/.notes.md.tmp", "dev": 8, "ino": 11,
                   "hash_source": "kernel_ima", "hash_status": "created"}),
            json!({"phase": "renamed", "filepath": "/w/notes.md", "dev": 8, "ino": 11,
                   "renamed_from": "/w/.notes.md.tmp", "replaced_ino": 10}),
            json!({"phase": "after_write", "filepath": "/w/notes.md", "dev": 8, "ino": 11,
                   "sha256": B, "hash_source": "userspace", "hash_status": "ok"}),
        ];
        for (i, data) in events.into_iter().enumerate() {
            view.ingest_event(&content_event(10 + i as u64, data))
                .unwrap();
        }
        let old = view
            .audit_rows(Some(FILE_CONTENT_AUDIT_TYPE), 10)
            .into_iter()
            .find(|row| row.details["ino"] == 10)
            .unwrap();
        assert_eq!(old.action.as_deref(), Some("replaced"));

        let report = report(&view);
        assert_eq!(report.len(), 1, "{report:?}");
        assert_eq!(report[0].path, "/w/notes.md");
        assert_eq!(report[0].method, "atomic_replace");
        assert_eq!(report[0].outcome, "modified");
        assert_eq!(report[0].before_sha256.as_deref(), Some(A));
        assert_eq!(report[0].after_sha256.as_deref(), Some(B));
        assert_eq!(report[0].renamed_from.as_deref(), Some("/w/.notes.md.tmp"));
        assert_eq!(
            report[0].inodes,
            vec!["8:10:0".to_string(), "8:11:0".to_string()]
        );
    }

    #[test]
    fn created_and_deleted_files() {
        let mut view = MaterializedView::new();
        let events = [
            json!({"phase": "before_write", "filepath": "/w/new.txt", "dev": 8, "ino": 20,
                   "hash_source": "kernel_ima", "hash_status": "created"}),
            json!({"phase": "after_write", "filepath": "/w/new.txt", "dev": 8, "ino": 20,
                   "sha256": C, "hash_source": "userspace", "hash_status": "ok"}),
            json!({"phase": "before_write", "filepath": "/w/gone.txt", "dev": 8, "ino": 21,
                   "sha256": A, "hash_source": "kernel_ima", "hash_status": "ok"}),
            json!({"phase": "deleted", "filepath": "/w/gone.txt", "dev": 8, "ino": 21}),
        ];
        for (i, data) in events.into_iter().enumerate() {
            view.ingest_event(&content_event(100 + i as u64, data))
                .unwrap();
        }
        let report = report(&view);
        let created = report.iter().find(|r| r.path == "/w/new.txt").unwrap();
        assert_eq!(created.outcome, "created");
        assert_eq!(created.before_sha256, None);
        assert_eq!(created.after_sha256.as_deref(), Some(C));
        let gone = report.iter().find(|r| r.path == "/w/gone.txt").unwrap();
        assert_eq!(gone.outcome, "deleted");
        assert_eq!(gone.before_sha256.as_deref(), Some(A));
        assert_eq!(gone.after_sha256, None);
    }

    fn ingest_all(view: &mut MaterializedView, events: Vec<Value>) {
        for (i, data) in events.into_iter().enumerate() {
            view.ingest_event(&content_event(1000 + i as u64, data))
                .unwrap();
        }
    }

    #[test]
    fn repeated_atomic_saves_are_one_row() {
        // original (10) <- tmp (11) <- tmp (12): one row, before of 10, after of 12.
        let mut view = MaterializedView::new();
        ingest_all(
            &mut view,
            vec![
                json!({"phase": "read", "filepath": "/w/x", "dev": 8, "ino": 10,
                       "sha256": A, "hash_source": "userspace", "hash_status": "ok"}),
                json!({"phase": "before_write", "filepath": "/w/x.tmp", "dev": 8, "ino": 11,
                       "hash_source": "kernel_ima", "hash_status": "created"}),
                json!({"phase": "renamed", "filepath": "/w/x", "dev": 8, "ino": 11,
                       "renamed_from": "/w/x.tmp", "replaced_ino": 10}),
                json!({"phase": "after_write", "filepath": "/w/x", "dev": 8, "ino": 11,
                       "sha256": B, "hash_source": "userspace", "hash_status": "ok"}),
                json!({"phase": "before_write", "filepath": "/w/x.tmp", "dev": 8, "ino": 12,
                       "hash_source": "kernel_ima", "hash_status": "created"}),
                json!({"phase": "renamed", "filepath": "/w/x", "dev": 8, "ino": 12,
                       "renamed_from": "/w/x.tmp", "replaced_ino": 11}),
                json!({"phase": "after_write", "filepath": "/w/x", "dev": 8, "ino": 12,
                       "sha256": C, "hash_source": "userspace", "hash_status": "ok"}),
            ],
        );
        let report = report(&view);
        assert_eq!(report.len(), 1, "{report:?}");
        assert_eq!(report[0].before_sha256.as_deref(), Some(A));
        assert_eq!(report[0].after_sha256.as_deref(), Some(C));
        assert_eq!(report[0].inodes, vec!["8:10:0", "8:11:0", "8:12:0"]);
        assert_eq!(report[0].outcome, "modified");
    }

    #[test]
    fn reused_inode_number_starts_a_new_life() {
        // ino 10 is replaced by 11; later a new temp file gets number 10 again.
        let mut view = MaterializedView::new();
        ingest_all(
            &mut view,
            vec![
                json!({"phase": "read", "filepath": "/w/x", "dev": 8, "ino": 10,
                       "sha256": A, "hash_source": "userspace", "hash_status": "ok"}),
                json!({"phase": "before_write", "filepath": "/w/x.tmp", "dev": 8, "ino": 11,
                       "hash_source": "kernel_ima", "hash_status": "created"}),
                json!({"phase": "renamed", "filepath": "/w/x", "dev": 8, "ino": 11,
                       "renamed_from": "/w/x.tmp", "replaced_ino": 10}),
                json!({"phase": "after_write", "filepath": "/w/x", "dev": 8, "ino": 11,
                       "sha256": B, "hash_source": "userspace", "hash_status": "ok"}),
                json!({"phase": "before_write", "filepath": "/w/x.tmp", "dev": 8, "ino": 10,
                       "hash_source": "kernel_ima", "hash_status": "created"}),
                json!({"phase": "renamed", "filepath": "/w/x", "dev": 8, "ino": 10,
                       "renamed_from": "/w/x.tmp", "replaced_ino": 11}),
                json!({"phase": "after_write", "filepath": "/w/x", "dev": 8, "ino": 10,
                       "sha256": C, "hash_source": "userspace", "hash_status": "ok"}),
            ],
        );
        let rows = view.audit_rows(Some(FILE_CONTENT_AUDIT_TYPE), 10);
        assert_eq!(rows.len(), 3, "two lives of inode 10 plus inode 11");
        let report = report(&view);
        assert_eq!(report.len(), 1, "{report:?}");
        assert_eq!(report[0].inodes, vec!["8:10:0", "8:11:0", "8:10:1"]);
        assert_eq!(report[0].before_sha256.as_deref(), Some(A));
        assert_eq!(report[0].after_sha256.as_deref(), Some(C));
    }

    #[test]
    fn exact_kernel_hash_beats_read_and_late_fallback() {
        let mut view = MaterializedView::new();
        ingest_all(
            &mut view,
            vec![
                // O_RDWR open: no kernel digest, late fallback with B.
                json!({"phase": "read", "filepath": "/w/db", "dev": 8, "ino": 30,
                       "sha256": A, "hash_source": "userspace", "hash_status": "ok"}),
                json!({"phase": "before_write", "filepath": "/w/db", "dev": 8, "ino": 30,
                       "hash_source": "kernel_ima", "hash_status": "rdwr"}),
                json!({"phase": "before_write", "filepath": "/w/db", "dev": 8, "ino": 30,
                       "sha256": B, "hash_source": "userspace_late", "hash_status": "ok"}),
                // O_RDWR open of a file never read: only the late fallback.
                json!({"phase": "before_write", "filepath": "/w/db2", "dev": 8, "ino": 31,
                       "hash_source": "kernel_ima", "hash_status": "rdwr"}),
                json!({"phase": "before_write", "filepath": "/w/db2", "dev": 8, "ino": 31,
                       "sha256": C, "hash_source": "userspace_late", "hash_status": "ok"}),
            ],
        );
        let report = report(&view);
        let db = report.iter().find(|r| r.path == "/w/db").unwrap();
        assert_eq!(
            db.before_sha256.as_deref(),
            Some(A),
            "read precedes the write"
        );
        assert_eq!(db.before_source.as_deref(), Some("userspace"));
        let db2 = report.iter().find(|r| r.path == "/w/db2").unwrap();
        assert_eq!(db2.before_sha256.as_deref(), Some(C));
        assert_eq!(db2.before_source.as_deref(), Some("userspace_late"));
    }

    #[test]
    fn rename_exchange_swaps_paths_without_replacing() {
        let mut view = MaterializedView::new();
        ingest_all(
            &mut view,
            vec![
                json!({"phase": "read", "filepath": "/w/a", "dev": 8, "ino": 40,
                       "sha256": A, "hash_source": "userspace", "hash_status": "ok"}),
                json!({"phase": "read", "filepath": "/w/b", "dev": 8, "ino": 41,
                       "sha256": B, "hash_source": "userspace", "hash_status": "ok"}),
                json!({"phase": "renamed", "filepath": "/w/b", "dev": 8, "ino": 40,
                       "renamed_from": "/w/a", "replaced_ino": 41, "exchange": true}),
            ],
        );
        let report = report(&view);
        assert_eq!(report.len(), 2, "{report:?}");
        assert!(report.iter().all(|r| r.method != "atomic_replace"));
        let at_a = report.iter().find(|r| r.path == "/w/a").unwrap();
        assert_eq!(at_a.before_sha256.as_deref(), Some(B));
    }

    #[test]
    fn lost_events_are_counted_in_one_row() {
        let mut view = MaterializedView::new();
        for (ts, data) in [
            (
                1,
                json!({"event": "CONTENT_HASH_LOST", "pid": 0, "comm": "process", "count": 3}),
            ),
            (
                2,
                json!({"event": "FILE_OPEN_LOST", "pid": 0, "comm": "process", "count": 4}),
            ),
        ] {
            let event = Event::new_with_timestamp(ts, "process".into(), 0, "process".into(), data);
            view.ingest_event(&event).unwrap();
        }
        let rows = view.audit_rows(Some(FILE_CONTENT_LOST_AUDIT_TYPE), 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].details["lost"], 7);
        assert!(report(&view).is_empty());
    }

    #[test]
    fn content_events_do_not_create_plain_file_audit_rows() {
        let mut view = MaterializedView::new();
        view.ingest_event(&content_event(
            1,
            json!({"phase": "after_write", "filepath": "/w/a.txt", "dev": 8, "ino": 1,
                   "sha256": A, "hash_source": "userspace", "hash_status": "ok"}),
        ))
        .unwrap();
        assert!(view.audit_rows(Some("file"), 10).is_empty());
    }
}
