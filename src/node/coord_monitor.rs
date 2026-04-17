//! Unified coordinate-monitoring events for tree and discovery state.

use std::collections::BTreeSet;

use crate::NodeAddr;
use crate::identity::encode_npub;
use crate::protocol::{LookupRequest, LookupResponse, TreeAnnounce};
use crate::tree::TreeCoordinate;
use serde_json::{Map as JsonMap, Value, json};
use tracing::debug;

use super::Node;

impl Node {
    fn coord_monitor_emit(&self, mut event: JsonMap<String, Value>) {
        event.insert("schema".into(), json!("coord_monitor_v2"));
        event.insert("observed_at_ms".into(), json!(Self::now_ms()));

        let payload = serde_json::to_string(&Value::Object(event)).unwrap_or_else(|e| {
            format!(
                r#"{{"schema":"coord_monitor_v2","event":"serialization_error","error":"{e}"}}"#
            )
        });
        debug!(target: "full_coord_monitoring", payload = %payload, "coord_monitor");
    }

    fn coord_monitor_node_addr(&self, addr: &NodeAddr) -> String {
        hex::encode(addr.as_bytes())
    }

    fn coord_monitor_npub(&self, addr: &NodeAddr) -> Option<String> {
        if addr == self.node_addr() {
            return Some(self.npub());
        }

        if let Some(peer) = self.peers.get(addr) {
            return Some(peer.npub());
        }

        if let Some(entry) = self.sessions.get(addr) {
            let (xonly, _) = entry.remote_pubkey().x_only_public_key();
            return Some(encode_npub(&xonly));
        }

        if let Some((_node_addr, pubkey, _last_seen_ms)) = self
            .identity_cache_iter()
            .find(|(node_addr, _, _)| *node_addr == addr)
        {
            let (xonly, _) = pubkey.x_only_public_key();
            return Some(encode_npub(&xonly));
        }

        if let Some(hostname) = self.host_map.lookup_hostname(addr)
            && let Some(npub) = self.host_map.lookup_npub(hostname)
        {
            return Some(npub.to_string());
        }

        None
    }

    fn coord_monitor_identity_entry(&self, addr: &NodeAddr) -> Value {
        let mut entry = JsonMap::new();
        entry.insert("display_name".into(), json!(self.peer_display_name(addr)));
        if let Some(npub) = self.coord_monitor_npub(addr) {
            entry.insert("npub".into(), json!(npub));
        }
        Value::Object(entry)
    }

    fn coord_monitor_collect_identities(
        &self,
        addrs: &[NodeAddr],
        coords: Option<&TreeCoordinate>,
    ) -> Value {
        let mut unique = BTreeSet::new();
        for addr in addrs {
            unique.insert(*addr);
        }
        if let Some(coords) = coords {
            for entry in coords.entries() {
                unique.insert(entry.node_addr);
            }
        }

        let mut identities = JsonMap::new();
        for addr in unique {
            identities.insert(
                self.coord_monitor_node_addr(&addr),
                self.coord_monitor_identity_entry(&addr),
            );
        }
        Value::Object(identities)
    }

    fn coord_monitor_insert_coords(
        &self,
        event: &mut JsonMap<String, Value>,
        kind: &str,
        coords: &TreeCoordinate,
    ) {
        let entries: Vec<String> = coords
            .entries()
            .iter()
            .map(|entry| self.coord_monitor_node_addr(&entry.node_addr))
            .collect();

        event.insert("coords_kind".into(), json!(kind));
        event.insert("coords".into(), json!(entries));
        event.insert(
            "coords_root".into(),
            json!(self.coord_monitor_node_addr(coords.root_id())),
        );
        event.insert("coords_depth".into(), json!(coords.depth()));
    }

    fn coord_monitor_insert_coord_entry_meta(
        &self,
        event: &mut JsonMap<String, Value>,
        coords: &TreeCoordinate,
    ) {
        let meta: Vec<Value> = coords
            .entries()
            .iter()
            .map(|entry| {
                json!({
                    "sequence": entry.sequence,
                    "timestamp": entry.timestamp,
                })
            })
            .collect();
        event.insert("coord_entry_meta".into(), Value::Array(meta));
    }

    fn coord_monitor_lookup_request_event(
        &self,
        event_name: &str,
        from: Option<&NodeAddr>,
        to: Option<&NodeAddr>,
        request: &LookupRequest,
        used_fallback: Option<bool>,
    ) {
        let observer = *self.node_addr();
        let mut referenced = vec![observer, request.target, request.origin];
        if let Some(from) = from {
            referenced.push(*from);
        }
        if let Some(to) = to {
            referenced.push(*to);
        }

        let mut event = JsonMap::new();
        event.insert("event".into(), json!(event_name));
        event.insert(
            "observer".into(),
            json!(self.coord_monitor_node_addr(&observer)),
        );
        if let Some(from) = from {
            event.insert("from".into(), json!(self.coord_monitor_node_addr(from)));
        }
        if let Some(to) = to {
            event.insert("to".into(), json!(self.coord_monitor_node_addr(to)));
        }
        event.insert("request_id".into(), json!(request.request_id));
        event.insert(
            "target".into(),
            json!(self.coord_monitor_node_addr(&request.target)),
        );
        event.insert(
            "origin".into(),
            json!(self.coord_monitor_node_addr(&request.origin)),
        );
        event.insert("ttl".into(), json!(request.ttl));
        event.insert("min_mtu".into(), json!(request.min_mtu));
        if let Some(used_fallback) = used_fallback {
            event.insert("used_fallback".into(), json!(used_fallback));
        }
        self.coord_monitor_insert_coords(&mut event, "origin_coords", &request.origin_coords);
        event.insert(
            "identities".into(),
            self.coord_monitor_collect_identities(&referenced, Some(&request.origin_coords)),
        );
        self.coord_monitor_emit(event);
    }

    fn coord_monitor_lookup_response_event(
        &self,
        event_name: &str,
        from: Option<&NodeAddr>,
        to: Option<&NodeAddr>,
        response: &LookupResponse,
    ) {
        let observer = *self.node_addr();
        let mut referenced = vec![observer, response.target];
        if let Some(from) = from {
            referenced.push(*from);
        }
        if let Some(to) = to {
            referenced.push(*to);
        }

        let mut event = JsonMap::new();
        event.insert("event".into(), json!(event_name));
        event.insert(
            "observer".into(),
            json!(self.coord_monitor_node_addr(&observer)),
        );
        if let Some(from) = from {
            event.insert("from".into(), json!(self.coord_monitor_node_addr(from)));
        }
        if let Some(to) = to {
            event.insert("to".into(), json!(self.coord_monitor_node_addr(to)));
        }
        event.insert("request_id".into(), json!(response.request_id));
        event.insert(
            "target".into(),
            json!(self.coord_monitor_node_addr(&response.target)),
        );
        event.insert("path_mtu".into(), json!(response.path_mtu));
        self.coord_monitor_insert_coords(&mut event, "target_coords", &response.target_coords);
        event.insert(
            "identities".into(),
            self.coord_monitor_collect_identities(&referenced, Some(&response.target_coords)),
        );
        self.coord_monitor_emit(event);
    }

    pub(crate) fn coord_monitor_lookup_request_received(
        &self,
        from: &NodeAddr,
        request: &LookupRequest,
    ) {
        self.coord_monitor_lookup_request_event(
            "lookup_request_received",
            Some(from),
            None,
            request,
            None,
        );
    }

    pub(crate) fn coord_monitor_lookup_request_sent(&self, to: &NodeAddr, request: &LookupRequest) {
        self.coord_monitor_lookup_request_event(
            "lookup_request_sent",
            None,
            Some(to),
            request,
            None,
        );
    }

    pub(crate) fn coord_monitor_lookup_request_forwarded(
        &self,
        from: &NodeAddr,
        to: &NodeAddr,
        request: &LookupRequest,
        used_fallback: bool,
    ) {
        self.coord_monitor_lookup_request_event(
            "lookup_request_forwarded",
            Some(from),
            Some(to),
            request,
            Some(used_fallback),
        );
    }

    pub(crate) fn coord_monitor_lookup_response_received(
        &self,
        from: &NodeAddr,
        response: &LookupResponse,
    ) {
        self.coord_monitor_lookup_response_event(
            "lookup_response_received",
            Some(from),
            None,
            response,
        );
    }

    pub(crate) fn coord_monitor_lookup_response_sent(
        &self,
        to: &NodeAddr,
        response: &LookupResponse,
    ) {
        self.coord_monitor_lookup_response_event("lookup_response_sent", None, Some(to), response);
    }

    pub(crate) fn coord_monitor_lookup_response_forwarded(
        &self,
        from: &NodeAddr,
        to: &NodeAddr,
        response: &LookupResponse,
    ) {
        self.coord_monitor_lookup_response_event(
            "lookup_response_forwarded",
            Some(from),
            Some(to),
            response,
        );
    }

    pub(crate) fn coord_monitor_tree_announce_received(
        &self,
        from: &NodeAddr,
        announce: &TreeAnnounce,
    ) {
        let observer = *self.node_addr();
        let sender = *announce.declaration.node_addr();
        let parent = *announce.declaration.parent_id();
        let mut event = JsonMap::new();

        event.insert("event".into(), json!("tree_announce_received"));
        event.insert(
            "observer".into(),
            json!(self.coord_monitor_node_addr(&observer)),
        );
        event.insert("from".into(), json!(self.coord_monitor_node_addr(from)));
        event.insert(
            "sender".into(),
            json!(self.coord_monitor_node_addr(&sender)),
        );
        event.insert(
            "declared_parent".into(),
            json!(self.coord_monitor_node_addr(&parent)),
        );
        event.insert(
            "declaration_sequence".into(),
            json!(announce.declaration.sequence()),
        );
        event.insert(
            "declaration_timestamp".into(),
            json!(announce.declaration.timestamp()),
        );
        self.coord_monitor_insert_coords(&mut event, "announced_ancestry", &announce.ancestry);
        self.coord_monitor_insert_coord_entry_meta(&mut event, &announce.ancestry);
        event.insert(
            "identities".into(),
            self.coord_monitor_collect_identities(
                &[observer, *from, sender, parent],
                Some(&announce.ancestry),
            ),
        );
        self.coord_monitor_emit(event);
    }

    pub(crate) fn coord_monitor_tree_announce_rejected(
        &self,
        from: &NodeAddr,
        announce: &TreeAnnounce,
        reason: &str,
    ) {
        let observer = *self.node_addr();
        let sender = *announce.declaration.node_addr();
        let parent = *announce.declaration.parent_id();
        let mut event = JsonMap::new();

        event.insert("event".into(), json!("tree_announce_rejected"));
        event.insert(
            "observer".into(),
            json!(self.coord_monitor_node_addr(&observer)),
        );
        event.insert("from".into(), json!(self.coord_monitor_node_addr(from)));
        event.insert(
            "sender".into(),
            json!(self.coord_monitor_node_addr(&sender)),
        );
        event.insert(
            "declared_parent".into(),
            json!(self.coord_monitor_node_addr(&parent)),
        );
        event.insert(
            "declaration_sequence".into(),
            json!(announce.declaration.sequence()),
        );
        event.insert(
            "declaration_timestamp".into(),
            json!(announce.declaration.timestamp()),
        );
        event.insert("reason".into(), json!(reason));
        self.coord_monitor_insert_coords(&mut event, "announced_ancestry", &announce.ancestry);
        self.coord_monitor_insert_coord_entry_meta(&mut event, &announce.ancestry);
        event.insert(
            "identities".into(),
            self.coord_monitor_collect_identities(
                &[observer, *from, sender, parent],
                Some(&announce.ancestry),
            ),
        );
        self.coord_monitor_emit(event);
    }

    pub(crate) fn coord_monitor_tree_announce_accepted(
        &self,
        from: &NodeAddr,
        announce: &TreeAnnounce,
    ) {
        let observer = *self.node_addr();
        let sender = *announce.declaration.node_addr();
        let parent = *announce.declaration.parent_id();
        let mut event = JsonMap::new();

        event.insert("event".into(), json!("tree_announce_accepted"));
        event.insert(
            "observer".into(),
            json!(self.coord_monitor_node_addr(&observer)),
        );
        event.insert("from".into(), json!(self.coord_monitor_node_addr(from)));
        event.insert(
            "sender".into(),
            json!(self.coord_monitor_node_addr(&sender)),
        );
        event.insert(
            "declared_parent".into(),
            json!(self.coord_monitor_node_addr(&parent)),
        );
        event.insert(
            "declaration_sequence".into(),
            json!(announce.declaration.sequence()),
        );
        event.insert(
            "declaration_timestamp".into(),
            json!(announce.declaration.timestamp()),
        );
        self.coord_monitor_insert_coords(&mut event, "announced_ancestry", &announce.ancestry);
        self.coord_monitor_insert_coord_entry_meta(&mut event, &announce.ancestry);
        event.insert(
            "identities".into(),
            self.coord_monitor_collect_identities(
                &[observer, *from, sender, parent],
                Some(&announce.ancestry),
            ),
        );
        self.coord_monitor_emit(event);
    }

    pub(crate) fn coord_monitor_local_tree_snapshot(&self, reason: &str) {
        let tree = self.tree_state();
        let observer = *self.node_addr();
        let parent = *tree.my_coords().parent_id();
        let mut event = JsonMap::new();

        event.insert("event".into(), json!("local_tree_snapshot"));
        event.insert("reason".into(), json!(reason));
        event.insert(
            "observer".into(),
            json!(self.coord_monitor_node_addr(&observer)),
        );
        event.insert(
            "parent".into(),
            json!(self.coord_monitor_node_addr(&parent)),
        );
        event.insert(
            "declaration_sequence".into(),
            json!(tree.my_declaration().sequence()),
        );
        self.coord_monitor_insert_coords(&mut event, "local_tree", tree.my_coords());
        self.coord_monitor_insert_coord_entry_meta(&mut event, tree.my_coords());
        event.insert(
            "identities".into(),
            self.coord_monitor_collect_identities(&[observer, parent], Some(tree.my_coords())),
        );
        self.coord_monitor_emit(event);
    }
}
