//! Builds incremental packet-filter indexes for browser paging.
//! Row storage stays in `store`; field explanations stay in `explain`.
//! Read `State::packets` for strict query validation and reusable cursors.
//! Display filters hide captured packets without changing capture or logs.

use super::{engine::failure, records, state::State};
use crate::{
    explain::web as words,
    filter::{self, Filter},
    flow::FlowId,
    log::{Json, JsonValue as V},
    pipeline::AppLabel,
    web::ApiReply,
};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

// Four full indexes bound memory to four times the retained packet-count cap.
const CACHE_COUNT: usize = 4;
const MATCH_SLICE: Duration = Duration::from_millis(8);
/// One filter's bounded, ordered packet numbers and completed matching cursor.
pub(super) struct Cache {
    text: String,
    filter: Filter,
    cursor: u64,
    ids: VecDeque<u64>,
    revision: u64,
    owners: HashMap<FlowId, Option<String>>,
    #[cfg(test)]
    /// Number of rows evaluated; compiled only for cursor-reuse assertions.
    pub(super) evaluated: u64,
}
impl Cache {
    /// Detects a late owner that invalidates historical app-filter matches.
    pub fn owner_changed(&self, id: FlowId, owner: Option<&AppLabel>) -> bool {
        self.owners
            .get(&id)
            .is_some_and(|old| old.as_deref() != owner.map(|a| a.name.as_str()))
    }
}
struct Page {
    after: Option<u64>,
    before: Option<u64>,
    limit: usize,
    filter: String,
}
fn page(query: &[(String, String)]) -> Result<Page, (u16, &'static str)> {
    records::keys(query, &["after", "before", "limit", "filter"])?;
    let after = records::number(query, "after")?;
    let before = records::number(query, "before")?;
    if after.is_some() && before.is_some() {
        return Err((400, words::error(400)));
    }
    let limit = records::number(query, "limit")?.unwrap_or(200);
    if limit == 0 || limit > 500 {
        return Err((400, words::error(400)));
    }
    Ok(Page {
        after,
        before,
        limit: limit as usize,
        filter: query
            .iter()
            .find(|(k, _)| k == "filter")
            .map(|(_, v)| v.clone())
            .unwrap_or_default(),
    })
}
impl State {
    /// Pages one cached filter; None requests another bounded matching slice.
    pub fn packets(&mut self, query: &[(String, String)]) -> Option<ApiReply> {
        let page = match page(query) {
            Ok(page) => page,
            Err((s, m)) => return Some(failure(s, m)),
        };
        let filter = match filter::parse(&page.filter) {
            Ok(filter) => filter,
            Err(error) => {
                return Some(ApiReply {
                    status: 200,
                    json: Json::object()
                        .num("total", self.visible_total())
                        .num("matched", 0)
                        .value(
                            "filter_error",
                            Json::object()
                                .num("position", error.position as u64)
                                .str("message", &error.message)
                                .into_value(),
                        )
                        .value("rows", V::array([]))
                        .finish(),
                });
            }
        };
        let index = self.caches.iter().position(|c| c.text == page.filter);
        let mut cache = index
            .and_then(|i| self.caches.remove(i))
            .unwrap_or_else(|| Cache {
                text: page.filter,
                filter,
                cursor: 0,
                ids: VecDeque::new(),
                revision: self.app_revision,
                owners: HashMap::new(),
                #[cfg(test)]
                evaluated: 0,
            });
        if cache.revision != self.app_revision {
            cache.ids.clear();
            cache.owners.clear();
            cache.cursor = 0;
            cache.revision = self.app_revision;
        }
        let done = self.extend(&mut cache);
        let reply = done.then(|| {
            let begin = if let Some(before) = page.before {
                cache
                    .ids
                    .partition_point(|id| *id < before)
                    .saturating_sub(page.limit)
            } else {
                cache
                    .ids
                    .partition_point(|id| *id <= page.after.unwrap_or(0))
            };
            let rows = cache
                .ids
                .iter()
                .skip(begin)
                .take(page.limit)
                .take_while(|id| page.before.is_none_or(|before| **id < before))
                .filter_map(|id| self.store.get(*id))
                .map(|e| super::packet::row(self, e));
            ApiReply {
                status: 200,
                json: Json::object()
                    .num("total", self.visible_total())
                    .num("matched", cache.ids.len() as u64)
                    .value("filter_error", V::null())
                    .value("rows", V::array(rows))
                    .finish(),
            }
        });
        if self.caches.len() == CACHE_COUNT {
            self.caches.pop_front();
        }
        self.caches.push_back(cache);
        reply
    }
    fn extend(&self, cache: &mut Cache) -> bool {
        let first = self
            .store
            .entries
            .front()
            .map_or(self.last_number.saturating_add(1), |e| e.row.number);
        while cache.ids.front().is_some_and(|id| *id < first) {
            cache.ids.pop_front();
        }
        // The owner map is bounded by retained tracker IDs. Clear stale owners
        // on eviction rather than letting past FlowIds accumulate with traffic.
        cache
            .owners
            .retain(|id, _| self.pipeline.tracker().flow(*id).is_some());
        let cutoff = self.cutoff();
        let start = Instant::now();
        let offset = self
            .store
            .entries
            .partition_point(|e| e.row.number <= cache.cursor);
        let mut done = true;
        for entry in self
            .store
            .entries
            .iter()
            .skip(offset)
            .take_while(|e| e.row.number <= cutoff)
        {
            if start.elapsed() >= MATCH_SLICE {
                done = false;
                break;
            }
            #[cfg(test)]
            {
                cache.evaluated += 1;
            }
            let row = &entry.row;
            let owner = row.flow.and_then(|id| self.app(id));
            if let Some(id) = row.flow {
                cache.owners.insert(id, owner.map(|a| a.name.clone()));
            }
            if cache.filter.matches(&filter::Row {
                summary: &row.summary,
                sentence: &row.sentence,
                src_name: Some(&row.src_label),
                dst_name: Some(&row.dst_label),
                app: owner.map(|a| a.name.as_str()),
                problem: row.problem,
            }) {
                cache.ids.push_back(row.number);
            }
            cache.cursor = row.number;
        }
        done
    }
    fn visible_total(&self) -> u64 {
        self.paused.as_ref().map_or(self.total, |p| p.total)
    }
}
