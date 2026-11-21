use std::future::Future;
use std::sync::{Arc, Mutex};

use crate::sync::lock;

type Trail = Option<Arc<Mutex<Vec<u64>>>>;

tokio::task_local! {
    static TRAIL: Trail;
}

/// Runs `task` and returns the ids of the DNS records that answered the lookups it made for
/// the connection, in the order they were noted and without repeats.
pub async fn traced<F: Future>(task: F) -> (F::Output, Vec<u64>) {
    let trail = Arc::new(Mutex::new(Vec::new()));
    let output = TRAIL.scope(Some(trail.clone()), task).await;
    let ids = std::mem::take(&mut *lock(&trail));
    (output, ids)
}

pub fn note_query(id: u64) {
    let _ = TRAIL.try_with(|trail| {
        if let Some(trail) = trail {
            let mut ids = lock(trail);
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    });
}

/// `task`, to be spawned, noting its queries on the caller's trail.
pub fn on_trail<F: Future>(task: F) -> impl Future<Output = F::Output> {
    TRAIL.scope(TRAIL.try_with(Clone::clone).ok().flatten(), task)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_trail_keeps_the_queries_noted_in_its_scope_and_in_tasks_carried_on_it() {
        note_query(1);
        let ((), ids) = traced(async {
            note_query(2);
            note_query(2);
            tokio::spawn(on_trail(async { note_query(3) }))
                .await
                .unwrap();
            tokio::spawn(async { note_query(4) }).await.unwrap();
        })
        .await;
        assert_eq!(ids, [2, 3]);
    }
}
