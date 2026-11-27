use crate::runtime::time::{TimerHandle, TimerShared};
use crate::time::error::InsertError;
use crate::util::linked_list::LinkedList;

mod level;
pub(crate) use self::level::Expiration;
use self::level::Level;

use std::ptr::NonNull;

use super::entry::{tick_of, NANOS_PER_TICK, REGISTERED_HELD, STATE_DEREGISTERED};

/// Timing wheel implementation.
///
/// This type provides the hashed timing wheel implementation that backs
/// [`Driver`].
///
/// See [`Driver`] documentation for some implementation notes.
///
/// [`Driver`]: crate::runtime::time::Driver
#[derive(Debug)]
pub(crate) struct Wheel {
    /// The number of milliseconds elapsed since the wheel started.
    elapsed: u64,

    /// Timer wheel.
    ///
    /// Levels:
    ///
    /// * 1 ms slots / 64 ms range
    /// * 64 ms slots / ~ 4 sec range
    /// * ~ 4 sec slots / ~ 4 min range
    /// * ~ 4 min slots / ~ 4 hr range
    /// * ~ 4 hr slots / ~ 12 day range
    /// * ~ 12 day slots / ~ 2 yr range
    levels: Box<[Level; NUM_LEVELS]>,

    /// Entries queued for firing
    pending: LinkedList<TimerShared>,

    // Concord: the clock reading, in nanoseconds, that the wheel last processed up to.
    elapsed_nanos: u64,

    // Concord: entries whose millisecond the wheel has processed but whose deadline lies later in it. The
    // levels cannot hold them: `next_occupied_slot` skips the slot holding `elapsed`.
    held: LinkedList<TimerShared>,
}

/// Number of levels. Each level has 64 slots. By using 6 levels with 64 slots
/// each, the timer is able to track time up to 2 years into the future with a
/// precision of 1 millisecond.
const NUM_LEVELS: usize = 6;

const BITS_PER_LEVEL: usize = 6;

/// The maximum duration of a `Sleep`.
const MAX_DURATION: u64 = 1 << (BITS_PER_LEVEL * NUM_LEVELS);

impl Wheel {
    /// Creates a new timing wheel.
    pub(crate) fn new() -> Wheel {
        let levels = (0..NUM_LEVELS).map(Level::new).collect::<Box<_>>();
        Wheel {
            elapsed: 0,
            levels: levels.try_into().unwrap(),
            pending: LinkedList::new(),
            elapsed_nanos: 0,
            held: LinkedList::new(),
        }
    }

    pub(crate) fn elapsed_nanos(&self) -> u64 {
        self.elapsed_nanos
    }

    /// Inserts an entry into the timing wheel.
    ///
    /// # Arguments
    ///
    /// * `item`: The item to insert into the wheel.
    ///
    /// # Return
    ///
    /// Returns `Ok` when the item is successfully inserted, `Err` otherwise.
    ///
    /// `Err(Elapsed)` indicates that `when` represents an instant that has
    /// already passed. In this case, the caller should fire the timeout
    /// immediately.
    ///
    /// # Safety
    ///
    /// This function registers item into an intrusive linked list. The caller
    /// must ensure that `item` is pinned and will not be dropped without first
    /// being deregistered.
    pub(crate) unsafe fn insert(
        &mut self,
        item: TimerHandle,
    ) -> Result<u64, (TimerHandle, InsertError)> {
        let when = unsafe { item.sync_when() };

        if when <= self.elapsed_nanos {
            return Err((item, InsertError::Elapsed));
        }

        let tick = tick_of(when);
        if tick <= self.elapsed {
            unsafe { self.hold(item) };
            return Ok(when);
        }

        // Get the level at which the entry should be stored
        let level = self.level_for(tick);

        unsafe {
            self.levels[level].add_entry(item);
        }

        debug_assert!({
            self.levels[level]
                .next_expiration(self.elapsed)
                .is_none_or(|e| e.deadline >= self.elapsed)
        });

        Ok(when)
    }

    /// Removes `item` from the timing wheel.
    pub(crate) unsafe fn remove(&mut self, item: NonNull<TimerShared>) {
        unsafe {
            let when = item.as_ref().registered_when();
            if when == STATE_DEREGISTERED {
                self.pending.remove(item);
            } else if when == REGISTERED_HELD {
                self.held.remove(item);
            } else {
                debug_assert!(
                    self.elapsed <= when,
                    "elapsed={}; when={}",
                    self.elapsed,
                    when
                );

                let level = self.level_for(when);
                self.levels[level].remove_entry(item);
            }
        }
    }

    // Concord: the nanosecond at which the driver must next process the wheel: the earliest deadline in the
    // held list or in the next level-0 slot, or the start of the next higher-level slot to cascade. An entry
    // reset past its level-0 slot counts at the slot's end, when processing the slot moves it.
    pub(crate) fn next_wake_nanos(&self) -> Option<u64> {
        if !self.pending.is_empty() {
            return Some(self.elapsed_nanos);
        }

        let slot = self.next_expiration().map(|expiration| {
            let start = expiration.deadline.saturating_mul(NANOS_PER_TICK);
            if expiration.level > 0 {
                return start;
            }
            let end = start.saturating_add(NANOS_PER_TICK);
            Self::earliest(self.levels[0].slot_list(expiration.slot)).map_or(end, |when| when.clamp(start, end))
        });

        match (Self::earliest(&self.held), slot) {
            (Some(held), Some(slot)) => Some(held.min(slot)),
            (held, slot) => held.or(slot),
        }
    }

    fn earliest(list: &LinkedList<TimerShared>) -> Option<u64> {
        list.targets()
            .map(|entry| unsafe { entry.as_ref().true_when() })
            .min()
    }

    unsafe fn hold(&mut self, item: TimerHandle) {
        unsafe { item.set_held() };
        self.held.push_front(item);
    }

    /// Advances the timer up to the clock reading `now_nanos`.
    pub(crate) fn poll(&mut self, now_nanos: u64) -> Option<TimerHandle> {
        let now = if now_nanos == u64::MAX {
            u64::MAX
        } else {
            tick_of(now_nanos)
        };

        loop {
            if let Some(handle) = self.pending.pop_back() {
                return Some(handle);
            }

            match self.next_expiration() {
                Some(ref expiration) if expiration.deadline <= now => {
                    self.process_expiration(expiration, now_nanos);

                    // During shutdown (`now == u64::MAX`), slots are drained
                    // directly without cascading entries across levels. Keep
                    // `self.elapsed` unchanged until all slots are empty so
                    // `level_for` remains valid if the lock is temporarily
                    // dropped to wake a batch of wakers.
                    if now != u64::MAX {
                        self.set_elapsed(expiration.deadline);
                    }
                }
                _ => {
                    // in this case the poll did not indicate an expiration
                    // _and_ we were not able to find a next expiration in
                    // the current list of timers.  advance to the poll's
                    // current time and do nothing else.
                    self.set_elapsed(now);
                    break;
                }
            }
        }

        if self.elapsed_nanos < now_nanos {
            self.elapsed_nanos = now_nanos;
        }
        self.process_held(now_nanos);

        self.pending.pop_back()
    }

    fn process_entry(&mut self, item: TimerHandle, now_nanos: u64, base_tick: u64) {
        match unsafe { item.mark_pending(now_nanos) } {
            Ok(()) => self.pending.push_front(item),
            Err(when) if tick_of(when) <= base_tick => unsafe { self.hold(item) },
            Err(when) => {
                let level = level_for(base_tick, tick_of(when));
                unsafe { self.levels[level].add_entry(item) };
            }
        }
    }

    fn process_held(&mut self, now_nanos: u64) {
        let mut held = std::mem::take(&mut self.held);
        while let Some(item) = held.pop_back() {
            self.process_entry(item, now_nanos, self.elapsed);
        }
    }

    /// Returns the instant at which the next timeout expires.
    fn next_expiration(&self) -> Option<Expiration> {
        if !self.pending.is_empty() {
            // Expire immediately as we have things pending firing
            return Some(Expiration {
                level: 0,
                slot: 0,
                deadline: self.elapsed,
            });
        }

        // Check all levels
        for (level_num, level) in self.levels.iter().enumerate() {
            if let Some(expiration) = level.next_expiration(self.elapsed) {
                // There cannot be any expirations at a higher level that happen
                // before this one.
                debug_assert!(self.no_expirations_before(level_num + 1, expiration.deadline));

                return Some(expiration);
            }
        }

        None
    }

    /// Used for debug assertions
    fn no_expirations_before(&self, start_level: usize, before: u64) -> bool {
        let mut res = true;

        for level in &self.levels[start_level..] {
            if let Some(e2) = level.next_expiration(self.elapsed) {
                if e2.deadline < before {
                    res = false;
                }
            }
        }

        res
    }

    /// iteratively find entries that are between the wheel's current
    /// time and the expiration time.  for each in that population either
    /// queue it for notification (in the case of the last level) or tier
    /// it down to the next level (in all other cases).
    pub(crate) fn process_expiration(&mut self, expiration: &Expiration, now_nanos: u64) {
        // Note that we need to take _all_ of the entries off the list before
        // processing any of them. This is important because it's possible that
        // those entries might need to be reinserted into the same slot.
        //
        // This happens only on the highest level, when an entry is inserted
        // more than MAX_DURATION into the future. When this happens, we wrap
        // around, and process some entries a multiple of MAX_DURATION before
        // they actually need to be dropped down a level. We then reinsert them
        // back into the same position; we must make sure we don't then process
        // those entries again or we'll end up in an infinite loop.
        let mut entries = self.take_entries(expiration);

        while let Some(item) = entries.pop_back() {
            if expiration.level == 0 && now_nanos != u64::MAX {
                debug_assert_eq!(unsafe { item.registered_when() }, expiration.deadline);
            }

            // Try to expire the entry; this is cheap (doesn't synchronize) if
            // the timer is not expired, and updates registered_when.
            self.process_entry(item, now_nanos, expiration.deadline);
        }
    }

    fn set_elapsed(&mut self, when: u64) {
        assert!(
            self.elapsed <= when,
            "elapsed={:?}; when={:?}",
            self.elapsed,
            when
        );

        if when > self.elapsed {
            self.elapsed = when;
        }
    }

    /// Obtains the list of entries that need processing for the given expiration.
    fn take_entries(&mut self, expiration: &Expiration) -> LinkedList<TimerShared> {
        self.levels[expiration.level].take_slot(expiration.slot)
    }

    fn level_for(&self, when: u64) -> usize {
        level_for(self.elapsed, when)
    }
}

fn level_for(elapsed: u64, when: u64) -> usize {
    const SLOT_MASK: u64 = (1 << BITS_PER_LEVEL) - 1;

    // Mask in the trailing bits ignored by the level calculation in order to cap
    // the possible leading zeros
    let masked = elapsed ^ when | SLOT_MASK;

    if masked >= MAX_DURATION {
        // Fudge the timer into the top level
        return NUM_LEVELS - 1;
    }

    masked.ilog2() as usize / BITS_PER_LEVEL
}

#[cfg(all(test, not(loom)))]
mod test {
    use std::pin::Pin;

    use super::*;

    #[test]
    fn test_level_for() {
        for pos in 0..64 {
            assert_eq!(0, level_for(0, pos), "level_for({pos}) -- binary = {pos:b}");
        }

        for level in 1..5 {
            for pos in level..64 {
                let a = pos * 64_usize.pow(level as u32);
                assert_eq!(
                    level,
                    level_for(0, a as u64),
                    "level_for({a}) -- binary = {a:b}"
                );

                if pos > level {
                    let a = a - 1;
                    assert_eq!(
                        level,
                        level_for(0, a as u64),
                        "level_for({a}) -- binary = {a:b}"
                    );
                }

                if pos < 64 {
                    let a = a + 1;
                    assert_eq!(
                        level,
                        level_for(0, a as u64),
                        "level_for({a}) -- binary = {a:b}"
                    );
                }
            }
        }
    }

    fn ms(n: u64) -> u64 {
        n * NANOS_PER_TICK
    }

    #[must_use]
    fn insert_entry(wheel: &mut Wheel, when: u64) -> Pin<Box<TimerShared>> {
        let entry = Box::pin(TimerShared::new());

        unsafe { entry.set_expiration(when) };

        unsafe { wheel.insert(entry.as_ref().handle()).unwrap() };

        entry
    }

    #[test]
    fn test_next_expiration_to_level_4() {
        let wheel = &mut Wheel::new();

        // that should occupy slot 1 of the level 4 of the wheel
        let when = ms((1 << 24) + 10);

        let _entry = insert_entry(wheel, when);

        let expiration = wheel.next_wake_nanos();
        // next expiration should be calculated as the start of the level 4 range
        assert_eq!(expiration, Some(ms(1 << 24)));

        // set the elapsed to the start of the previous expiration
        wheel.poll(ms(1 << 24));

        let expiration = wheel.next_wake_nanos();
        // that should be equal of the LEVEL_WHEN which is 10 ms after previous expiration
        assert_eq!(expiration, Some(when));

        wheel.poll(when);

        assert!(wheel.next_expiration().is_none());
    }

    #[test]
    fn test_next_expiration_to_level_5() {
        let wheel = &mut Wheel::new();

        // that will occupy slot 1 of the level 5 of the wheel
        let when = ms((1 << 30) + 10);
        let _entry = insert_entry(wheel, when);

        let expiration = wheel.next_wake_nanos();

        assert_eq!(expiration, Some(ms(1 << 30)));

        // set the elapsed to the start of the previous expiration
        wheel.poll(ms(1 << 30));

        let expiration = wheel.next_wake_nanos();

        assert_eq!(expiration, Some(ms((1 << 30) + 10)));

        wheel.poll(when);

        assert!(wheel.next_expiration().is_none());
    }

    #[test]
    fn test_next_expiration_after_level_5() {
        let wheel = &mut Wheel::new();

        // that will occupy slot 0 of the level 5 of the wheel
        let when = ms((1 << 36) + 5);
        let _entry = insert_entry(wheel, when);

        let expiration = wheel.next_wake_nanos();

        // that should come after the wheel
        assert_eq!(expiration, Some(ms(1 << 36)));

        // set the elapsed to the start of the previous expiration
        wheel.poll(ms(1 << 36));

        let expiration = wheel.next_wake_nanos();

        assert_eq!(expiration, Some(when));

        wheel.poll(when);

        assert!(wheel.next_wake_nanos().is_none());
    }

    #[test]
    fn test_next_expiration_after_level_5_twice() {
        let wheel = &mut Wheel::new();

        // that will occupy slot 0 of the level 5 of the wheel
        let when = ms((1 << 37) + 5);
        let _entry = insert_entry(wheel, when);

        let expiration = wheel.next_wake_nanos();

        // that should come after the wheel
        assert_eq!(expiration, Some(ms(1 << 36)));

        // set the elapsed to the start of the previous expiration
        wheel.poll(ms(1 << 36));

        let expiration = wheel.next_wake_nanos();

        assert_eq!(expiration, Some(ms(1 << 37)));

        wheel.poll(ms(1 << 37));

        let expiration = wheel.next_wake_nanos();

        assert_eq!(expiration, Some(when));

        wheel.poll(when);

        assert!(wheel.next_wake_nanos().is_none());
    }

    #[test]
    fn test_next_expiration_to_level_5_and_after_level_5() {
        let wheel = &mut Wheel::new();

        // that will occupy slot 0 of the level 5 of the wheel
        let when = ms((1 << 36) + 1);
        let _entry = insert_entry(wheel, when);

        // that will occupy slot 1 of the level 5 of the wheel
        let when = ms((1 << 30) + 10);
        let _entry = insert_entry(wheel, when);

        let expiration = wheel.next_wake_nanos();

        // this should point to the expiration of the slot 1 entry
        // and not the slot 0 that is higher than 2^36
        assert_eq!(expiration, Some(ms(1 << 30)));

        // set the elapsed to the start of the previous expiration
        wheel.poll(ms(1 << 30));

        let expiration = wheel.next_wake_nanos();

        assert_eq!(expiration, Some(ms((1 << 30) + 10)));

        wheel.poll(when);

        let expiration = wheel.next_wake_nanos();

        // The next expiration show refer the next loop of top level
        assert_eq!(expiration, Some(ms(1 << 36)));
    }

    #[test]
    fn test_next_expiration_at_slot_5_of_the_top_level() {
        let wheel = &mut Wheel::new();

        // move the wheel into slot 5 of the top level
        wheel.poll(ms(5 << 30));

        // that will occupy slot 5 of the level 5 of the wheel, the same slot the
        // elapsed time sits in, so it is reachable only one rotation of the
        // level later
        let when = ms((1 << 36) + (5 << 30) + 1);
        let _entry = insert_entry(wheel, when);

        // that will occupy slot 20 of the level 5 of the wheel, still ahead in
        // the current rotation
        let when = ms((20 << 30) + 10);
        let _entry = insert_entry(wheel, when);

        let expiration = wheel.next_wake_nanos();

        // this should point to the start of the slot 20 and not to the slot 5
        // that comes around only after the whole level rotates
        assert_eq!(expiration, Some(ms(20 << 30)));
    }
}
