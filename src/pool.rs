//! A small scoped worker pool that hands results back in input order.

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;

/// Receives the results of [`run_ordered`] on the calling thread.
pub trait Sink<R> {
    /// Called whenever an item finishes, with the number finished so far.
    fn progress(&mut self, _finished: usize) {}

    /// Called once per item, in input order. An error stops the run.
    fn accept(&mut self, index: usize, result: R) -> io::Result<()>;
}

/// Applies `work` to every item on up to `threads` threads.
///
/// Results are delivered to `sink` in input order as soon as they and all
/// their predecessors are ready, so output can be streamed deterministically.
/// If the sink fails, workers finish the item they are on and stop.
pub fn run_ordered<T, R, W, S>(items: &[T], threads: usize, work: W, sink: &mut S) -> io::Result<()>
where
    T: Sync,
    R: Send,
    W: Fn(&T) -> R + Sync,
    S: Sink<R>,
{
    let threads = threads.min(items.len());
    if threads <= 1 {
        for (index, item) in items.iter().enumerate() {
            let result = work(item);
            sink.progress(index + 1);
            sink.accept(index, result)?;
        }
        return Ok(());
    }

    let cursor = AtomicUsize::new(0);
    let (sender, receiver) = mpsc::channel();

    thread::scope(|scope| {
        for _ in 0..threads {
            let sender = sender.clone();
            let (cursor, work) = (&cursor, &work);
            scope.spawn(move || {
                loop {
                    let index = cursor.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(index) else { break };
                    if sender.send((index, work(item))).is_err() {
                        break;
                    }
                }
            });
        }
        drop(sender);

        // Results arrive in completion order; park them until their turn.
        let mut parked = BTreeMap::new();
        let mut next = 0;
        for (finished, (index, result)) in receiver.into_iter().enumerate() {
            sink.progress(finished + 1);
            parked.insert(index, result);
            while let Some(result) = parked.remove(&next) {
                if let Err(err) = sink.accept(next, result) {
                    // Keep idle workers from picking up further items; busy
                    // ones notice the closed channel when they try to send.
                    cursor.store(items.len(), Ordering::Relaxed);
                    return Err(err);
                }
                next += 1;
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[derive(Default)]
    struct Collect {
        seen: Vec<(usize, u64)>,
        finished: usize,
        fail_at: Option<usize>,
    }

    impl Sink<u64> for Collect {
        fn progress(&mut self, finished: usize) {
            self.finished = finished;
        }

        fn accept(&mut self, index: usize, result: u64) -> io::Result<()> {
            if self.fail_at == Some(index) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.seen.push((index, result));
            Ok(())
        }
    }

    /// Later items finish first, so ordering has to come from the pool.
    fn slow_square(value: &u64) -> u64 {
        thread::sleep(Duration::from_millis(20u64.saturating_sub(*value)));
        value * value
    }

    #[test]
    fn delivers_results_in_input_order() {
        let items: Vec<u64> = (0..20).collect();
        for threads in [0, 1, 4, 64] {
            let mut sink = Collect::default();
            run_ordered(&items, threads, slow_square, &mut sink).unwrap();
            let expected: Vec<_> = items.iter().map(|&v| (v as usize, v * v)).collect();
            assert_eq!(sink.seen, expected, "threads = {threads}");
            assert_eq!(sink.finished, items.len());
        }
    }

    #[test]
    fn handles_empty_input() {
        let mut sink = Collect::default();
        run_ordered(&[], 8, slow_square, &mut sink).unwrap();
        assert!(sink.seen.is_empty());
    }

    #[test]
    fn stops_when_the_sink_fails() {
        let items: Vec<u64> = (0..200).collect();
        let mut sink = Collect {
            fail_at: Some(3),
            ..Collect::default()
        };
        let err = run_ordered(&items, 4, slow_square, &mut sink).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(sink.seen.len(), 3);
    }
}
