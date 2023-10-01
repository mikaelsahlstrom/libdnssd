use std::thread;
use std::sync::mpsc::{ Receiver, channel };
use std::time::Duration;

pub struct ThreadWithTimeout<T>
{
    handle: thread::JoinHandle<T>,
    signal: Receiver<()>
}

impl<T> ThreadWithTimeout<T>
{
    pub fn join(self, timeout: Duration) -> Result<T, Self>
    {
        if let Err(_) = self.signal.recv_timeout(timeout)
        {
            return Err(self);
        }

        Ok(self.handle.join().unwrap())
    }
}

pub fn spawn_with_timeout<T: Send + 'static, F: FnOnce() -> T + Send + 'static>(f: F) -> ThreadWithTimeout<T>
{
    let (send, recv) = channel();
    let t = thread::spawn(move ||
    {
        let x = f();
        send.send(()).unwrap();
        x
    });

    ThreadWithTimeout
    {
        handle: t,
        signal: recv
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_threadtimeout()
    {
        let start = Instant::now();
        let handle = spawn_with_timeout(|| -> u32
        {
            thread::sleep(Duration::from_secs(2));
            42
        });

        let result = handle.join(Duration::from_secs(1));
        assert!(result.is_err());
        assert!(start.elapsed().as_secs() < 2);
    }
}
