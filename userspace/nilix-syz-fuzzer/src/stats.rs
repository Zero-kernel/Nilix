use std::time::{Duration, Instant};

pub struct FuzzStats {
    pub iterations: u64,
    pub successes: u64,
    pub crashes: u64,
    pub timeouts: u64,
    pub hangs: u64,
    pub errors: u64,
    pub new_coverage: u64,
    start_time: Instant,
    last_report: Instant,
}

impl FuzzStats {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            iterations: 0,
            successes: 0,
            crashes: 0,
            timeouts: 0,
            hangs: 0,
            errors: 0,
            new_coverage: 0,
            start_time: now,
            last_report: now,
        }
    }

    pub fn print_progress(&mut self) {
        let elapsed = self.start_time.elapsed();
        let exec_per_sec = self.iterations as f64 / elapsed.as_secs_f64();

        println!(
            "[{:>6}s] iters={:<8} exec/s={:<6.1} crashes={:<4} errors={:<4} new_cov={:<6} success={:<6} timeout={:<4}",
            elapsed.as_secs(),
            self.iterations,
            exec_per_sec,
            self.crashes,
            self.errors,
            self.new_coverage,
            self.successes,
            self.timeouts
        );

        self.last_report = Instant::now();
    }

    pub fn print_final(&self) {
        let elapsed = self.start_time.elapsed();
        println!("Total iterations: {}", self.iterations);
        println!("Successes:        {}", self.successes);
        println!("Crashes:          {}", self.crashes);
        println!("Timeouts:         {}", self.timeouts);
        println!("Hangs:            {}", self.hangs);
        println!("Errors:           {}", self.errors);
        println!("New coverage:     {}", self.new_coverage);
        println!("Elapsed time:     {}s", elapsed.as_secs());
        println!(
            "Exec/sec:         {:.1}",
            self.iterations as f64 / elapsed.as_secs_f64()
        );
    }

    pub fn should_report(&self) -> bool {
        self.last_report.elapsed() > Duration::from_secs(5)
    }
}

impl Default for FuzzStats {
    fn default() -> Self {
        Self::new()
    }
}
