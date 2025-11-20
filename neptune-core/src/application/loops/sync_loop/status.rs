use std::fmt::Display;

#[derive(Debug, Clone, Copy)]
pub struct Status {
    num_blocks_downloaded: u64,
    total_span: u64,
}

impl Status {
    pub(crate) fn new(span: u64) -> Self {
        Self {
            num_blocks_downloaded: 0,
            total_span: span,
        }
    }

    pub(crate) fn with_num_blocks_downloaded(mut self, num_blocks: u64) -> Self {
        self.num_blocks_downloaded = num_blocks;
        assert!(
            self.num_blocks_downloaded <= self.total_span,
            "num blocks downloaded {} > total span {}",
            self.num_blocks_downloaded,
            self.total_span
        );
        self
    }

    pub(crate) fn as_fraction(&self) -> f64 {
        (self.num_blocks_downloaded as f64) / (self.total_span as f64)
    }

    pub(crate) fn as_percentage(&self) -> f64 {
        let fraction = self.as_fraction();
        assert!(
            fraction <= 1.0,
            "fraction was {fraction} but should be <= 1.0"
        );
        100.0_f64 * fraction
    }
}

impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.2}%", self.as_percentage())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest::prop_assume;
    use test_strategy::proptest;

    #[proptest]
    fn can_display(num_blocks_downloaded: u64, total_span: u64) {
        prop_assume!(total_span >= num_blocks_downloaded);
        let status = Status {
            num_blocks_downloaded,
            total_span,
        };
        println!("{status}"); // no crash
    }

    #[proptest]
    fn fraction_can_never_be_larger_than_1(num_blocks_downloaded: u64, total_span: u64) {
        prop_assume!(total_span >= num_blocks_downloaded);
        let status = Status::new(total_span).with_num_blocks_downloaded(num_blocks_downloaded);
        prop_assert!(status.as_fraction() <= 1.0);
    }

    #[proptest]
    fn initial_fraction_is_zero(total_span: u64) {
        let status = Status::new(total_span);
        prop_assert_eq!(0.0f64, status.as_fraction());
    }
}
