use std::fmt::Display;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Mul;
use std::ops::Sub;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

#[cfg(any(test, feature = "arbitrary-impls"))]
use arbitrary::Arbitrary;
use chrono::DateTime;
use chrono::Local;
use chrono::Utc;
use get_size2::GetSize;
use num_traits::Zero;
#[cfg(any(test, feature = "arbitrary-impls"))]
use proptest::strategy::BoxedStrategy;
#[cfg(any(test, feature = "arbitrary-impls"))]
use proptest::strategy::Strategy;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::TasmObject;
use tasm_lib::twenty_first::math::b_field_element::BFieldElement;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

/// Dedicated struct for timestamps (and durations). Counts the number of
/// milliseconds elapsed since the Unix epoch (00:00 UTC on 1 Jan 1970) using
/// a single BFieldElement.
#[derive(
    Debug,
    Clone,
    Copy,
    Hash,
    BFieldCodec,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    GetSize,
    Default,
    TasmObject,
)]
#[cfg_attr(any(test, feature = "arbitrary-impls"), derive(Arbitrary))]
pub struct Timestamp(pub BFieldElement);

impl From<Timestamp> for Duration {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.as_duration()
    }
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.value().cmp(&other.0.value())
    }
}

impl Zero for Timestamp {
    fn zero() -> Self {
        Timestamp(BFieldElement::new(0))
    }

    fn is_zero(&self) -> bool {
        self.0 == BFieldElement::new(0)
    }
}

impl Add for Timestamp {
    type Output = Timestamp;

    fn add(self, rhs: Self) -> Self::Output {
        Timestamp(self.0 + rhs.0)
    }
}

impl Sub for Timestamp {
    type Output = Timestamp;

    fn sub(self, rhs: Self) -> Self::Output {
        Timestamp(self.0 - rhs.0)
    }
}

impl AddAssign for Timestamp {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl Mul<usize> for Timestamp {
    type Output = Timestamp;

    /// Multiply the duration a number of times.
    ///
    /// # Panics
    ///
    /// Panics if there is overflow mod P = 2^64 - 2^32 + 1.
    fn mul(self, rhs: usize) -> Self::Output {
        let value: u128 = u128::from(self.0.value()) * (u128::try_from(rhs).unwrap());

        assert!(value < u128::from(BFieldElement::P));

        Self(BFieldElement::new(value as u64))
    }
}

impl Timestamp {
    pub fn now() -> Timestamp {
        Timestamp(BFieldElement::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        ))
    }

    pub const fn years(num: usize) -> Timestamp {
        Timestamp(BFieldElement::new((num as u64) * 365240 * 2 * 60 * 60 * 12))
    }

    pub const fn months(num: usize) -> Timestamp {
        Timestamp(BFieldElement::new((num as u64) * 365240 * 2 * 60 * 60))
    }

    pub const fn days(num: usize) -> Timestamp {
        Timestamp(BFieldElement::new((num as u64) * 24 * 60 * 60 * 1000))
    }

    pub const fn hours(num: usize) -> Timestamp {
        Timestamp(BFieldElement::new((num as u64) * 60 * 60 * 1000))
    }

    pub const fn minutes(num: usize) -> Timestamp {
        Timestamp(BFieldElement::new((num as u64) * 60 * 1000))
    }

    pub const fn seconds(num: u64) -> Timestamp {
        Timestamp(BFieldElement::new(num * 1000))
    }

    pub const fn millis(num: u64) -> Timestamp {
        Timestamp(BFieldElement::new(num))
    }

    pub const fn to_millis(&self) -> u64 {
        self.0.value()
    }

    pub fn format(&self, format_descriptor: &str) -> String {
        match DateTime::from_timestamp_millis(self.0.value() as i64) {
            Some(dt) => dt.format(format_descriptor).to_string(),
            None => "".to_string(),
        }
    }

    /// converts `Timestamp` to a [`Duration`]
    pub fn as_duration(&self) -> Duration {
        Duration::from_millis(self.to_millis())
    }

    /// Formats the `Timestamp` into a human-readable duration string.
    ///
    /// This method converts the `Timestamp` into its equivalent `std::time::Duration`
    /// and then breaks it down into weeks, days, hours, minutes, and seconds.
    /// The result is a string representing the duration, with units
    /// displayed only if their value is greater than zero (except for seconds,
    /// which is always shown), e.g., "1 week, 2 days, 3 hours", or "5 seconds".
    ///
    /// plural/singular forms are taken into account.
    ///
    /// sub-second values are not displayed.
    ///
    /// # Examples
    ///
    /// ```
    /// use neptune_cash::api::export::Timestamp;
    ///
    /// let timestamp = Timestamp::millis(1234567*1000);
    /// assert_eq!(timestamp.format_human_duration(), "2 weeks, 6 hours, 56 minutes, 7 seconds");
    ///
    /// let short_ts = Timestamp::millis(65*1000);
    /// assert_eq!(short_ts.format_human_duration(), "1 minute, 5 seconds");
    ///
    /// let zero_ts = Timestamp::millis(150);
    /// assert_eq!(zero_ts.format_human_duration(), "0 seconds");
    /// ```
    pub fn format_human_duration(&self) -> String {
        const SECS_IN_MINUTE: u64 = 60;
        const SECS_IN_HOUR: u64 = 60 * SECS_IN_MINUTE;
        const SECS_IN_DAY: u64 = 24 * SECS_IN_HOUR;
        const SECS_IN_WEEK: u64 = 7 * SECS_IN_DAY;

        let div_rem = |n: u64, d: u64| (n / d, n % d);

        let secs = self.as_duration().as_secs();
        let (weeks, secs) = div_rem(secs, SECS_IN_WEEK);
        let (days, secs) = div_rem(secs, SECS_IN_DAY);
        let (hours, secs) = div_rem(secs, SECS_IN_HOUR);
        let (mins, secs) = div_rem(secs, SECS_IN_MINUTE);

        let mut parts = Vec::new();
        let maybe_plural_s = |i: u64| if i == 1 { "" } else { "s" };

        if weeks > 0 {
            parts.push(format!("{weeks} week{}", maybe_plural_s(weeks)));
        }
        if days > 0 {
            parts.push(format!("{days} day{}", maybe_plural_s(days)));
        }
        if hours > 0 {
            parts.push(format!("{hours} hour{}", maybe_plural_s(hours)));
        }
        if mins > 0 {
            parts.push(format!("{mins} minute{}", maybe_plural_s(mins)));
        }
        if secs > 0 || parts.is_empty() {
            parts.push(format!("{secs} second{}", maybe_plural_s(secs)));
        }

        parts.join(", ")
    }

    pub fn standard_format(&self) -> String {
        let millis: i64 = self.0.value().try_into().unwrap_or(0);

        let Some(utc) = DateTime::<Utc>::from_timestamp_millis(millis) else {
            return "Too far into the future".to_string();
        };

        utc.with_timezone(&Local)
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false)
    }

    #[cfg(any(test, feature = "arbitrary-impls"))]
    pub fn arbitrary_between(start: Timestamp, stop: Timestamp) -> BoxedStrategy<Timestamp> {
        (start.0.value()..stop.0.value())
            .prop_map(|v| Timestamp(BFieldElement::new(v)))
            .boxed()
    }

    #[cfg(any(test, feature = "arbitrary-impls"))]
    pub fn arbitrary_after(reference: Timestamp) -> BoxedStrategy<Timestamp> {
        (reference.0.value()..BFieldElement::P)
            .prop_map(|v| Timestamp(BFieldElement::new(v)))
            .boxed()
    }
}

impl Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.value())
    }
}

impl Distribution<Timestamp> for StandardUniform {
    fn sample<R: rand::prelude::Rng + ?Sized>(&self, rng: &mut R) -> Timestamp {
        Timestamp(rng.random::<BFieldElement>())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::prelude::BFieldElement;
    use test_strategy::proptest;

    use crate::protocol::proof_abstractions::timestamp::Timestamp;

    #[test]
    fn print_now() {
        println!("{}", Timestamp::now());
    }

    #[test]
    fn std_format_cannot_panic_unit() {
        let _a = Timestamp(BFieldElement::new(0)).standard_format();
        let _b = Timestamp(BFieldElement::new(BFieldElement::MAX)).standard_format();
        let _c = Timestamp(BFieldElement::new(u64::MAX)).standard_format();
    }

    #[proptest]
    fn std_format_cannot_panic_prop(#[strategy(arb())] timestamp: Timestamp) {
        let _a = timestamp.standard_format();
    }

    #[test]
    fn format_cannot_panic_unit() {
        let fmt = "%Y-%m-%d %H:%M:%S";
        let _a = Timestamp(BFieldElement::new(0)).format(fmt);
        let _b = Timestamp(BFieldElement::new(BFieldElement::MAX)).format(fmt);
        let _c = Timestamp(BFieldElement::new(u64::MAX)).format(fmt);
    }

    #[proptest]
    fn format_cannot_panic_prop(#[strategy(arb())] timestamp: Timestamp) {
        let _a = timestamp.format("%Y-%m-%d %H:%M:%S");
    }

    #[test]
    fn year_is_sane() {
        assert_eq!(365240 * 60 * 60 * 24, Timestamp::years(1).to_millis());
        assert_eq!(5 * 365240 * 60 * 60 * 24, Timestamp::years(5).to_millis());
    }

    #[test]
    fn month_is_sane() {
        assert_eq!(365240 * 60 * 60 * 24 / 12, Timestamp::months(1).to_millis());
        assert_eq!(
            5 * 365240 * 60 * 60 * 24 / 12,
            Timestamp::months(5).to_millis()
        );
    }

    #[test]
    fn day_is_sane() {
        assert_eq!(1000 * 60 * 60 * 24, Timestamp::days(1).to_millis());
        assert_eq!(12 * 1000 * 60 * 60 * 24, Timestamp::days(12).to_millis());
    }

    #[test]
    fn hour_is_sane() {
        assert_eq!(1000 * 60 * 60, Timestamp::hours(1).to_millis());
        assert_eq!(6 * 1000 * 60 * 60, Timestamp::hours(6).to_millis());
    }

    #[test]
    fn minute_is_sane() {
        assert_eq!(1000 * 60, Timestamp::minutes(1).to_millis());
        assert_eq!(1915 * 1000 * 60, Timestamp::minutes(1915).to_millis());
    }

    #[test]
    fn second_is_sane() {
        assert_eq!(1000, Timestamp::seconds(1).to_millis());
        assert_eq!(59 * 1000, Timestamp::seconds(59).to_millis());
    }
}
