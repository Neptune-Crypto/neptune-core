use std::fmt::Display;
use std::ops::Add;
use std::ops::Sub;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use arbitrary::Arbitrary;
use chrono::DateTime;
use chrono::Local;
use chrono::NaiveDateTime;
use chrono::Utc;
use get_size::GetSize;
use num_traits::Zero;
use proptest::strategy::BoxedStrategy;
use proptest::strategy::Strategy;
use rand::distributions::Distribution;
use rand::distributions::Standard;
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
pub struct Timestamp(pub BFieldElement);

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

impl Timestamp {
    pub fn now() -> Timestamp {
        Timestamp(BFieldElement::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        ))
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

    pub fn format(&self, format_descriptor: &str) -> String {
        match DateTime::from_timestamp_millis(self.0.value() as i64) {
            Some(dt) => dt.format(format_descriptor).to_string(),
            None => "".to_string(),
        }
    }

    pub fn standard_format(&self) -> String {
        let naive =
            NaiveDateTime::from_timestamp_millis(self.0.value().try_into().unwrap_or(0)).unwrap();
        let utc: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, *Utc::now().offset());
        let offset: DateTime<Local> = DateTime::from(utc);
        offset.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false)
    }

    pub fn arbitrary_between(start: Timestamp, stop: Timestamp) -> BoxedStrategy<Timestamp> {
        (start.0.value()..stop.0.value())
            .prop_map(|v| Timestamp(BFieldElement::new(v)))
            .boxed()
    }
}

impl Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.value())
    }
}

impl Distribution<Timestamp> for Standard {
    fn sample<R: rand::prelude::Rng + ?Sized>(&self, rng: &mut R) -> Timestamp {
        Timestamp(rng.gen::<BFieldElement>())
    }
}

impl<'a> Arbitrary<'a> for Timestamp {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Result::Ok(Timestamp(BFieldElement::new(
            (u.arbitrary::<u128>()? % (BFieldElement::P as u128)) as u64,
        )))
    }
}

#[cfg(test)]
mod test {
    use crate::models::proof_abstractions::timestamp::Timestamp;

    #[test]
    fn print_now() {
        println!("{}", Timestamp::now());
    }
}
