// RustyValue is an interface for serializing data as bytes for storing
// in the database.  See type description below.
//
// RustyValue now makes use of `bincode` for serializing data.
// Any rust `serializer` crate that understands serde
// Serialize and Deserialize traits could be plugged in instead.
//
// Here is a good comparison of rust serializers and their performance/size.
//  https://github.com/djkoloski/rust_serialization_benchmark
// See also this blog:
//  https://david.kolo.ski/blog/rkyv-is-faster-than/
//
// An important consideration is that many of these crates are not
// compatible with `serde`.   of those that are, `bincode` and `postcard`
// appear to be the fastest options, and are pretty close.
// `postcard` seems to create smaller serialized data size though,
// so that could be a good reason to use it for a large DB like
// a blockchain.  `ron` appears too slow to be a good option.
//
// With regards to blockchain size, we should also consider
// compressing our serialized data with something like zlib.
// In the above benchmarks, all libraries are compared with
// both uncompressed size and zlib compressed size.
//
// The fn that does the compression in the benchmark is:
//  https://github.com/djkoloski/rust_serialization_benchmark/blob/e1f6a31a431d5e8c3889525696231acbb691cbd9/src/lib.rs#L169
//
// For RustyValue, we would do the compression/decompression in the
// `serialize` and `deserialize` functions.
//
// Before making final decision(s), we should benchmark our
// code with real data and try out different crates/options.
//
// todo: consider moving the serialization functions, or perhaps all
// of rusty_value.rs to a top level module, eg twenty-first::serialization.

use std::fmt::Debug;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;

/// Represents a database value as bytes and provides conversions for standard types
///
/// It is simple to extend RustyValue for use with any locally defined type
/// that implements `serde::Serialize` and `serde::Deserialize`.
///
/// ## Examples
///
/// ```
/// use serde::{Serialize, Deserialize};
/// use neptune_cash::application::database::storage::storage_schema::RustyValue;
///
/// #[derive(Debug, Clone, Serialize, Deserialize)]
/// pub struct Person {
///     name: String,
///     age: u16,
/// }
///
/// impl From<RustyValue> for Person {
///    fn from(value: RustyValue) -> Self {
///        value.into_any()
///    }
/// }
///
/// impl From<Person> for RustyValue {
///    fn from(value: Person) -> Self {
///        Self::from_any(&value)
///    }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustyValue(pub Vec<u8>);

impl RustyValue {
    /// serialize a value `T` that implements `serde::Serialize` into `RustyValue`
    ///
    /// This provides the serialization for `RustyValue` in the database
    /// (or anywhere else it is stored)
    ///
    /// At present `bincode` is used for de/serialization, but this could
    /// change in the future.  No guarantee is made as the to serialization format.
    #[inline]
    pub fn from_any<T: Serialize>(value: &T) -> Self {
        Self(serialize(value))
    }
    /// Deserialize `RustyValue` into a value `T` that implements `serde::de::DeserializeOwned`
    ///
    /// This provides the deserialization for `RustyValue` from the database
    /// (or anywhere else it is stored)
    ///
    /// At present `bincode` is used for de/serialization, but this could
    /// change in the future.  No guarantee is made as the to serialization format.
    #[inline]
    pub fn into_any<T: DeserializeOwned>(&self) -> T {
        deserialize(&self.0)
    }
}

/// serialize a value T that implements serde::Serialize into bytes
///
/// At present `bincode` is used for de/serialization, but this could
/// change in the future.  No guarantee is made as the to serialization format.
///
// todo: consider compressing serialized bytes with zlib, or similar.
//       see comments at top of file.
// todo: consider moving this fn, or perhaps all of rusty_value.rs
//       to a top level module, eg twenty-first::serialization
#[inline]
pub fn serialize<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serialize(value).expect("should have serialized T into bytes")

    // for now, we use bincode.  but it would be so easy to switch to eg postcard or ron.
    // ron::to_string(value).unwrap().as_bytes().to_vec()
    // postcard::to_allocvec(value).unwrap()
}

/// serialize bytes into a value T that implements serde::de::SerializeOwned
///
/// At present `bincode` is used for de/serialization, but this could
/// change in the future.  No guarantee is made as the to serialization format.
///
// todo: consider decompressing serialized bytes with zlib, or similar.
//       see comments at top of file.
// todo: consider moving this fn, or perhaps all of rusty_value.rs
//       to a top level module, eg twenty-first::serialization
#[inline]
pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> T {
    bincode::deserialize(bytes).expect("should have deserialized bytes")

    // for now, we use bincode.  but it would be so easy to switch to eg postcard or ron.
    // ron::from_str(String::from_utf8(bytes.to_vec()).unwrap().as_str()).unwrap()
    // postcard::from_bytes(bytes).unwrap()
}
