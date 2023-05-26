use serde::de::{Deserialize, Deserializer, Error, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeTuple, Serializer};
use std::fmt;
use std::marker::PhantomData;

pub trait CompositeBigArray<'de>: Sized {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}

macro_rules! big_array {
    ($($len:expr,)+) => {
        $(
            // This Option<[T; $len]> is serialized by letting the T::default() value
            // represent the `None` and a randomly generation `u128` value inserted below represent
            // the `Some`. This should work as long as the default value for T does not serialize
            // to the random value.
            impl<'de, T> CompositeBigArray<'de> for Option<[T; $len]>
                where T: Default + Copy + Serialize + Deserialize<'de>+ PartialEq
            {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                    where S: Serializer
                {
                    let default = T::default();
                    match self {
                        None => {
                            let mut seq = serializer.serialize_tuple(1)?;
                            seq.serialize_element(&default)?;
                            seq.end()
                        },
                        Some(array) => {
                            let mut seq = serializer.serialize_tuple(array.len() + 1)?;
                            seq.serialize_element(&244708374526624735806982989568916108891u128)?;
                            for elem in &array[0..] {
                                seq.serialize_element(elem)?;
                            }
                            seq.end()
                        }
                    }

                }

                fn deserialize<D>(deserializer: D) -> Result<Option<[T; $len]>, D::Error>
                    where D: Deserializer<'de>
                {
                    struct ArrayVisitor<T> {
                        element: PhantomData<T>,
                    }

                    impl<'de, T> Visitor<'de> for ArrayVisitor<T>
                        where T: Default + Copy + Deserialize<'de> + PartialEq
                    {
                        type Value = Option<[T; $len]>;

                        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                            formatter.write_str(concat!("an array of length ", $len))
                        }

                        fn visit_seq<A>(self, mut seq: A) -> Result<Option<[T; $len]>, A::Error>
                            where A: SeqAccess<'de>
                        {
                            let default = T::default();
                            if default == seq.next_element()?
                            .ok_or_else(|| Error::invalid_length(0, &self))? {
                                Ok(None)
                            } else {
                                let mut arr = [T::default(); $len];
                                for i in 0..$len {
                                    arr[i] = seq.next_element()?
                                        .ok_or_else(|| Error::invalid_length(i, &self))?;
                                }
                                Ok(Some(arr))
                            }
                        }
                    }

                    let visitor = ArrayVisitor { element: PhantomData };
                    deserializer.deserialize_tuple($len + 1, visitor)
                }
            }

            impl<'de, T> CompositeBigArray<'de> for Box<[T; $len]>
                where T: Default + Copy + Serialize + Deserialize<'de>
            {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                    where S: Serializer
                {
                    let mut seq = serializer.serialize_tuple(self.len())?;
                    for elem in &self[..] {
                        seq.serialize_element(elem)?;
                    }
                    seq.end()
                }

                fn deserialize<D>(deserializer: D) -> Result<Box<[T; $len]>, D::Error>
                    where D: Deserializer<'de>
                {
                    struct ArrayVisitor<T> {
                        element: PhantomData<T>,
                    }

                    impl<'de, T> Visitor<'de> for ArrayVisitor<T>
                        where T: Default + Copy + Deserialize<'de>
                    {
                        type Value = Box<[T; $len]>;

                        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                            formatter.write_str(concat!("an array of length ", $len))
                        }

                        fn visit_seq<A>(self, mut seq: A) -> Result<Box<[T; $len]>, A::Error>
                            where A: SeqAccess<'de>
                        {
                            let mut arr = Box::new([T::default(); $len]);
                            for i in 0..$len {
                                arr[i] = seq.next_element()?
                                    .ok_or_else(|| Error::invalid_length(i, &self))?;
                            }
                            Ok(arr)
                        }
                    }

                    let visitor = ArrayVisitor { element: PhantomData };
                    deserializer.deserialize_tuple($len, visitor)
                }
            }
        )+
    }
}

big_array! {
    40, 48, 50, 56, 64, 72, 96, 100, 128, 160, 192, 200, 224, 256, 384, 512,
    768, 1000,
}
