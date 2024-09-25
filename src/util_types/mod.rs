use std::fmt::Debug;

pub mod mutator_set;

#[cfg(test)]
pub mod test_shared;

/// Split a list into multiple instances of the same type.
///
/// input argument specifies the length of each returned instance.
///
/// # Panics
/// Panics if input argument does not sum to the number of elements in the
/// input list.
#[expect(dead_code, reason = "under development")]
pub(crate) fn split_list_by<const N: usize, T: Clone + Debug>(
    list: Vec<T>,
    lengths: [usize; N],
) -> [Vec<T>; N] {
    let resulting_size: usize = lengths.into_iter().sum();
    assert_eq!(list.len(), resulting_size);

    let mut ret = vec![];

    let mut counter = 0;
    for length in lengths {
        let mut inner_list = vec![];
        for _ in 0..length {
            inner_list.push(list[counter].clone());
            counter += 1;
        }

        ret.push(inner_list);
    }

    ret.try_into().unwrap()
}
