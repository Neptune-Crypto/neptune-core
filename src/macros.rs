macro_rules! fn_name_bare {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        type_name_of(f)
            .rsplit("::")
            .find(|&part| part != "f" && part != "{{closure}}")
            .expect("Short function name")
    }};
}

macro_rules! fn_name {
    () => {{
        format!("{}()", crate::macros::fn_name_bare!())
    }};
}

// These allow the macros to be used as
// use crate::macros::xxxxx;
//
// see: https://stackoverflow.com/a/67140319/10087197

#[allow(unused_imports)]
pub(crate) use fn_name;
#[allow(unused_imports)]
pub(crate) use fn_name_bare;

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn fn_name_test() {
        assert_eq!(fn_name!(), "fn_name_test()");
    }

    #[tokio::test]
    async fn async_fn_name_test() {
        assert_eq!(fn_name!(), "async_fn_name_test()");
    }
}
