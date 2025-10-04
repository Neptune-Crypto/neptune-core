use convert_case::Casing;
use proc_macro::TokenStream;
use quote::format_ident;
use quote::quote;
use syn::ItemEnum;
use syn::parse_macro_input;

pub fn json_router_derive(input: TokenStream) -> TokenStream {
    let enum_item = parse_macro_input!(input as ItemEnum);
    let enum_name = &enum_item.ident;

    let mut inserts = vec![];

    for variant in &enum_item.variants {
        let variant_name = &variant.ident;
        let variant_str = variant_name.to_string();

        let namespace = variant
            .attrs
            .iter()
            .find(|attr| attr.path().is_ident("namespace"))
            .and_then(|attr| attr.parse_args::<syn::ExprPath>().ok())
            .expect("Each variant must have #[namespace(...)]");

        let namespace_str = namespace
            .path
            .segments
            .last()
            .expect("Invalid namespace")
            .ident
            .to_string()
            .to_case(convert_case::Case::Snake);
        let method_suffix = variant_str.to_case(convert_case::Case::Camel);
        let method_name = format!("{}_{}", namespace_str, method_suffix);

        let req_type = format_ident!("{}Request", variant_name);
        let res_type = format_ident!("{}Response", variant_name);
        let call_fn = format_ident!("{}_call", variant_str.to_case(convert_case::Case::Snake));

        inserts.push(quote! {
            if namespaces.contains(&#namespace) {
                router.insert(#method_name, |api, params| async move {
                    let req: #req_type = serde_json::from_value(params)
                        .map_err(|_| RpcError::InvalidParams)?;
                    let resp: #res_type = api.#call_fn(req).await;
                    serde_json::to_value(resp).map_err(|_| RpcError::InternalError)
                });
            }
        });
    }

    let expanded = quote! {
        impl #enum_name {
            pub fn new_router(
                api: std::sync::Arc<dyn RpcApi>,
                namespaces: std::collections::HashSet<Namespace>
            ) -> RpcRouter {
                let mut router = RpcRouter::new(api);
                #(#inserts)*
                router
            }
        }
    };

    expanded.into()
}
