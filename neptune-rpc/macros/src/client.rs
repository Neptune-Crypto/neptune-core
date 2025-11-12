use convert_case::Casing;
use proc_macro::TokenStream;
use quote::format_ident;
use quote::quote;
use syn::ItemEnum;
use syn::parse_macro_input;

pub fn json_routes_derive(input: TokenStream) -> TokenStream {
    let enum_item = parse_macro_input!(input as ItemEnum);

    let mut methods = vec![];

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

        methods.push(quote! {
            async fn #call_fn(&self, request: #req_type) -> RpcResult<#res_type> {
                let params = serde_json::to_value(&request)
                    .map_err(|_| JsonError::ParseError)?;
                let value = self.call(#method_name, params).await?;
                let resp: #res_type = serde_json::from_value(value)
                    .map_err(|_| JsonError::ParseError)?;
                Ok(resp)
            }
        });
    }

    let expanded = quote! {
        #[async_trait::async_trait]
        impl<T: Transport> RpcApi for T {
            #(#methods)*
        }
    };

    expanded.into()
}
