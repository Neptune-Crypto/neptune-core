use proc_macro::TokenStream;

mod client;
mod server;

#[proc_macro_derive(Router, attributes(namespace))]
pub fn json_router_derive(input: TokenStream) -> TokenStream {
    server::json_router_derive(input)
}

#[proc_macro_derive(Routes, attributes(namespace))]
pub fn json_routes_derive(input: TokenStream) -> TokenStream {
    client::json_routes_derive(input)
}
