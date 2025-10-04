use proc_macro::TokenStream;

mod client;
mod server;

#[proc_macro_derive(Router, attributes(namespace))]
pub fn json_router_derive(input: TokenStream) -> TokenStream {
    server::json_router_derive(input)
}
