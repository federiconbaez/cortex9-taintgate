//! taintgate: an MCP gateway that labels tool outputs with information-flow
//! labels (`private`, `untrusted`), finds that content again in later
//! tool-call arguments (exact, n-gram and decoded matches), and blocks or
//! asks for approval when a call would complete the lethal trifecta.

#[allow(dead_code, rustdoc::broken_intra_doc_links)]
pub mod jsonrpc;

pub mod downstream;
pub mod engine;
pub mod labels;
pub mod normalize;
pub mod policy;
pub mod proxy;
pub mod taint;
pub mod world;
