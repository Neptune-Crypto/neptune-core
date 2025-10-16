//! P2P integration layer
//!
//! This module provides integration between the P2P module and the existing
//! Neptune Core main loop and global state.

pub mod main_loop_integration;
pub mod service_factory;

// Re-export main types
pub use main_loop_integration::MainLoopIntegration;
pub use service_factory::P2PServiceFactory;
