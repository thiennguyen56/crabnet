mod linux;
mod manager;

pub(crate) use linux::{LinuxRouteBackend, TokioCommandRunner};

pub(crate) use manager::{
  full_tunnel_operations, server_operations, split_tunnel_operations, RouteManager,
};

pub use manager::RoutingConfig;
