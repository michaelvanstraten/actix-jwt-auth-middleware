#[cfg(feature = "use_jwt_on_resource")]
mod resource;
mod app_and_scope;


#[cfg(feature = "use_jwt_on_resource")]
pub use resource::*;
pub use app_and_scope::*;
