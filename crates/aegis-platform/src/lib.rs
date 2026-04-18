mod mock;
mod traits;

pub use mock::MockPlatform;
pub use traits::{
    KernelIntegrity, PlatformProtection, PlatformResponse, PlatformSensor, PreemptiveBlock,
};
