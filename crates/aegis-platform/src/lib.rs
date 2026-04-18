mod mock;
mod traits;

pub use mock::{MockAction, MockPlatform};
pub use traits::{
    KernelIntegrity, KernelTransport, PlatformDescriptor, PlatformProtection, PlatformResponse,
    PlatformRuntime, PlatformSensor, PlatformTarget, PreemptiveBlock,
};
