mod mock;
mod traits;
mod windows;

pub use mock::{MockAction, MockPlatform};
pub use traits::{
    KernelIntegrity, KernelTransport, PlatformDescriptor, PlatformProtection, PlatformResponse,
    PlatformRuntime, PlatformSensor, PlatformTarget, PreemptiveBlock,
};
pub use windows::{WindowsEventStub, WindowsPlatform, WindowsProviderKind};
