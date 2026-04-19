mod linux;
mod macos;
mod mock;
mod traits;
mod windows;

pub use linux::{LinuxDegradeLevel, LinuxEventStub, LinuxPlatform, LinuxProviderKind};
pub use macos::{
    MacosAuthorizationState, MacosEventStub, MacosPlatform, MacosProviderKind, MacosSubscription,
};
pub use mock::{MockAction, MockPlatform};
pub use traits::{
    KernelIntegrity, KernelTransport, PlatformDescriptor, PlatformProtection, PlatformResponse,
    PlatformRuntime, PlatformSensor, PlatformTarget, PreemptiveBlock,
};
pub use windows::{WindowsEventStub, WindowsPlatform, WindowsProviderKind};
