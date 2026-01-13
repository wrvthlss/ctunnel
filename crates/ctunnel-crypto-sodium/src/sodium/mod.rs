pub(crate) mod ffi;
pub(crate) mod safe;

use once_cell::sync::Lazy;
use libsodium_sys::sodium_init;

/// Ensure libsodium is initialized exactly once.
static SODIUM_INIT: Lazy<()> = Lazy::new(|| {
    // Safe wrapper around unsafe ffi call.
    // If initialization fails, panic: crypto backend cannot operate.
    safe::sodium_init().expect("libsodium initialization failed");
});

pub(crate) fn init() {
    Lazy::force(&SODIUM_INIT);
}