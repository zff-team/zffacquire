#[cfg(target_family = "windows")]
mod windows;

#[cfg(target_family = "windows")]
pub(crate) use windows::*;