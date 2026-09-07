use log::LevelFilter;

mod acquisition;
mod app;
mod screens;
mod style;

use app::ZffAcquireApp;

fn main() -> iced::Result {
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .init();

    iced::application(
        ZffAcquireApp::new,
        ZffAcquireApp::update,
        ZffAcquireApp::view,
    )
    .title(|state: &ZffAcquireApp| state.title())
    .subscription(ZffAcquireApp::subscription)
    .theme(|_state: &ZffAcquireApp| style::forensic_theme())
    .window_size((1080.0, 760.0))
    .run()
}
