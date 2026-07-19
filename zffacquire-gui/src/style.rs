use iced::{
    Border, Shadow, Vector,
    gradient::{self, Gradient},
    widget::{button, checkbox, container, progress_bar, text, text_input},
    Background, Color, Length, Theme,
};

use crate::app::Screen;

// ─── Color Palette ───────────────────────────────────────────────────

pub const BG_DARK: Color = Color::from_rgba(0.051, 0.067, 0.09, 1.0);
pub const BG_SURFACE: Color = Color::from_rgba(0.078, 0.094, 0.118, 1.0);
pub const BG_CARD: Color = Color::from_rgba(0.094, 0.11, 0.137, 1.0);
pub const BG_CARD_HOVER: Color = Color::from_rgba(0.118, 0.137, 0.165, 1.0);
pub const BG_INPUT: Color = Color::from_rgba(0.059, 0.071, 0.09, 1.0);
pub const BG_LOG: Color = Color::from_rgba(0.039, 0.047, 0.063, 1.0);

pub const TEXT: Color = Color::from_rgba(0.788, 0.82, 0.851, 1.0);
pub const TEXT_DIM: Color = Color::from_rgba(0.545, 0.584, 0.624, 1.0);
pub const TEXT_BRIGHT: Color = Color::from_rgba(0.933, 0.949, 0.965, 1.0);

pub const PRIMARY: Color = Color::from_rgba(0.345, 0.651, 1.0, 1.0);
pub const PRIMARY_LIGHT: Color = Color::from_rgba(0.5, 0.76, 1.0, 1.0);
pub const PRIMARY_DARK: Color = Color::from_rgba(0.22, 0.45, 0.75, 1.0);
pub const SUCCESS: Color = Color::from_rgba(0.247, 0.725, 0.314, 1.0);
pub const SUCCESS_LIGHT: Color = Color::from_rgba(0.38, 0.82, 0.45, 1.0);
pub const SUCCESS_DARK: Color = Color::from_rgba(0.156, 0.522, 0.22, 1.0);
pub const WARNING: Color = Color::from_rgba(0.824, 0.6, 0.133, 1.0);
pub const DANGER: Color = Color::from_rgba(0.974, 0.319, 0.286, 1.0);
pub const DANGER_DARK: Color = Color::from_rgba(0.7, 0.2, 0.18, 1.0);

pub const BORDER_COLOR: Color = Color::from_rgba(0.16, 0.192, 0.235, 1.0);
pub const BORDER_SUBTLE: Color = Color::from_rgba(0.12, 0.14, 0.17, 1.0);

// ─── Theme ───────────────────────────────────────────────────────────

pub fn forensic_theme() -> Theme {
    Theme::CatppuccinMocha
}

// ─── Gradients ───────────────────────────────────────────────────────

fn gradient_primary() -> Background {
    Gradient::Linear(
        gradient::Linear::new(0.0)
            .add_stop(0.0, PRIMARY)
            .add_stop(1.0, PRIMARY_LIGHT),
    )
    .into()
}

fn gradient_success() -> Background {
    Gradient::Linear(
        gradient::Linear::new(0.0)
            .add_stop(0.0, SUCCESS)
            .add_stop(1.0, SUCCESS_LIGHT),
    )
    .into()
}

fn gradient_progress_bar() -> Background {
    Gradient::Linear(
        gradient::Linear::new(0.0)
            .add_stop(0.0, PRIMARY)
            .add_stop(0.6, Color::from_rgba(0.38, 0.78, 0.88, 1.0))
            .add_stop(1.0, SUCCESS),
    )
    .into()
}

// ─── Shadows ─────────────────────────────────────────────────────────

fn shadow_sm() -> Shadow {
    Shadow {
        color: Color::from_rgba(0.0, 0.0, 0.0, 0.35),
        offset: Vector::new(0.0, 1.0),
        blur_radius: 4.0,
    }
}

fn shadow_glow(color: Color) -> Shadow {
    Shadow {
        color: Color {
            a: 0.25,
            ..color
        },
        offset: Vector::new(0.0, 2.0),
        blur_radius: 12.0,
    }
}

// ─── Borders ─────────────────────────────────────────────────────────

fn border_card() -> Border {
    Border::default().rounded(12).width(1).color(BORDER_COLOR)
}

fn border_input() -> Border {
    Border::default().rounded(6).width(1).color(BORDER_COLOR)
}

fn border_input_focus() -> Border {
    Border::default().rounded(6).width(1.5).color(PRIMARY)
}

// ─── Container Styles ────────────────────────────────────────────────

pub fn app_background(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(BG_DARK.into()),
        text_color: Some(TEXT),
        ..Default::default()
    }
}

pub fn card_flat(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(BG_SURFACE.into()),
        text_color: Some(TEXT),
        border: Border::default().rounded(8).width(1).color(BORDER_SUBTLE),
        shadow: Shadow::default(),
        snap: false,
    }
}

pub fn section_card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(BG_CARD.into()),
        text_color: Some(TEXT),
        border: border_card(),
        shadow: shadow_sm(),
        snap: false,
    }
}

pub fn log_panel(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(BG_LOG.into()),
        text_color: Some(TEXT_DIM),
        border: Border::default().rounded(8).width(1).color(BORDER_COLOR),
        shadow: Shadow::default(),
        snap: false,
    }
}

pub fn stepper_container(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(BG_SURFACE.into()),
        text_color: Some(TEXT),
        border: Border::default().rounded(0).width(0).color(Color::TRANSPARENT),
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.2),
            offset: Vector::new(0.0, 2.0),
            blur_radius: 6.0,
        },
        snap: false,
    }
}

pub fn warning_card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Color::from_rgba(0.824, 0.6, 0.133, 0.12).into()),
        text_color: Some(WARNING),
        border: Border::default()
            .rounded(8)
            .width(1)
            .color(Color::from_rgba(0.824, 0.6, 0.133, 0.4)),
        shadow: Shadow::default(),
        snap: false,
    }
}

// ─── Button Styles ───────────────────────────────────────────────────

pub fn btn_primary(_theme: &Theme, status: button::Status) -> button::Style {
    match status {
        button::Status::Active => button::Style {
            background: Some(gradient_primary()),
            text_color: Color::WHITE,
            border: Border::default().rounded(8),
            shadow: shadow_glow(PRIMARY),
            snap: false,
        },
        button::Status::Hovered => button::Style {
            background: Some(BG_CARD_HOVER.into()),
            text_color: PRIMARY,
            border: Border::default().rounded(8).width(1).color(PRIMARY),
            shadow: shadow_glow(PRIMARY),
            snap: false,
        },
        button::Status::Pressed => button::Style {
            background: Some(PRIMARY_DARK.into()),
            text_color: Color::WHITE,
            border: Border::default().rounded(8),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Disabled => button::Style {
            background: Some(BG_CARD.into()),
            text_color: TEXT_DIM,
            border: Border::default().rounded(8),
            shadow: Shadow::default(),
            snap: false,
        },
    }
}

pub fn btn_success(_theme: &Theme, status: button::Status) -> button::Style {
    match status {
        button::Status::Active => button::Style {
            background: Some(gradient_success()),
            text_color: Color::WHITE,
            border: Border::default().rounded(8),
            shadow: shadow_glow(SUCCESS),
            snap: false,
        },
        button::Status::Hovered => button::Style {
            background: Some(BG_CARD_HOVER.into()),
            text_color: SUCCESS,
            border: Border::default().rounded(8).width(1).color(SUCCESS),
            shadow: shadow_glow(SUCCESS),
            snap: false,
        },
        button::Status::Pressed => button::Style {
            background: Some(SUCCESS_DARK.into()),
            text_color: Color::WHITE,
            border: Border::default().rounded(8),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Disabled => button::Style {
            background: Some(BG_CARD.into()),
            text_color: TEXT_DIM,
            border: Border::default().rounded(8),
            shadow: Shadow::default(),
            snap: false,
        },
    }
}

pub fn btn_secondary(_theme: &Theme, status: button::Status) -> button::Style {
    match status {
        button::Status::Active => button::Style {
            background: Some(BG_CARD.into()),
            text_color: TEXT,
            border: Border::default().rounded(8).width(1).color(BORDER_COLOR),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Hovered => button::Style {
            background: Some(BG_CARD_HOVER.into()),
            text_color: TEXT_BRIGHT,
            border: Border::default().rounded(8).width(1).color(PRIMARY),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Pressed => button::Style {
            background: Some(PRIMARY_DARK.into()),
            text_color: Color::WHITE,
            border: Border::default().rounded(8).width(1).color(PRIMARY),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Disabled => button::Style {
            background: Some(BG_CARD.into()),
            text_color: TEXT_DIM,
            border: Border::default().rounded(8),
            shadow: Shadow::default(),
            snap: false,
        },
    }
}

pub fn btn_ghost(_theme: &Theme, status: button::Status) -> button::Style {
    match status {
        button::Status::Active => button::Style {
            background: None,
            text_color: TEXT_DIM,
            border: Border::default().rounded(8),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Hovered => button::Style {
            background: Some(BG_CARD.into()),
            text_color: TEXT,
            border: Border::default().rounded(8),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Pressed => button::Style {
            background: Some(BG_CARD_HOVER.into()),
            text_color: TEXT_BRIGHT,
            border: Border::default().rounded(8),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Disabled => button::Style {
            background: None,
            text_color: TEXT_DIM,
            border: Border::default().rounded(8),
            shadow: Shadow::default(),
            snap: false,
        },
    }
}

pub fn btn_danger(_theme: &Theme, status: button::Status) -> button::Style {
    match status {
        button::Status::Active => button::Style {
            background: Some(DANGER.into()),
            text_color: Color::WHITE,
            border: Border::default().rounded(8),
            shadow: shadow_glow(DANGER),
            snap: false,
        },
        button::Status::Hovered => button::Style {
            background: Some(BG_CARD_HOVER.into()),
            text_color: DANGER,
            border: Border::default().rounded(8).width(1).color(DANGER),
            shadow: shadow_glow(DANGER),
            snap: false,
        },
        button::Status::Pressed => button::Style {
            background: Some(DANGER_DARK.into()),
            text_color: Color::WHITE,
            border: Border::default().rounded(8),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Disabled => button::Style {
            background: Some(BG_CARD.into()),
            text_color: TEXT_DIM,
            border: Border::default().rounded(8),
            shadow: Shadow::default(),
            snap: false,
        },
    }
}

pub fn btn_selected(_theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(PRIMARY.into()),
        text_color: Color::WHITE,
        border: Border::default().rounded(8).width(1).color(PRIMARY),
        shadow: shadow_glow(PRIMARY),
        snap: false,
    }
}

pub fn btn_remove(_theme: &Theme, status: button::Status) -> button::Style {
    match status {
        button::Status::Active => button::Style {
            background: Some(Color::from_rgba(0.974, 0.319, 0.286, 0.12).into()),
            text_color: DANGER,
            border: Border::default()
                .rounded(6)
                .width(1)
                .color(Color::from_rgba(0.974, 0.319, 0.286, 0.3)),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Hovered => button::Style {
            background: Some(DANGER.into()),
            text_color: Color::WHITE,
            border: Border::default().rounded(6).width(1).color(DANGER),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Pressed => button::Style {
            background: Some(DANGER_DARK.into()),
            text_color: Color::WHITE,
            border: Border::default().rounded(6).width(1).color(DANGER),
            shadow: Shadow::default(),
            snap: false,
        },
        button::Status::Disabled => button::Style {
            background: Some(BG_CARD.into()),
            text_color: TEXT_DIM,
            border: Border::default().rounded(6),
            shadow: Shadow::default(),
            snap: false,
        },
    }
}

pub fn btn_pill_selected(_theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(PRIMARY.into()),
        text_color: Color::WHITE,
        border: Border::default().rounded(20).width(1).color(PRIMARY),
        shadow: shadow_glow(PRIMARY),
        snap: false,
    }
}

pub fn btn_pill(_theme: &Theme, status: button::Status) -> button::Style {
    match status {
        button::Status::Active | button::Status::Hovered | button::Status::Pressed => {
            button::Style {
                background: Some(BG_CARD.into()),
                text_color: TEXT,
                border: Border::default().rounded(20).width(1).color(BORDER_COLOR),
                shadow: Shadow::default(),
                snap: false,
            }
        }
        button::Status::Disabled => button::Style {
            background: Some(BG_CARD.into()),
            text_color: TEXT_DIM,
            border: Border::default().rounded(20),
            shadow: Shadow::default(),
            snap: false,
        },
    }
}

// ─── TextInput Styles ────────────────────────────────────────────────

pub fn input(_theme: &Theme, status: text_input::Status) -> text_input::Style {
    match status {
        text_input::Status::Active => text_input::Style {
            background: BG_INPUT.into(),
            border: border_input(),
            icon: TEXT_DIM,
            placeholder: TEXT_DIM,
            value: TEXT_BRIGHT,
            selection: Color::from_rgba(0.345, 0.651, 1.0, 0.3),
        },
        text_input::Status::Hovered => text_input::Style {
            background: BG_INPUT.into(),
            border: border_input_focus(),
            icon: TEXT_DIM,
            placeholder: TEXT_DIM,
            value: TEXT_BRIGHT,
            selection: Color::from_rgba(0.345, 0.651, 1.0, 0.3),
        },
        text_input::Status::Focused { is_hovered: _ } => text_input::Style {
            background: BG_INPUT.into(),
            border: border_input_focus(),
            icon: PRIMARY,
            placeholder: TEXT_DIM,
            value: TEXT_BRIGHT,
            selection: Color::from_rgba(0.345, 0.651, 1.0, 0.35),
        },
        text_input::Status::Disabled => text_input::Style {
            background: BG_CARD.into(),
            border: border_input(),
            icon: TEXT_DIM,
            placeholder: TEXT_DIM,
            value: TEXT_DIM,
            selection: Color::TRANSPARENT,
        },
    }
}

// ─── ProgressBar Style ───────────────────────────────────────────────

pub fn progress(_theme: &Theme) -> progress_bar::Style {
    progress_bar::Style {
        background: BG_INPUT.into(),
        bar: gradient_progress_bar(),
        border: Border::default().rounded(6).width(1).color(BORDER_COLOR),
    }
}

// ─── Checkbox Styles ─────────────────────────────────────────────────

pub fn checkbox_checked(_theme: &Theme, _status: checkbox::Status) -> checkbox::Style {
    checkbox::Style {
        background: PRIMARY.into(),
        icon_color: Color::WHITE,
        border: Border::default().rounded(4).width(1).color(PRIMARY),
        text_color: Some(TEXT),
    }
}

pub fn checkbox_unchecked(_theme: &Theme, _status: checkbox::Status) -> checkbox::Style {
    checkbox::Style {
        background: BG_INPUT.into(),
        icon_color: Color::TRANSPARENT,
        border: Border::default().rounded(4).width(1).color(BORDER_COLOR),
        text_color: Some(TEXT),
    }
}

// ─── Text Style Closures ─────────────────────────────────────────────

pub fn title_text(_theme: &Theme) -> text::Style {
    text::Style {
        color: Some(TEXT_BRIGHT),
    }
}

pub fn accent_text(_theme: &Theme) -> text::Style {
    text::Style {
        color: Some(PRIMARY),
    }
}

pub fn dim_text(_theme: &Theme) -> text::Style {
    text::Style {
        color: Some(TEXT_DIM),
    }
}

pub fn success_text(_theme: &Theme) -> text::Style {
    text::Style {
        color: Some(SUCCESS),
    }
}

pub fn danger_text(_theme: &Theme) -> text::Style {
    text::Style {
        color: Some(DANGER),
    }
}

// ─── Stepper ─────────────────────────────────────────────────────────

const STEPS: [(&str, &str); 5] = [
    ("1", "Command"),
    ("2", "Parameters"),
    ("3", "Input"),
    ("4", "Review"),
    ("5", "Progress"),
];

pub fn step_index(screen: &Screen) -> usize {
    match screen {
        Screen::CommandSelect => 0,
        Screen::Parameters => 1,
        Screen::InputSelect => 2,
        Screen::Review => 3,
        Screen::Progress => 4,
    }
}

pub fn stepper_bar<'a, Message: 'a>(current_screen: &'a Screen) -> iced::Element<'a, Message> {
    let current = step_index(current_screen);

    let mut steps_row = iced::widget::row![].spacing(0);

    for (i, (num, label)) in STEPS.iter().enumerate() {
        let is_completed = i < current;
        let is_current = i == current;

        let circle_color = if is_completed {
            SUCCESS
        } else if is_current {
            PRIMARY
        } else {
            BG_CARD
        };

        let circle_text_color = if is_completed || is_current {
            Color::WHITE
        } else {
            TEXT_DIM
        };

        let circle_border_color = if is_completed {
            SUCCESS
        } else if is_current {
            PRIMARY
        } else {
            BORDER_COLOR
        };

        let num_str = *num;
        let label_str = *label;

        let circle = container(
            iced::widget::text(num_str)
                .size(13)
                .style(move |_theme: &Theme| text::Style {
                    color: Some(circle_text_color),
                }),
        )
        .center_y(24)
        .center_x(24)
        .style(move |_theme: &Theme| container::Style {
            background: Some(circle_color.into()),
            text_color: Some(circle_text_color),
            border: Border::default()
                .rounded(12)
                .width(1.5)
                .color(circle_border_color),
            shadow: if is_current || is_completed {
                shadow_glow(circle_color)
            } else {
                Shadow::default()
            },
            snap: false,
        });

        let label_color = if is_current {
            TEXT_BRIGHT
        } else if is_completed {
            SUCCESS
        } else {
            TEXT_DIM
        };

        let label_text = iced::widget::text(label_str)
            .size(12)
            .style(move |_theme: &Theme| text::Style {
                color: Some(label_color),
            })
            .center();

        let step_col =
            iced::widget::column![circle, label_text].spacing(4).align_x(iced::Center);

        steps_row = steps_row.push(step_col);

        if i < STEPS.len() - 1 {
            let line_color = if i < current { SUCCESS } else { BORDER_COLOR };

            let connector = container(iced::widget::text(""))
                .width(Length::FillPortion(1))
                .height(2)
                .max_width(60)
                .center_x(Length::Fill)
                .center_y(24)
                .style(move |_theme: &Theme| container::Style {
                    background: Some(line_color.into()),
                    border: Border::default().rounded(1),
                    ..Default::default()
                });

            steps_row = steps_row.push(connector);
        }
    }

    let stepper_content = steps_row.width(Length::Fill).padding(iced::Padding {
        top: 16.0,
        bottom: 16.0,
        left: 24.0,
        right: 24.0,
    });

    container(stepper_content)
        .max_width(600)
        .center_x(Length::Fill)
        .style(stepper_container)
        .into()
}
