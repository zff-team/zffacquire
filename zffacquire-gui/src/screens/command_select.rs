use iced::{Element, Length};
use iced::widget::{button, column, container, text};

use crate::app::{AcquireCommand, Message, ZffAcquireApp};
use crate::style;

pub fn view(model: &ZffAcquireApp) -> Element<'_, Message> {
    let title = text("zffacquire")
        .size(36)
        .width(Length::Fill)
        .center()
        .style(style::title_text);

    let subtitle = text("Forensic Data Acquisition Tool")
        .size(15)
        .width(Length::Fill)
        .center()
        .style(style::accent_text);

    let instruction = text("Select the type of acquisition to perform")
        .size(14)
        .width(Length::Fill)
        .center()
        .style(style::dim_text);

    // Only what the GUI can actually carry out is offered. Memory acquisition
    // and extending a container are implemented in the command line tool alone;
    // listing them here would let the user walk the whole wizard only to be
    // told at the end that nothing was going to happen.
    let commands: Vec<(&str, &str, AcquireCommand, bool)> = vec![
        ("Physical Disk", "Raw disk image acquisition", AcquireCommand::Physical, true),
        ("Logical Files", "File and folder acquisition", AcquireCommand::Logical, true),
        ("Convert Format", "Convert TAR or E01 to ZFF", AcquireCommand::Convert, true),
    ];

    let mut cards = column![].spacing(10).width(Length::Fill).max_width(520);

    for (label, description, cmd, enabled) in commands {
        if !enabled {
            continue;
        }
        let is_selected = model.selected_command.as_ref() == Some(&cmd);

        let card_title = text(label)
            .size(15)
            .width(Length::Fill)
            .style(if is_selected { style::title_text } else { style::dim_text });

        let card_desc = text(description)
            .size(12)
            .width(Length::Fill)
            .style(style::dim_text);

        let card_content = column![card_title, card_desc].spacing(4);

        let card = button(card_content)
            .on_press(Message::SelectCommand(cmd))
            .width(Length::Fill)
            .padding(16.0)
            .style(if is_selected { style::btn_selected } else { style::btn_secondary });

        cards = cards.push(card);
    }

    let selected_text = match &model.selected_command {
        Some(cmd) => {
            let label = match cmd {
                AcquireCommand::Physical => "Physical Disk",
                AcquireCommand::Logical => "Logical Files",
                AcquireCommand::Convert => "Convert Format",
            };
            text(format!("Selected: {label}"))
                .size(13)
                .width(Length::Fill)
                .center()
                .style(style::success_text)
        }
        None => text("No command selected")
            .size(13)
            .width(Length::Fill)
            .center()
            .style(style::dim_text),
    };

    let content = column![
        text("").height(Length::FillPortion(1)),
        title,
        subtitle,
        text("").height(Length::FillPortion(1)),
        instruction,
        cards,
        selected_text,
        text("").height(Length::FillPortion(1)),
    ]
    .spacing(12)
    .padding(iced::Padding { top: 0.0, right: 40.0, bottom: 0.0, left: 40.0 })
    .width(Length::Fill)
    .height(Length::Fill)
    .align_x(iced::Center);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(style::app_background)
        .into()
}
