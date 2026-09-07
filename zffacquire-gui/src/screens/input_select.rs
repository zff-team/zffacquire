use iced::widget::{button, column, container, row, scrollable, text};
use iced::{Element, Length};

use crate::app::{AcquireCommand, ConvertFormat, Message, ZffAcquireApp};
use crate::style;

fn dropzone_label(label: &str) -> Element<'static, Message> {
    text(label.to_string())
        .size(13)
        .style(style::dim_text)
        .into()
}

fn path_display(path: &str) -> Element<'static, Message> {
    text(path.to_string())
        .size(13)
        .width(Length::Fill)
        .style(style::title_text)
        .into()
}

pub fn view(model: &ZffAcquireApp) -> Element<'_, Message> {
    let title = text("Input / Output Selection")
        .size(20)
        .width(Length::Fill)
        .center()
        .style(style::title_text);

    let mut content = column![title]
        .spacing(16)
        .padding(iced::Padding {
            top: 8.0,
            right: 40.0,
            bottom: 24.0,
            left: 40.0,
        })
        .width(Length::Fill);

    let input_display = model
        .input_files
        .first()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "Not selected".to_string());
    let output_display = model
        .output_file
        .as_ref()
        .map(|p| {
            let mut path = p.clone();
            path.set_extension("z01");
            path.display().to_string()
        })
        .unwrap_or_else(|| "Not selected".to_string());

    let selected_count = model.input_files.len();

    match &model.selected_command {
        Some(AcquireCommand::Physical) => {
            let input_card = {
                let inner = column![
                    dropzone_label("Input Device"),
                    container(path_display(&input_display))
                        .padding(iced::Padding::from([10.0f32, 14.0]))
                        .width(Length::Fill)
                        .style(style::card_flat),
                    button(text("Browse Device...").size(13))
                        .on_press(Message::PickInputFile)
                        .padding(iced::Padding::from([10.0f32, 20.0]))
                        .style(style::btn_primary),
                ]
                .spacing(10)
                .width(Length::Fill);
                container(inner)
                    .padding(20)
                    .width(Length::Fill)
                    .style(style::section_card)
            };
            let output_card = {
                let inner = column![
                    dropzone_label("Output File"),
                    container(path_display(&output_display))
                        .padding(iced::Padding::from([10.0f32, 14.0]))
                        .width(Length::Fill)
                        .style(style::card_flat),
                    button(text("Browse Output...").size(13))
                        .on_press(Message::PickOutputFile)
                        .padding(iced::Padding::from([10.0f32, 20.0]))
                        .style(style::btn_primary),
                ]
                .spacing(10)
                .width(Length::Fill);
                container(inner)
                    .padding(20)
                    .width(Length::Fill)
                    .style(style::section_card)
            };
            content = content.push(input_card).push(output_card);
        }
        Some(AcquireCommand::Logical) => {
            let input_card = {
                let buttons_row = row![
                    button(text("Add Files...").size(13))
                        .on_press(Message::PickInputFile)
                        .padding(iced::Padding::from([10.0f32, 16.0]))
                        .style(style::btn_secondary),
                    button(text("Add Folder...").size(13))
                        .on_press(Message::PickInputFolder)
                        .padding(iced::Padding::from([10.0f32, 16.0]))
                        .style(style::btn_secondary),
                    button(text("Clear All").size(13))
                        .on_press(Message::ClearInputFiles)
                        .padding(iced::Padding::from([10.0f32, 16.0]))
                        .style(style::btn_danger),
                ]
                .spacing(8);

                let count_badge = text(format!(
                    "{} item{} selected",
                    selected_count,
                    if selected_count == 1 { "" } else { "s" }
                ))
                .size(12)
                .style(if selected_count > 0 {
                    style::success_text
                } else {
                    style::dim_text
                });

                let header_row = row![buttons_row, count_badge]
                    .spacing(12)
                    .width(Length::Fill)
                    .align_y(iced::Center);

                let mut file_list = column![].spacing(2);
                for path in &model.input_files {
                    let file_row = container(text(path.display().to_string()).size(12))
                        .padding(iced::Padding::from([6.0f32, 10.0]))
                        .width(Length::Fill)
                        .style(style::card_flat);
                    file_list = file_list.push(file_row);
                }
                let file_list_scroll: iced::Element<'_, Message> = if model.input_files.is_empty() {
                    container(
                        text("No files added yet")
                            .size(12)
                            .center()
                            .width(Length::Fill)
                            .style(style::dim_text),
                    )
                    .padding(30)
                    .width(Length::Fill)
                    .center_x(Length::Fill)
                    .style(style::card_flat)
                    .into()
                } else {
                    scrollable(file_list).height(Length::FillPortion(1)).into()
                };

                let inner = column![header_row, file_list_scroll]
                    .spacing(10)
                    .width(Length::Fill);
                container(inner)
                    .padding(20)
                    .width(Length::Fill)
                    .height(Length::FillPortion(1))
                    .style(style::section_card)
            };

            let output_card = {
                let inner = column![
                    dropzone_label("Output File"),
                    container(path_display(&output_display))
                        .padding(iced::Padding::from([10.0f32, 14.0]))
                        .width(Length::Fill)
                        .style(style::card_flat),
                    button(text("Browse Output...").size(13))
                        .on_press(Message::PickOutputFile)
                        .padding(iced::Padding::from([10.0f32, 20.0]))
                        .style(style::btn_primary),
                ]
                .spacing(10)
                .width(Length::Fill);
                container(inner)
                    .padding(20)
                    .width(Length::Fill)
                    .style(style::section_card)
            };

            content = content.push(input_card).push(output_card);
        }
        Some(AcquireCommand::Convert) => {
            let hint_text = match model.convert_format {
                ConvertFormat::Tar => "Supported: .tar, .tar.gz, .tar.zst, .tar.lz4",
                ConvertFormat::Ewf => "Supported: .E01, .e01 (EWF segment files)",
            };

            let input_card = {
                let inner = column![
                    dropzone_label("Input File"),
                    text(hint_text).size(11).style(style::dim_text),
                    container(path_display(&input_display))
                        .padding(iced::Padding::from([10.0f32, 14.0]))
                        .width(Length::Fill)
                        .style(style::card_flat),
                    button(text("Browse Input...").size(13))
                        .on_press(Message::PickInputFile)
                        .padding(iced::Padding::from([10.0f32, 20.0]))
                        .style(style::btn_primary),
                ]
                .spacing(10)
                .width(Length::Fill);
                container(inner)
                    .padding(20)
                    .width(Length::Fill)
                    .style(style::section_card)
            };
            let output_card = {
                let inner = column![
                    dropzone_label("Output File"),
                    text("Output will be ZFF format")
                        .size(11)
                        .style(style::dim_text),
                    container(path_display(&output_display))
                        .padding(iced::Padding::from([10.0f32, 14.0]))
                        .width(Length::Fill)
                        .style(style::card_flat),
                    button(text("Browse Output...").size(13))
                        .on_press(Message::PickOutputFile)
                        .padding(iced::Padding::from([10.0f32, 20.0]))
                        .style(style::btn_primary),
                ]
                .spacing(10)
                .width(Length::Fill);
                container(inner)
                    .padding(20)
                    .width(Length::Fill)
                    .style(style::section_card)
            };
            content = content.push(input_card).push(output_card);
        }
        None => {
            content = content.push(text("No command selected").size(14).style(style::dim_text));
        }
    }

    let prev_button = button(text("Back").size(14))
        .on_press(Message::PrevScreen)
        .padding(iced::Padding::from([12.0f32, 32.0]))
        .style(style::btn_ghost);
    let next_button = button(text("Next").size(14))
        .on_press(Message::NextScreen)
        .padding(iced::Padding::from([12.0f32, 32.0]))
        .style(style::btn_primary);
    let nav_row = row![prev_button, next_button]
        .spacing(12)
        .width(Length::Fill);

    content = content.push(nav_row);

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(style::app_background)
        .into()
}
