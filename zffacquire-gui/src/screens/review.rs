use iced::{Element, Length};
use iced::widget::{button, column, container, row, scrollable, text};

use crate::app::{AcquireCommand, Message, ZffAcquireApp};
use crate::style;

pub fn view(model: &ZffAcquireApp) -> Element<'_, Message> {
    let title = text("Review Configuration")
        .size(20)
        .width(Length::Fill)
        .center()
        .style(style::title_text);

    let mut items: Vec<Element<'static, Message>> = Vec::new();

    if let Some(cmd) = &model.selected_command {
        let label = match cmd {
            crate::app::AcquireCommand::Physical => "Physical Disk",
            crate::app::AcquireCommand::Logical => "Logical Files",
            crate::app::AcquireCommand::Memory => "Memory",
            crate::app::AcquireCommand::Extend => "Extend Container",
            crate::app::AcquireCommand::Convert => "Convert Format",
        };
        items.push(review_row("Command", label));

        if matches!(cmd, AcquireCommand::Convert) {
            items.push(review_row("Input Format", model.convert_format.label()));
        }
    }

    if !model.input_files.is_empty() {
        let input_display = if model.input_files.len() == 1 {
            model.input_files[0].display().to_string()
        } else {
            format!("{} items", model.input_files.len())
        };
        items.push(review_row("Input", &input_display));
    }

    if let Some(output) = &model.output_file {
        let mut path = output.clone();
        path.set_extension("z01");
        items.push(review_row("Output", &path.display().to_string()));
    }

    items.push(review_row("Compression", &format!("{} level {}", model.compression_algo, model.compression_level)));

    if model.encrypt {
        let enc_status = if model.password == model.password_confirm {
            format!("{:?} / {}", model.encryption_algo, model.kdf_pbe.label())
        } else {
            "WARNING: Passwords do not match!".to_string()
        };
        items.push(review_row_highlight("Encryption", &enc_status));
    } else {
        items.push(review_row("Encryption", "Disabled"));
    }

    let hash_display = if model.hash_algorithms.is_empty() {
        "None".to_string()
    } else {
        model.hash_algorithms.iter().map(|h| format!("{h:?}")).collect::<Vec<_>>().join(", ")
    };
    items.push(review_row("Hash", &hash_display));
    items.push(review_row("Signing", if model.sign_data { "Enabled" } else { "Disabled" }));

    let is_convert = model.selected_command.as_ref() == Some(&AcquireCommand::Convert);

    if !is_convert {
        if let Some(case) = &model.case_number {
            items.push(review_row("Case", case));
        }
        if let Some(evidence) = &model.evidence_number {
            items.push(review_row("Evidence", evidence));
        }
        if let Some(examiner) = &model.examiner_name {
            items.push(review_row("Examiner", examiner));
        }
        if let Some(notes) = &model.notes {
            items.push(review_row("Notes", notes));
        }

        items.push(review_row("Chunk size", &model.chunk_size));
        items.push(review_row("Chunkmap size", &model.chunkmap_size));
        if let Some(ref seg) = model.segment_size {
            items.push(review_row("Segment size", seg));
        }
    }

    let can_start = model.selected_command.is_some()
        && model.output_file.is_some()
        && !model.input_files.is_empty()
        && (!model.encrypt || model.password == model.password_confirm);

    let mut review_items = column![].spacing(2);
    for item in items {
        review_items = review_items.push(item);
    }

    let review_card = container(review_items).padding(20).width(Length::Fill).style(style::section_card);

    let mut content_col = column![title, review_card]
        .spacing(16)
        .padding(iced::Padding { top: 8.0, right: 40.0, bottom: 24.0, left: 40.0 })
        .width(Length::Fill);

    if !can_start {
        let mut issues = Vec::new();
        if model.selected_command.is_none() { issues.push("No command selected"); }
        if model.input_files.is_empty() { issues.push("No input files selected"); }
        if model.output_file.is_none() { issues.push("No output file selected"); }
        if model.encrypt && model.password != model.password_confirm { issues.push("Passwords do not match"); }

        let warning = container(
            text(format!("Cannot start: {}", issues.join(", "))).size(12).width(Length::Fill).style(style::danger_text),
        ).padding(iced::Padding::from([12.0f32, 16.0])).width(Length::Fill).style(style::warning_card);

        content_col = content_col.push(warning);
    }

    let prev_button = button(text("Back").size(14)).on_press(Message::PrevScreen).padding(iced::Padding::from([12.0f32, 32.0])).style(style::btn_ghost);
    let start_button = if can_start {
        button(text("Start Acquisition").size(14)).on_press(Message::StartAcquisition).padding(iced::Padding::from([14.0f32, 40.0])).style(style::btn_success)
    } else {
        button(text("Start Acquisition").size(14)).padding(iced::Padding::from([14.0f32, 40.0])).style(style::btn_success)
    };

    let nav_row = row![prev_button, start_button].spacing(12).width(Length::Fill);
    content_col = content_col.push(nav_row);

    container(scrollable(content_col)).width(Length::Fill).height(Length::Fill).style(style::app_background).into()
}

fn review_row(label: &str, value: &str) -> Element<'static, Message> {
    let left = text(label.to_string()).size(13).width(Length::FillPortion(1)).style(style::dim_text);
    let right = text(value.to_string()).size(13).width(Length::FillPortion(2)).style(style::title_text);
    let row_content = row![left, right].spacing(16).width(Length::Fill).padding(iced::Padding::from([8.0f32, 0.0]));
    container(row_content).width(Length::Fill).padding(iced::Padding::from([0.0f32, 4.0])).into()
}

fn review_row_highlight(label: &str, value: &str) -> Element<'static, Message> {
    let left = text(label.to_string()).size(13).width(Length::FillPortion(1)).style(style::dim_text);
    let value_style = if value.contains("WARNING") { style::danger_text } else { style::success_text };
    let right = text(value.to_string()).size(13).width(Length::FillPortion(2)).style(value_style);
    let row_content = row![left, right].spacing(16).width(Length::Fill).padding(iced::Padding::from([8.0f32, 0.0]));
    container(row_content).width(Length::Fill).padding(iced::Padding::from([0.0f32, 4.0])).into()
}
