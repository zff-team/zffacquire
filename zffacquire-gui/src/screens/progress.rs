use iced::{Element, Length};
use iced::widget::{button, column, container, row, scrollable, text};

use zffacquire_common::HumanReadable;

use crate::app::{Message, ZffAcquireApp};
use crate::style;

pub fn view(model: &ZffAcquireApp) -> Element<'_, Message> {
    let (percent, current_display, total_display) = if model.progress_total > 0 {
        let pct = (model.progress_current as f64 / model.progress_total as f64 * 100.0) as u32;
        let cur = model.progress_current.bytes_as_hrb();
        let tot = model.progress_total.bytes_as_hrb();
        (Some(pct), cur, tot)
    } else {
        (None, "0 B".to_string(), "unknown".to_string())
    };

    let progress_bar = iced::widget::progress_bar(0.0..=100.0, percent.unwrap_or(0) as f32)
        .style(style::progress);

    let progress_label = if let Some(pct) = percent {
        text(format!("{pct}%  —  {current_display} / {total_display}"))
            .size(22)
            .width(Length::Fill)
            .center()
            .style(style::title_text)
    } else {
        text("Waiting for data...")
            .size(14)
            .width(Length::Fill)
            .center()
            .style(style::dim_text)
    };

    let status_style = if model.progress_status.contains("fail") || model.progress_status.contains("Passwords") {
        style::danger_text
    } else if model.progress_status.contains("completed") {
        style::success_text
    } else {
        style::accent_text
    };

    let status_text = text(&model.progress_status)
        .size(13)
        .width(Length::Fill)
        .style(status_style);

    let progress_section = column![progress_bar, progress_label, status_text]
        .spacing(12)
        .width(Length::Fill)
        .padding(20);

    let progress_card = container(progress_section).width(Length::Fill).style(style::section_card);

    let log_header = text("Log Output").size(13).width(Length::Fill).style(style::accent_text);

    let log_content = if model.log_lines.is_empty() {
        text("No log entries yet...").size(12).width(Length::Fill).center().style(style::dim_text)
    } else {
        let log_str = model.log_lines.iter().rev().take(100).cloned().collect::<Vec<_>>().join("\n");
        text(log_str).size(12).width(Length::Fill)
    };

    let log_scroll = scrollable(
        container(log_content).width(Length::Fill).padding(iced::Padding::from([14.0f32, 14.0])),
    )
    .height(Length::Fill);

    let log_card = container(column![log_header, log_scroll].spacing(8))
        .padding(12)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(style::log_panel);

    let cancel_or_back = if model.is_running {
        button(text("Cancel").size(14)).on_press(Message::CancelAcquisition).padding(iced::Padding::from([12.0f32, 32.0])).style(style::btn_danger)
    } else {
        button(text("Back to Review").size(14)).on_press(Message::PrevScreen).padding(iced::Padding::from([12.0f32, 32.0])).style(style::btn_ghost)
    };

    let nav_row = row![cancel_or_back].spacing(12);

    let content = column![progress_card, log_card, nav_row]
        .spacing(16)
        .padding(iced::Padding { top: 8.0, right: 40.0, bottom: 24.0, left: 40.0 })
        .width(Length::Fill)
        .height(Length::Fill);

    container(content).width(Length::Fill).height(Length::Fill).style(style::app_background).into()
}
