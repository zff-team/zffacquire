use iced::widget::{button, checkbox, column, container, row, scrollable, text, text_input};
use iced::{Element, Length};

use zffacquire_common::{CompressionAlgorithm, EncryptionAlgorithm, HashType};

use crate::app::{
    AcquireCommand, ConvertFormat, DeduplicationMode, KdfPbeOption, Message, ZffAcquireApp,
};
use crate::style;

fn section_card<'a>(
    title: &'a str,
    content: iced::Element<'a, Message>,
) -> iced::Element<'a, Message> {
    let header = text(title)
        .size(15)
        .width(Length::Fill)
        .style(style::accent_text);

    let card_content = column![header, content]
        .spacing(10)
        .padding(16)
        .width(Length::Fill);

    container(card_content).style(style::section_card).into()
}

fn field_label(label: &str) -> Element<'_, Message> {
    text(label).size(12).style(style::dim_text).into()
}

pub fn view(model: &ZffAcquireApp) -> Element<'_, Message> {
    let level_str = model.compression_level.to_string();
    let threshold_str = model.compression_threshold.to_string();

    let algo_zstd = model.compression_algo == CompressionAlgorithm::Zstd;
    let algo_lz4 = model.compression_algo == CompressionAlgorithm::Lz4;
    let algo_none = !algo_zstd && !algo_lz4;

    let comp_algo_row = row![
        button(text("None").size(12))
            .on_press(Message::CompressionAlgoChanged(CompressionAlgorithm::None))
            .style(if algo_none {
                style::btn_pill_selected
            } else {
                style::btn_pill
            }),
        button(text("Zstd").size(12))
            .on_press(Message::CompressionAlgoChanged(CompressionAlgorithm::Zstd))
            .style(if algo_zstd {
                style::btn_pill_selected
            } else {
                style::btn_pill
            }),
        button(text("LZ4").size(12))
            .on_press(Message::CompressionAlgoChanged(CompressionAlgorithm::Lz4))
            .style(if algo_lz4 {
                style::btn_pill_selected
            } else {
                style::btn_pill
            }),
    ]
    .spacing(8)
    .width(Length::Fill);

    let mut compression_inner =
        column![field_label("Compression Algorithm"), comp_algo_row,].spacing(8);

    if !algo_none {
        compression_inner = compression_inner
            .push(field_label("Compression Level (1-9)"))
            .push(
                text_input("3", &level_str)
                    .on_input(|s| {
                        s.parse()
                            .map(Message::CompressionLevelChanged)
                            .unwrap_or(Message::CompressionLevelChanged(3))
                    })
                    .style(style::input)
                    .padding(iced::Padding::from([10.0f32, 12.0])),
            )
            .push(field_label("Compression Threshold"))
            .push(
                text_input("1.05", &threshold_str)
                    .on_input(Message::CompressionThresholdChanged)
                    .style(style::input)
                    .padding(iced::Padding::from([10.0f32, 12.0])),
            );
    }

    let compression_section = compression_inner;

    let mut encryption_inner = column![
        checkbox(model.encrypt)
            .label("Enable encryption")
            .on_toggle(Message::ToggleEncryption)
            .style(if model.encrypt {
                style::checkbox_checked
            } else {
                style::checkbox_unchecked
            }),
    ]
    .spacing(8);

    if model.encrypt {
        encryption_inner = encryption_inner
            .push(
                text_input("Password", &model.password)
                    .secure(true)
                    .on_input(Message::PasswordChanged)
                    .style(style::input)
                    .padding(iced::Padding::from([10.0f32, 12.0])),
            )
            .push(
                text_input("Confirm password", &model.password_confirm)
                    .secure(true)
                    .on_input(Message::PasswordConfirmChanged)
                    .style(style::input)
                    .padding(iced::Padding::from([10.0f32, 12.0])),
            );
    }

    let encryption_section = encryption_inner;

    let mut kdf_and_algo = column![].spacing(16);

    if model.encrypt {
        let mut kdf_buttons = column![].spacing(6);
        for opt in KdfPbeOption::all() {
            let is_selected = model.kdf_pbe == *opt;
            let label = opt.label().to_string();
            let opt_clone = opt.clone();
            kdf_buttons = kdf_buttons.push(
                button(text(label).size(12))
                    .on_press(Message::KdfPbeChanged(opt_clone))
                    .width(Length::Fill)
                    .padding(iced::Padding::from([10.0f32, 12.0]))
                    .style(if is_selected {
                        style::btn_selected
                    } else {
                        style::btn_secondary
                    }),
            );
        }

        let kdf_section =
            column![field_label("Key Derivation / PBE Scheme"), kdf_buttons].spacing(8);

        let enc_aes128 = model.encryption_algo == EncryptionAlgorithm::AES128GCM;
        let enc_aes256 = model.encryption_algo == EncryptionAlgorithm::AES256GCM;
        let enc_chacha = model.encryption_algo == EncryptionAlgorithm::CHACHA20POLY1305;

        let enc_algo_row = row![
            button(text("AES-128-GCM").size(12))
                .on_press(Message::EncryptionAlgoChanged(
                    EncryptionAlgorithm::AES128GCM
                ))
                .style(if enc_aes128 {
                    style::btn_pill_selected
                } else {
                    style::btn_pill
                }),
            button(text("AES-256-GCM").size(12))
                .on_press(Message::EncryptionAlgoChanged(
                    EncryptionAlgorithm::AES256GCM
                ))
                .style(if enc_aes256 {
                    style::btn_pill_selected
                } else {
                    style::btn_pill
                }),
            button(text("ChaCha20").size(12))
                .on_press(Message::EncryptionAlgoChanged(
                    EncryptionAlgorithm::CHACHA20POLY1305
                ))
                .style(if enc_chacha {
                    style::btn_pill_selected
                } else {
                    style::btn_pill
                }),
        ]
        .spacing(8)
        .width(Length::Fill);

        let enc_algo_section =
            column![field_label("Encryption Algorithm"), enc_algo_row].spacing(8);

        kdf_and_algo = kdf_and_algo.push(kdf_section).push(enc_algo_section);
    }

    let full_encryption_section = column![encryption_section, kdf_and_algo].spacing(16);

    let blake3 = model.hash_algorithms.contains(&HashType::Blake3);
    let sha256 = model.hash_algorithms.contains(&HashType::SHA256);
    let sha512 = model.hash_algorithms.contains(&HashType::SHA512);
    let blake2b = model.hash_algorithms.contains(&HashType::Blake2b512);
    let sha3_256 = model.hash_algorithms.contains(&HashType::SHA3_256);

    let hash_section = column![
        checkbox(blake3)
            .label("Blake3")
            .on_toggle(|_| Message::ToggleHash(HashType::Blake3))
            .style(if blake3 {
                style::checkbox_checked
            } else {
                style::checkbox_unchecked
            }),
        checkbox(sha256)
            .label("SHA-256")
            .on_toggle(|_| Message::ToggleHash(HashType::SHA256))
            .style(if sha256 {
                style::checkbox_checked
            } else {
                style::checkbox_unchecked
            }),
        checkbox(sha512)
            .label("SHA-512")
            .on_toggle(|_| Message::ToggleHash(HashType::SHA512))
            .style(if sha512 {
                style::checkbox_checked
            } else {
                style::checkbox_unchecked
            }),
        checkbox(blake2b)
            .label("Blake2b-512")
            .on_toggle(|_| Message::ToggleHash(HashType::Blake2b512))
            .style(if blake2b {
                style::checkbox_checked
            } else {
                style::checkbox_unchecked
            }),
        checkbox(sha3_256)
            .label("SHA3-256")
            .on_toggle(|_| Message::ToggleHash(HashType::SHA3_256))
            .style(if sha3_256 {
                style::checkbox_checked
            } else {
                style::checkbox_unchecked
            }),
    ]
    .spacing(8);

    let mut signing_inner = column![
        checkbox(model.sign_data)
            .label("Sign data (Ed25519)")
            .on_toggle(Message::ToggleSignData)
            .style(if model.sign_data {
                style::checkbox_checked
            } else {
                style::checkbox_unchecked
            }),
    ]
    .spacing(8);

    if model.sign_data {
        signing_inner = signing_inner.push(
            text_input(
                "Sign key (base64, optional)",
                &model.sign_key.clone().unwrap_or_default(),
            )
            .on_input(Message::SignKeyChanged)
            .style(style::input)
            .padding(iced::Padding::from([10.0f32, 12.0])),
        );
    }

    let signing_section = signing_inner;

    let sizes_section = column![
        field_label("Chunk size"),
        text_input("32KB", &model.chunk_size)
            .on_input(Message::ChunkSizeChanged)
            .style(style::input)
            .padding(iced::Padding::from([10.0f32, 12.0])),
        field_label("Chunkmap size"),
        text_input("32KB", &model.chunkmap_size)
            .on_input(Message::ChunkmapSizeChanged)
            .style(style::input)
            .padding(iced::Padding::from([10.0f32, 12.0])),
        field_label("Segment size (optional)"),
        text_input("e.g. 1GB", &model.segment_size.clone().unwrap_or_default())
            .on_input(Message::SegmentSizeChanged)
            .style(style::input)
            .padding(iced::Padding::from([10.0f32, 12.0])),
    ]
    .spacing(8);

    let description_section = column![
        field_label("Case number"),
        text_input("", &model.case_number.clone().unwrap_or_default())
            .on_input(Message::CaseNumberChanged)
            .style(style::input)
            .padding(iced::Padding::from([10.0f32, 12.0])),
        field_label("Evidence number"),
        text_input("", &model.evidence_number.clone().unwrap_or_default())
            .on_input(Message::EvidenceNumberChanged)
            .style(style::input)
            .padding(iced::Padding::from([10.0f32, 12.0])),
        field_label("Examiner name"),
        text_input("", &model.examiner_name.clone().unwrap_or_default())
            .on_input(Message::ExaminerNameChanged)
            .style(style::input)
            .padding(iced::Padding::from([10.0f32, 12.0])),
        field_label("Notes"),
        text_input("", &model.notes.clone().unwrap_or_default())
            .on_input(Message::NotesChanged)
            .style(style::input)
            .padding(iced::Padding::from([10.0f32, 12.0])),
    ]
    .spacing(8);

    let mut custom_descs = column![].spacing(8);
    for (i, (key, value)) in model.custom_descriptions.iter().enumerate() {
        let row = row![
            text_input("Key", key)
                .on_input(move |s| Message::CustomDescriptionKeyChanged(i, s))
                .width(Length::FillPortion(1))
                .style(style::input)
                .padding(iced::Padding::from([10.0f32, 12.0])),
            text_input("Value", value)
                .on_input(move |s| Message::CustomDescriptionValueChanged(i, s))
                .width(Length::FillPortion(2))
                .style(style::input)
                .padding(iced::Padding::from([10.0f32, 12.0])),
            button(text("×").size(16))
                .on_press(Message::RemoveCustomDescription(i))
                .padding(iced::Padding::from([8.0f32, 12.0]))
                .style(style::btn_remove),
        ]
        .spacing(8);
        custom_descs = custom_descs.push(row);
    }
    let add_custom_button = button(text("Add Custom Description").size(12))
        .on_press(Message::AddCustomDescription)
        .padding(iced::Padding::from([10.0f32, 16.0]))
        .style(style::btn_ghost);
    custom_descs = custom_descs.push(add_custom_button);

    let uncompress_on = model.uncompress_input;
    let input_section = column![
        field_label("Decompress input"),
        row![
            button(text("Off").size(12))
                .on_press(Message::UncompressInputChanged(false))
                .style(if !uncompress_on {
                    style::btn_pill_selected
                } else {
                    style::btn_pill
                }),
            button(text("On").size(12))
                .on_press(Message::UncompressInputChanged(true))
                .style(if uncompress_on {
                    style::btn_pill_selected
                } else {
                    style::btn_pill
                }),
        ]
        .spacing(8),
    ]
    .spacing(8);

    let dedup_in_memory = matches!(model.deduplication, DeduplicationMode::InMemory);
    let dedup_none = matches!(model.deduplication, DeduplicationMode::None);
    let dedup_on_disk = matches!(model.deduplication, DeduplicationMode::OnDisk(_));

    let mut dedup_section = column![
        field_label("Deduplication"),
        row![
            button(text("None").size(12))
                .on_press(Message::DeduplicationChanged(DeduplicationMode::None))
                .style(if dedup_none {
                    style::btn_pill_selected
                } else {
                    style::btn_pill
                }),
            button(text("In-Memory").size(12))
                .on_press(Message::DeduplicationChanged(DeduplicationMode::InMemory))
                .style(if dedup_in_memory {
                    style::btn_pill_selected
                } else {
                    style::btn_pill
                }),
            button(text("On-Disk...").size(12))
                .on_press(Message::PickDeduplicationFile)
                .style(if dedup_on_disk {
                    style::btn_pill_selected
                } else {
                    style::btn_pill
                }),
        ]
        .spacing(8),
    ]
    .spacing(8);

    if let DeduplicationMode::OnDisk(path) = &model.deduplication {
        dedup_section = dedup_section.push(
            text(path.display().to_string())
                .size(11)
                .style(style::dim_text),
        );
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

    let is_convert = model.selected_command.as_ref() == Some(&AcquireCommand::Convert);

    let mut params_col = column![].spacing(16);

    if is_convert {
        let fmt_tar = model.convert_format == ConvertFormat::Tar;
        let fmt_ewf = model.convert_format == ConvertFormat::Ewf;

        let format_row = row![
            button(text("TAR Archive").size(12))
                .on_press(Message::ConvertFormatChanged(ConvertFormat::Tar))
                .style(if fmt_tar {
                    style::btn_pill_selected
                } else {
                    style::btn_pill
                }),
            button(text("EWF (E01)").size(12))
                .on_press(Message::ConvertFormatChanged(ConvertFormat::Ewf))
                .style(if fmt_ewf {
                    style::btn_pill_selected
                } else {
                    style::btn_pill
                }),
        ]
        .spacing(8)
        .width(Length::Fill);

        let format_section = column![field_label("Input Format"), format_row,].spacing(8);

        params_col = params_col.push(section_card("Conversion Format", format_section.into()));
    }

    params_col = params_col
        .push(section_card("Compression", compression_section.into()))
        .push(section_card("Encryption", full_encryption_section.into()))
        .push(section_card("Hash Algorithms", hash_section.into()))
        .push(section_card("Signing", signing_section.into()));

    if model.selected_command.as_ref() == Some(&AcquireCommand::Physical) {
        params_col = params_col.push(section_card("Input", input_section.into()));
    }

    if !is_convert {
        params_col = params_col
            .push(section_card("Sizes", sizes_section.into()))
            .push(section_card("Description", description_section.into()))
            .push(section_card("Custom Descriptions", custom_descs.into()))
            .push(section_card("Deduplication", dedup_section.into()));
    }

    params_col = params_col.push(nav_row);

    let content = scrollable(
        params_col
            .spacing(16)
            .padding(iced::Padding {
                top: 8.0,
                right: 40.0,
                bottom: 24.0,
                left: 40.0,
            })
            .width(Length::Fill),
    );

    container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(style::app_background)
        .into()
}
