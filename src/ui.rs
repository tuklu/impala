use std::sync::atomic::Ordering;

use iwdrs::modes::Mode;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Text},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};

use crate::app::{App, FocusedBlock};

pub fn render(app: &mut App, frame: &mut Frame) {
    if app.reset.enable {
        app.reset.render(frame);
    } else {
        if !app.device.is_powered {
            app.device
                .render(frame, app.focused_block, app.config.clone())
        } else {
            let device = app.device.clone();
            match app.device.mode {
                Mode::Station => {
                    if let Some(station) = &mut app.device.station {
                        station.render(frame, app.focused_block, &device, app.config.clone(), &app.captive_networks);
                    }
                }
                Mode::Ap => {
                    if let Some(ap) = &mut app.device.ap {
                        ap.render(frame, app.focused_block, &device, app.config.clone());
                    }
                }
            }
        };

        if app.focused_block == FocusedBlock::WpaEntrepriseAuth
            && let Some(eap) = &mut app.auth.eap
        {
            eap.render(frame);
        }

        if app.focused_block == FocusedBlock::AdapterInfos {
            app.adapter.render(frame, app.device.address.clone());
        }

        if app.agent.psk_required.load(Ordering::Relaxed) {
            app.focused_block = FocusedBlock::PskAuthKey;

            app.auth
                .psk
                .render(frame, app.network_name_requiring_auth.clone());
        }

        if app
            .agent
            .private_key_passphrase_required
            .load(Ordering::Relaxed)
            && let Some(req) = &app.auth.request_key_passphrase
        {
            req.render(frame);
        }

        if app.agent.password_required.load(Ordering::Relaxed)
            && let Some(req) = &app.auth.request_password
        {
            req.render(frame);
        }

        if app
            .agent
            .username_and_password_required
            .load(Ordering::Relaxed)
            && let Some(req) = &app.auth.request_username_and_password
        {
            req.render(frame);
        }

        if let Some(station) = &app.device.station
            && let Some(conn) = &station.connct_hidden_network
        {
            conn.render(frame);
        }

        if app.focused_block == FocusedBlock::CaptivePortalPrompt {
            if let Some(url) = &app.captive_portal_url {
                render_captive_portal_prompt(frame, url);
            }
        }

        // Notifications
        for (index, notification) in app.notifications.iter().enumerate() {
            notification.render(index, frame);
        }
    }
}

fn render_captive_portal_prompt(frame: &mut Frame, url: &str) {
    let area = frame.area();

    let popup_width = 64u16.min(area.width.saturating_sub(4));
    let popup_height = 5u16;

    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(popup_height),
            Constraint::Fill(1),
        ])
        .split(area);

    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(popup_width),
            Constraint::Fill(1),
        ])
        .split(vertical[1]);

    let popup_area = horizontal[1];

    let truncated_url = if url.len() > (popup_width as usize).saturating_sub(4) {
        format!("{}...", &url[..(popup_width as usize).saturating_sub(7)])
    } else {
        url.to_string()
    };

    let text = Text::from(vec![
        Line::from(""),
        Line::from(truncated_url).centered().yellow(),
        Line::from(""),
    ]);

    frame.render_widget(Clear, popup_area);
    frame.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .title(" Captive Portal Detected ")
                .title_style(Style::default().bold().fg(Color::Yellow))
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .border_style(Style::default().fg(Color::Yellow)),
        ),
        popup_area,
    );
}
