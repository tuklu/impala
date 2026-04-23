use anyhow::Result;
use iwdrs::{
    error::{IWDError, network::ConnectError},
    network::{Network as iwdNetwork, NetworkType},
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    event::Event,
    mode::station::known_network::KnownNetwork,
    notification::{Notification, NotificationLevel},
};

const PROBE_URL: &str = "http://connectivitycheck.gstatic.com/generate_204";

async fn curl_probe(ip_flag: &str) -> (String, String) {
    let Ok(output) = tokio::process::Command::new("curl")
        .args([
            ip_flag, "-s", "-o", "/dev/null",
            "-w", "%{http_code} %{redirect_url}",
            "--max-time", "5",
            PROBE_URL,
        ])
        .output()
        .await
    else {
        log::warn!("captive: curl ({ip_flag}) failed to spawn");
        return (String::new(), String::new());
    };
    let raw = String::from_utf8_lossy(&output.stdout);
    let mut parts = raw.trim().splitn(2, ' ');
    let code = parts.next().unwrap_or("").trim().to_string();
    let url = parts.next().unwrap_or("").trim().to_string();
    (code, url)
}

fn pick_result(
    (v4_code, v4_url): (String, String),
    (v6_code, v6_url): (String, String),
) -> Option<(String, String)> {
    for (code, url) in [(&v4_code, &v4_url), (&v6_code, &v6_url)] {
        if url.starts_with("http://") || url.starts_with("https://") {
            return Some((code.clone(), url.clone()));
        }
    }
    for (code, url) in [(&v4_code, &v4_url), (&v6_code, &v6_url)] {
        if !code.is_empty() && code != "204" {
            return Some((code.clone(), url.clone()));
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct Network {
    pub n: iwdNetwork,
    pub name: String,
    pub network_type: NetworkType,
    pub is_connected: bool,
    pub known_network: Option<KnownNetwork>,
}

impl Network {
    pub async fn new(n: iwdNetwork) -> Result<Self> {
        let name = n.name().await?;
        let network_type = n.network_type().await?;
        let is_connected = n.connected().await?;
        let known_network = {
            match n.known_network().await {
                Ok(v) => match v {
                    Some(net) => Some(KnownNetwork::new(net).await.unwrap()),
                    None => None,
                },
                Err(_) => None,
            }
        };

        Ok(Self {
            n,
            name,
            network_type,
            is_connected,
            known_network,
        })
    }

    pub async fn connect(&self, sender: UnboundedSender<Event>) -> Result<()> {
        match self.n.connect().await {
            Ok(()) => {
                Notification::send(
                    format!("Connected to {}", self.name),
                    NotificationLevel::Info,
                    &sender,
                )?;
                let notif_sender = sender.clone();
                tokio::spawn(async move {
                    log::debug!("captive: probe started (v4 + v6 in parallel)");

                    let (v4, v6) = tokio::join!(
                        curl_probe("-4"),
                        curl_probe("-6"),
                    );

                    log::debug!("captive: v4={v4:?} v6={v6:?}");

                    let Some((_http_code, redirect_url)) = pick_result(v4, v6) else {
                        log::debug!("captive: both probes clean or failed, no portal");
                        return;
                    };

                    let redirect_is_ip = {
                        let host = redirect_url
                            .trim_start_matches("http://")
                            .trim_start_matches("https://")
                            .split('/')
                            .next()
                            .unwrap_or("")
                            .split(':')
                            .next()
                            .unwrap_or("");
                        host.parse::<std::net::IpAddr>().is_ok()
                    };

                    let portal_url = if redirect_is_ip {
                        log::debug!("captive: portal via IP redirect to {redirect_url}");
                        redirect_url
                    } else {
                        // hostname redirect — use gateway IP, client DNS might not resolve it
                        let gw = tokio::process::Command::new("ip")
                            .args(["route", "show", "default"])
                            .output()
                            .await
                            .ok()
                            .and_then(|o| {
                                String::from_utf8_lossy(&o.stdout)
                                    .lines()
                                    .find_map(|line| {
                                        let mut parts = line.split_whitespace();
                                        while let Some(w) = parts.next() {
                                            if w == "via" {
                                                return parts.next().map(|ip| format!("http://{ip}/"));
                                            }
                                        }
                                        None
                                    })
                            });

                        match gw {
                            Some(gw) => {
                                if redirect_url.is_empty() {
                                    log::debug!("captive: no redirect, using gateway {gw}");
                                } else {
                                    log::debug!(
                                        "captive: hostname redirect {redirect_url:?}, using gateway {gw} (bypasses DNS)"
                                    );
                                }
                                gw
                            }
                            None if !redirect_url.is_empty() => {
                                log::warn!(
                                    "captive: gateway lookup failed, trying redirect URL {redirect_url:?} as best effort"
                                );
                                redirect_url
                            }
                            None => {
                                log::warn!("captive: portal detected but could not determine portal URL");
                                return;
                            }
                        }
                    };

                    log::debug!("captive: prompting user for {portal_url}");
                    let _ = notif_sender
                        .send(crate::event::Event::CaptivePortalDetected(portal_url));
                });
            }
            Err(e) => match e {
                IWDError::OperationError(e) => match e {
                    ConnectError::Aborted => {
                        Notification::send(e.to_string(), NotificationLevel::Info, &sender)?;
                    }
                    _ => {
                        Notification::send(e.to_string(), NotificationLevel::Error, &sender)?;
                    }
                },
                _ => {
                    Notification::send(e.to_string(), NotificationLevel::Error, &sender)?;
                }
            },
        }
        Ok(())
    }
}
