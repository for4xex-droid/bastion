/*
 * Bastion - Generic Security Engine
 * Copyright (C) 2026 motivationstudio,LLC
 */

use std::net::IpAddr;
use anyhow::{bail, Result};

#[cfg(feature = "net")]
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
#[cfg(feature = "net")]
use trust_dns_resolver::TokioAsyncResolver;
#[cfg(feature = "net")]
use reqwest::{Client, redirect::Policy};

/// Network access control client (Shield)
#[derive(Clone, Debug)]
pub struct ShieldClient {
    #[cfg(feature = "net")]
    client: Client,
    allowlist: Vec<String>,
}

impl ShieldClient {
    pub fn builder() -> ShieldClientBuilder {
        ShieldClientBuilder::default()
    }

    #[cfg(feature = "net")]
    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        self.validate_url(url).await?;
        Ok(self.client.get(url).send().await?)
    }

    #[cfg(feature = "net")]
    pub async fn post<T: serde::Serialize>(&self, url: &str, json_body: &T) -> Result<reqwest::Response> {
        self.validate_url(url).await?;
        Ok(self.client.post(url).json(json_body).send().await?)
    }

    pub async fn validate_url(&self, url_str: &str) -> Result<()> {
        let url = url::Url::parse(url_str)?;
        let host = url.host_str().ok_or_else(|| anyhow::anyhow!("No host in URL"))?;

        if self.allowlist.contains(&host.to_string()) {
            return Ok(());
        }

        #[cfg(feature = "net")]
        {
            let resolver = TokioAsyncResolver::tokio(
                ResolverConfig::default(),
                ResolverOpts::default(),
            );
            
            let response = resolver.lookup_ip(host).await?;
            for ip in response.iter() {
                if self.is_private_ip(ip) {
                    bail!("Access Denied: Private IP address detected ({})", ip);
                }
            }
            bail!("Access Denied: Host '{}' is not in the allowlist (Strict Mode)", host);
        }

        #[cfg(not(feature = "net"))]
        bail!("Access Denied: Host '{}' is not in the allowlist", host);
    }

    fn is_private_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_broadcast() || v4.is_documentation() || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || 
                (v6.segments()[0] & 0xfe00) == 0xfc00 || // Unique Local (fc00::/7)
                (v6.segments()[0] & 0xffc0) == 0xfe80    // Link-Local (fe80::/10)
            }
        }
    }
}

#[derive(Default)]
pub struct ShieldClientBuilder {
    allowlist: Vec<String>,
}

impl ShieldClientBuilder {
    pub fn allow_endpoint(mut self, host: &str) -> Self {
        self.allowlist.push(host.to_string());
        self
    }

    pub fn block_private_ips(self, _block: bool) -> Self {
        // Now it's always blocked by default in validate_url, 
        // but we keep the method for API compatibility.
        self
    }

    #[cfg(feature = "net")]
    pub fn build(self) -> Result<ShieldClient> {
        let client = Client::builder()
            .redirect(Policy::none())
            .build()?;

        Ok(ShieldClient {
            client,
            allowlist: self.allowlist,
        })
    }

    #[cfg(not(feature = "net"))]
    pub fn build(self) -> Result<ShieldClient> {
        Ok(ShieldClient {
            allowlist: self.allowlist,
        })
    }
}
