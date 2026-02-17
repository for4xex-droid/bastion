//! # net_guard (Net Shield)
//! 
//! SSRF (Server-Side Request Forgery) および DNS Rebinding 攻撃を物理的に防ぐための
//! 産業グレードのネットワークガード。
//! 
//! ## 防御の仕組み:
//! 1. **名前解決の強制**: OSのキャッシュに頼らず、独自に名前解決（A/AAAA）を行う。
//! 2. **IP検証**: 解決されたすべてのIPがプライベート、ループバック、リンクローカル等でないか検証。
//! 3. **TOCTOU防止**: 検証したIPを直接リクエストに使用する（DNS Rebindingの余地を与えない）。

use std::net::IpAddr;
use anyhow::{bail, Result, anyhow};
use url::Url;

#[cfg(feature = "net")]
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
#[cfg(feature = "net")]
use trust_dns_resolver::TokioAsyncResolver;
#[cfg(feature = "net")]
use reqwest::{Client, redirect::Policy, header};

/// ネットワークアクセスの制限を行う構造体
pub struct ShieldClient {
    #[cfg(feature = "net")]
    client: Client,
    allowlist: Vec<String>,
}

impl ShieldClient {
    /// ShieldClient のビルダー
    pub fn builder() -> ShieldClientBuilder {
        ShieldClientBuilder::default()
    }

    /// 安全に GET リクエストを送信する。
    /// 内部で DNS Rebinding 対策のために IP アドレスへの直接置換を行う。
    #[cfg(feature = "net")]
    pub async fn get(&self, url_str: &str) -> Result<reqwest::Response> {
        let (safe_url, original_host) = self.prepare_safe_request(url_str).await?;
        
        let mut request = self.client.get(safe_url);
        
        // 元のホスト名を Host ヘッダーにセットする（仮想ホスティング対応）
        if let Some(host) = original_host {
            request = request.header(header::HOST, host);
        }

        Ok(request.send().await?)
    }

    /// URL を検証し、DNS Rebinding を防ぐためにホスト名を IP に置換した URL を返す。
    #[cfg(feature = "net")]
    async fn prepare_safe_request(&self, url_str: &str) -> Result<(Url, Option<String>)> {
        let mut url = Url::parse(url_str)?;
        let host_str = url.host_str().ok_or_else(|| anyhow!("No host in URL"))?.to_string();

        // 1. Allowlist チェック (Allowlist にある場合は名前解決を行わずそのまま許可)
        if self.allowlist.contains(&host_str) {
            return Ok((url, None));
        }

        // 2. DNS 名前解決 (A/AAAA)
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        
        let response = resolver.lookup_ip(&host_str).await?;
        let first_ip = response.iter().next().ok_or_else(|| anyhow!("Failed to resolve host"))?;

        // 3. すべての解決された IP を検証
        for ip in response.iter() {
            if self.is_private_ip(ip) {
                bail!("Access Denied: Private IP address detected ({})", ip);
            }
        }

        // 4. DNS Rebinding 対策: URL のホスト部分を IP アドレスに置換
        // これにより、通信時の再名前解決を防ぐ。
        url.set_host(Some(&first_ip.to_string()))?;

        Ok((url, Some(host_str)))
    }

    /// プライベート IP かどうかを判定する (IPv4/v6)
    fn is_private_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || 
                v4.is_broadcast() || v4.is_documentation() || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || 
                (v6.segments()[0] & 0xfe00) == 0xfc00 || // Unique Local (fc00::/7)
                (v6.segments()[0] & 0xffc0) == 0xfe80    // Link-Local (fe80::/10)
            }
        }
    }
}

/// ShieldClient を構築するためのビルダー
pub struct ShieldClientBuilder {
    allowlist: Vec<String>,
}

impl Default for ShieldClientBuilder {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
        }
    }
}

impl ShieldClientBuilder {
    /// 特定のホストをスキャンの例外として許可する
    pub fn allow_endpoint(mut self, host: &str) -> Self {
        self.allowlist.push(host.to_string());
        self
    }

    #[cfg(feature = "net")]
    pub fn build(self) -> Result<ShieldClient> {
        let client = Client::builder()
            .redirect(Policy::none()) // SSRF防止のためリダイレクトは禁止
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

#[cfg(test)]
#[cfg(feature = "net")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_is_private_ip() {
        let shield = ShieldClient::builder().build().unwrap();
        
        assert!(shield.is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(shield.is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(shield.is_private_ip("::1".parse().unwrap()));
        assert!(!shield.is_private_ip("8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_prepare_safe_request() {
        let shield = ShieldClient::builder().build().unwrap();
        
        // ローカルホストへのアクセスは拒否されるべき
        let res = shield.prepare_safe_request("http://localhost").await;
        assert!(res.is_err());
        
        // 許可リスト
        let shield_with_allow = ShieldClient::builder()
            .allow_endpoint("localhost")
            .build().unwrap();
        let res = shield_with_allow.prepare_safe_request("http://localhost").await;
        assert!(res.is_ok());
    }
}
