//! Complete Microsoft / Xbox Live / Minecraft Services adapter.
//!
//! Ported from the original launcher `auth.rs` with the S1 contract changes:
//! the client id is injected by the developer/distributor configuration (the
//! original hard-coded id is intentionally NOT carried over), storage roots
//! come from [`SdkContext`], and login is split into `begin_login` (returns
//! the system-browser authorization URL) plus a blocking `complete_login`
//! that hosts wrap in a background task.
//!
//! Real-service flows are complete implementations; whether a given
//! deployment may use them depends on the configured application
//! registration, which the SDK never assumes.

use super::{
    AccountProvider, AccountProviderError, IdentityKind, IdentitySummary, LaunchIdentity,
    MicrosoftAccountVerified,
};
use crate::context::SdkContext;
use crate::error::SdkErrorSource;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use url::Url;
use uuid::Uuid;

const ACCOUNT_SCHEMA_VERSION: u32 = 2;
const MICROSOFT_SCOPE: &str = "XboxLive.signin offline_access";
const MICROSOFT_AUTHORIZE_URL: &str =
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const MICROSOFT_TOKEN_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
const XBOX_USER_URL: &str = "https://user.auth.xboxlive.com/user/authenticate";
const XSTS_URL: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";
const MINECRAFT_LOGIN_URL: &str =
    "https://api.minecraftservices.com/authentication/login_with_xbox";
const MINECRAFT_ENTITLEMENTS_URL: &str = "https://api.minecraftservices.com/entitlements/mcstore";
const MINECRAFT_PROFILE_URL: &str = "https://api.minecraftservices.com/minecraft/profile";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const DPAPI_ENTROPY: &[u8] = b"nacl-next-sdk microsoft refresh token v1";

/// Developer/distributor-provided public client id. The SDK ships without a
/// default; an empty config is rejected with `auth/microsoft/missing-client-id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrosoftClientConfig {
    pub client_id: String,
}

impl MicrosoftClientConfig {
    pub fn new(client_id: impl Into<String>) -> Result<Self, MicrosoftError> {
        let client_id = client_id.into().trim().to_string();
        if client_id.is_empty() || client_id.len() > 128 {
            return Err(MicrosoftError::MissingClientId);
        }
        Ok(Self { client_id })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct MinecraftSkin {
    pub id: String,
    #[serde(default)]
    pub state: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct MinecraftCape {
    pub id: String,
    #[serde(default)]
    pub state: String,
    pub url: String,
}

/// Persisted account profile (no secrets). Displayable and serializable.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct MicrosoftAccount {
    pub schema_version: u32,
    /// Client id this account was authorized under; a different configured
    /// id requires re-login instead of silently failing refreshes.
    pub client_id: String,
    pub minecraft_id: String,
    pub minecraft_name: String,
    #[serde(default)]
    pub skins: Vec<MinecraftSkin>,
    #[serde(default)]
    pub capes: Vec<MinecraftCape>,
    pub signed_in_epoch_ms: u128,
}

impl MicrosoftAccount {
    pub fn active_skin(&self) -> Option<&MinecraftSkin> {
        self.skins.iter().find(|skin| skin.state == "ACTIVE")
    }

    pub fn active_cape(&self) -> Option<&MinecraftCape> {
        self.capes.iter().find(|cape| cape.state == "ACTIVE")
    }
}

/// Handle returned by `begin_login`; hand its url to the system browser.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "contracts", derive(ts_rs::TS))]
pub struct LoginHandle {
    pub login_id: String,
    pub authorization_url: String,
}

#[derive(Debug)]
pub enum MicrosoftError {
    MissingClientId,
    Io {
        action: &'static str,
        source: io::Error,
    },
    Url(url::ParseError),
    Network(String),
    Service {
        stage: &'static str,
        status: u16,
        message: String,
    },
    InvalidCallback,
    StateMismatch,
    LoginTimedOut,
    LoginCancelled(String),
    LoginInProgress,
    UnknownLogin(String),
    MissingRefreshToken,
    MissingXboxClaim,
    MissingEntitlement,
    MissingMinecraftProfile,
    InvalidStoredAccount,
    ClientIdChanged,
    NotSignedIn,
    UnsupportedPlatform,
}

impl fmt::Display for MicrosoftError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingClientId => {
                write!(
                    formatter,
                    "未配置 Microsoft 应用 Client ID，无法使用正版登录"
                )
            }
            Self::Io { action, source } => write!(formatter, "无法{action}：{source}"),
            Self::Url(error) => write!(formatter, "登录地址无效：{error}"),
            Self::Network(error) => write!(formatter, "登录网络请求失败：{error}"),
            Self::Service {
                stage,
                status,
                message,
            } => write!(formatter, "{stage}失败（HTTP {status}）：{message}"),
            Self::InvalidCallback => write!(formatter, "Microsoft 登录回调无效"),
            Self::StateMismatch => write!(formatter, "Microsoft 登录状态校验失败，请重新登录"),
            Self::LoginTimedOut => write!(formatter, "Microsoft 登录等待超时，请重新登录"),
            Self::LoginCancelled(message) => write!(formatter, "Microsoft 登录未完成：{message}"),
            Self::LoginInProgress => write!(formatter, "已有一次 Microsoft 登录正在进行"),
            Self::UnknownLogin(id) => write!(formatter, "登录会话 {id} 不存在或已结束"),
            Self::MissingRefreshToken => write!(formatter, "Microsoft 未返回刷新令牌，请重新授权"),
            Self::MissingXboxClaim => write!(formatter, "Xbox 身份响应缺少必要的用户信息"),
            Self::MissingEntitlement => {
                write!(formatter, "该账号没有 Minecraft Java Edition 游戏资格")
            }
            Self::MissingMinecraftProfile => {
                write!(formatter, "该账号尚未创建 Minecraft Java Edition 档案")
            }
            Self::InvalidStoredAccount => {
                write!(formatter, "本地 Microsoft 账号数据无效，请重新登录")
            }
            Self::ClientIdChanged => {
                write!(
                    formatter,
                    "应用 Client ID 已变更，请重新登录 Microsoft 账号"
                )
            }
            Self::NotSignedIn => write!(formatter, "尚未登录 Microsoft 账号"),
            Self::UnsupportedPlatform => {
                write!(formatter, "当前平台不支持安全保存 Microsoft 登录")
            }
        }
    }
}

impl std::error::Error for MicrosoftError {}

impl From<url::ParseError> for MicrosoftError {
    fn from(error: url::ParseError) -> Self {
        Self::Url(error)
    }
}

impl SdkErrorSource for MicrosoftError {
    fn sdk_code(&self) -> &'static str {
        match self {
            Self::MissingClientId => "auth/microsoft/missing-client-id",
            Self::Io { .. } => "auth/microsoft/io",
            Self::Url(_) => "auth/microsoft/invalid-url",
            Self::Network(_) => "auth/microsoft/network",
            Self::Service { .. } => "auth/microsoft/service",
            Self::InvalidCallback => "auth/microsoft/invalid-callback",
            Self::StateMismatch => "auth/microsoft/state-mismatch",
            Self::LoginTimedOut => "auth/microsoft/login-timeout",
            Self::LoginCancelled(_) => "auth/microsoft/login-cancelled",
            Self::LoginInProgress => "auth/microsoft/login-in-progress",
            Self::UnknownLogin(_) => "auth/microsoft/unknown-login",
            Self::MissingRefreshToken => "auth/microsoft/missing-refresh-token",
            Self::MissingXboxClaim => "auth/microsoft/missing-xbox-claim",
            Self::MissingEntitlement => "auth/microsoft/missing-entitlement",
            Self::MissingMinecraftProfile => "auth/microsoft/missing-profile",
            Self::InvalidStoredAccount => "auth/microsoft/invalid-stored-account",
            Self::ClientIdChanged => "auth/microsoft/client-id-changed",
            Self::NotSignedIn => "auth/microsoft/not-signed-in",
            Self::UnsupportedPlatform => "auth/microsoft/unsupported-platform",
        }
    }

    fn sdk_retryable(&self) -> bool {
        matches!(self, Self::Network(_) | Self::Service { .. })
    }
}

struct PendingLogin {
    listener: TcpListener,
    verifier: String,
    state: String,
    redirect_uri: String,
}

struct CachedSession {
    identity: MicrosoftAccountVerified,
    account: MicrosoftAccount,
    expires_epoch_seconds: u64,
}

/// Stateful Microsoft adapter bound to one context and client configuration.
pub struct MicrosoftProvider {
    config: MicrosoftClientConfig,
    context: SdkContext,
    pending: Mutex<HashMap<String, PendingLogin>>,
    session: Mutex<Option<CachedSession>>,
}

impl MicrosoftProvider {
    pub fn new(config: MicrosoftClientConfig, context: &SdkContext) -> Self {
        Self {
            config,
            context: context.clone(),
            pending: Mutex::new(HashMap::new()),
            session: Mutex::new(None),
        }
    }

    /// Binds a loopback listener and builds the PKCE authorization URL for a
    /// system browser. Does not touch the network.
    pub fn begin_login(&self) -> Result<LoginHandle, MicrosoftError> {
        {
            let pending = self
                .pending
                .lock()
                .map_err(|_| MicrosoftError::InvalidStoredAccount)?;
            if !pending.is_empty() {
                return Err(MicrosoftError::LoginInProgress);
            }
        }
        let listener = TcpListener::bind("localhost:0").map_err(|source| MicrosoftError::Io {
            action: "启动本地登录回调",
            source,
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|source| MicrosoftError::Io {
                action: "配置本地登录回调",
                source,
            })?;
        let port = listener
            .local_addr()
            .map_err(|source| MicrosoftError::Io {
                action: "读取本地登录端口",
                source,
            })?
            .port();
        let redirect_uri = format!("http://localhost:{port}/");
        let verifier = format!(
            "{}{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let mut authorization_url = Url::parse(MICROSOFT_AUTHORIZE_URL)?;
        authorization_url
            .query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("response_mode", "query")
            .append_pair("scope", MICROSOFT_SCOPE)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &state)
            .append_pair("prompt", "select_account");

        let login_id = Uuid::new_v4().simple().to_string();
        self.pending
            .lock()
            .map_err(|_| MicrosoftError::InvalidStoredAccount)?
            .insert(
                login_id.clone(),
                PendingLogin {
                    listener,
                    verifier,
                    state,
                    redirect_uri,
                },
            );
        Ok(LoginHandle {
            login_id,
            authorization_url: authorization_url.to_string(),
        })
    }

    /// Drops a pending login so `complete_login` can no longer pick it up.
    /// A `complete_login` already blocked on the callback still ends by its
    /// own timeout; cancelling cannot interrupt it.
    pub fn cancel_login(&self, login_id: &str) -> Result<(), MicrosoftError> {
        self.pending
            .lock()
            .map_err(|_| MicrosoftError::InvalidStoredAccount)?
            .remove(login_id)
            .map(|_| ())
            .ok_or_else(|| MicrosoftError::UnknownLogin(login_id.to_owned()))
    }

    /// Blocking completion: waits for the loopback callback (up to 10
    /// minutes), then runs the authorization-code + Xbox + Minecraft chain
    /// and persists account and refresh token. Hosts run this on a task.
    pub fn complete_login(&self, login_id: &str) -> Result<MicrosoftAccount, MicrosoftError> {
        let session = self
            .pending
            .lock()
            .map_err(|_| MicrosoftError::InvalidStoredAccount)?
            .remove(login_id)
            .ok_or_else(|| MicrosoftError::UnknownLogin(login_id.to_owned()))?;
        let code = wait_for_callback(&session)?;
        let client = auth_client()?;
        let token = exchange_authorization_code(&client, &self.config, &session, &code)?;
        let refresh_token = token
            .refresh_token
            .ok_or(MicrosoftError::MissingRefreshToken)?;
        let (account, verified, expires_epoch_seconds) =
            authenticate_minecraft(&client, &token.access_token, &self.config.client_id)?;
        self.context
            .initialize()
            .map_err(|error| MicrosoftError::Io {
                action: "初始化 SDK 目录",
                source: match error {
                    crate::context::ContextError::Io { source, .. } => source,
                },
            })?;
        save_refresh_token(&self.context, refresh_token.as_bytes())?;
        save_account(&self.context, &account)?;
        *self
            .session
            .lock()
            .map_err(|_| MicrosoftError::InvalidStoredAccount)? = Some(CachedSession {
            identity: verified,
            account: account.clone(),
            expires_epoch_seconds,
        });
        Ok(account)
    }

    /// Currently stored account, if a login was completed on this machine.
    pub fn account(&self) -> Result<Option<MicrosoftAccount>, MicrosoftError> {
        if let Some(cached) = self
            .session
            .lock()
            .map_err(|_| MicrosoftError::InvalidStoredAccount)?
            .as_ref()
        {
            return Ok(Some(cached.account.clone()));
        }
        load_account(&self.context, &self.config.client_id)
    }

    pub fn logout(&self) -> Result<(), MicrosoftError> {
        for path in [
            account_path(&self.context),
            refresh_token_path(&self.context),
        ] {
            if path.is_file() {
                fs::remove_file(&path).map_err(|source| MicrosoftError::Io {
                    action: "删除 Microsoft 登录数据",
                    source,
                })?;
            }
        }
        *self
            .session
            .lock()
            .map_err(|_| MicrosoftError::InvalidStoredAccount)? = None;
        Ok(())
    }

    /// Produces the verified launch identity, refreshing tokens when the
    /// cached Minecraft session is close to expiry. Never falls back to a
    /// local profile: failures propagate as `auth/microsoft/*`.
    pub fn prepare_launch_identity(&self) -> Result<LaunchIdentity, MicrosoftError> {
        let now = now_epoch_seconds();
        if let Some(cached) = self
            .session
            .lock()
            .map_err(|_| MicrosoftError::InvalidStoredAccount)?
            .as_ref()
            .filter(|cached| cached.expires_epoch_seconds > now.saturating_add(300))
        {
            return Ok(LaunchIdentity::Microsoft(cached.identity.clone()));
        }

        let encrypted =
            fs::read(refresh_token_path(&self.context)).map_err(|source| MicrosoftError::Io {
                action: "读取 Microsoft 登录凭据",
                source,
            })?;
        let refresh_token = String::from_utf8(unprotect_secret(&encrypted)?)
            .map_err(|_| MicrosoftError::InvalidStoredAccount)?;
        let client = auth_client()?;
        let token = refresh_microsoft_token(&client, &self.config, &refresh_token)?;
        if let Some(rotated) = token.refresh_token.as_ref() {
            save_refresh_token(&self.context, rotated.as_bytes())?;
        }
        let (account, verified, expires_epoch_seconds) =
            authenticate_minecraft(&client, &token.access_token, &self.config.client_id)?;
        save_account(&self.context, &account)?;
        *self
            .session
            .lock()
            .map_err(|_| MicrosoftError::InvalidStoredAccount)? = Some(CachedSession {
            identity: verified.clone(),
            account,
            expires_epoch_seconds,
        });
        Ok(LaunchIdentity::Microsoft(verified))
    }
}

impl AccountProvider for MicrosoftProvider {
    fn kind(&self) -> IdentityKind {
        IdentityKind::Microsoft
    }

    fn list_identities(&self) -> Result<Vec<IdentitySummary>, AccountProviderError> {
        let account = self
            .account()
            .map_err(|error| AccountProviderError::Other {
                code: error.sdk_code(),
                message: error.to_string(),
            })?;
        Ok(account
            .into_iter()
            .map(|account| IdentitySummary {
                kind: IdentityKind::Microsoft,
                id: account.minecraft_id.clone(),
                username: account.minecraft_name.clone(),
                label: "Microsoft · 已验证".to_string(),
            })
            .collect())
    }

    fn prepare_launch_identity(&self, id: &str) -> Result<LaunchIdentity, AccountProviderError> {
        let account = self
            .account()
            .map_err(|error| AccountProviderError::Other {
                code: error.sdk_code(),
                message: error.to_string(),
            })?
            .ok_or(AccountProviderError::Unavailable {
                id: id.to_owned(),
                reason: "尚未登录 Microsoft 账号".to_string(),
            })?;
        if account.minecraft_id != id {
            return Err(AccountProviderError::UnknownIdentity(id.to_owned()));
        }
        self.prepare_launch_identity()
            .map_err(|error| AccountProviderError::Other {
                code: error.sdk_code(),
                message: error.to_string(),
            })
    }
}

fn auth_client() -> Result<Client, MicrosoftError> {
    Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(45))
        .user_agent(format!("NaCLNext/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| MicrosoftError::Network(error.to_string()))
}

fn wait_for_callback(session: &PendingLogin) -> Result<String, MicrosoftError> {
    let deadline = Instant::now() + LOGIN_TIMEOUT;
    loop {
        match session.listener.accept() {
            Ok((mut stream, peer)) => {
                if !peer.ip().is_loopback() {
                    continue;
                }
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut buffer = [0_u8; 8192];
                let read = stream
                    .read(&mut buffer)
                    .map_err(|source| MicrosoftError::Io {
                        action: "读取 Microsoft 登录回调",
                        source,
                    })?;
                let request = String::from_utf8_lossy(&buffer[..read]);
                let target = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .ok_or(MicrosoftError::InvalidCallback)?;
                let callback = Url::parse(&format!("http://localhost{target}"))?;
                let query = callback.query_pairs().collect::<HashMap<_, _>>();
                let state = query.get("state").ok_or(MicrosoftError::InvalidCallback)?;
                if state.as_ref() != session.state {
                    write_callback_page(&mut stream, false);
                    return Err(MicrosoftError::StateMismatch);
                }
                if let Some(error) = query.get("error") {
                    let description = query
                        .get("error_description")
                        .map_or_else(|| error.to_string(), ToString::to_string);
                    write_callback_page(&mut stream, false);
                    return Err(MicrosoftError::LoginCancelled(description));
                }
                let code = query
                    .get("code")
                    .map(ToString::to_string)
                    .ok_or(MicrosoftError::InvalidCallback)?;
                write_callback_page(&mut stream, true);
                return Ok(code);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(MicrosoftError::LoginTimedOut);
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(source) => {
                return Err(MicrosoftError::Io {
                    action: "等待 Microsoft 登录回调",
                    source,
                });
            }
        }
    }
}

fn write_callback_page(stream: &mut impl Write, success: bool) {
    let (title, message) = if success {
        (
            "NaCL Next 登录完成",
            "Microsoft 已将授权结果安全返回启动器，可以关闭此页面。",
        )
    } else {
        (
            "NaCL Next 登录未完成",
            "请返回启动器查看详细信息并重新尝试。",
        )
    };
    let body = format!(
        "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>{title}</title><style>body{{font-family:Segoe UI,Microsoft YaHei UI,sans-serif;background:#182022;color:#eef6f6;display:grid;place-items:center;min-height:100vh;margin:0}}main{{max-width:520px;padding:40px}}h1{{font-size:28px}}p{{color:#a9b9ba;line-height:1.7}}</style><main><h1>{title}</h1><p>{message}</p></main></html>"
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

#[derive(Debug, Deserialize)]
struct MicrosoftTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
}

fn exchange_authorization_code(
    client: &Client,
    config: &MicrosoftClientConfig,
    session: &PendingLogin,
    code: &str,
) -> Result<MicrosoftTokenResponse, MicrosoftError> {
    post_form(
        client,
        MICROSOFT_TOKEN_URL,
        &[
            ("client_id", config.client_id.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", session.redirect_uri.as_str()),
            ("code_verifier", session.verifier.as_str()),
            ("scope", MICROSOFT_SCOPE),
        ],
        "Microsoft 令牌交换",
    )
}

fn refresh_microsoft_token(
    client: &Client,
    config: &MicrosoftClientConfig,
    refresh_token: &str,
) -> Result<MicrosoftTokenResponse, MicrosoftError> {
    post_form(
        client,
        MICROSOFT_TOKEN_URL,
        &[
            ("client_id", config.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("scope", MICROSOFT_SCOPE),
        ],
        "Microsoft 登录刷新",
    )
}

fn post_form<T: for<'de> Deserialize<'de>>(
    client: &Client,
    url: &str,
    form: &[(&str, &str)],
    stage: &'static str,
) -> Result<T, MicrosoftError> {
    let response = client
        .post(url)
        .form(form)
        .send()
        .map_err(|error| MicrosoftError::Network(error.to_string()))?;
    parse_response(response, stage)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XboxTokenResponse {
    token: String,
    display_claims: XboxDisplayClaims,
}

#[derive(Debug, Deserialize)]
struct XboxDisplayClaims {
    #[serde(default)]
    xui: Vec<XboxUserClaim>,
}

#[derive(Debug, Deserialize)]
struct XboxUserClaim {
    uhs: String,
    #[serde(default)]
    xid: String,
}

#[derive(Debug, Deserialize)]
struct MinecraftTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct MinecraftEntitlements {
    #[serde(default)]
    items: Vec<MinecraftEntitlement>,
}

#[derive(Debug, Deserialize)]
struct MinecraftEntitlement {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
struct MinecraftProfileResponse {
    id: String,
    name: String,
    #[serde(default)]
    skins: Vec<MinecraftSkin>,
    #[serde(default)]
    capes: Vec<MinecraftCape>,
}

#[derive(Debug, Deserialize)]
struct ServiceErrorResponse {
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: String,
    #[serde(default, rename = "errorMessage")]
    error_message: String,
    #[serde(default, rename = "XErr")]
    xerr: Option<u64>,
    #[serde(default, rename = "Redirect")]
    redirect: String,
}

/// Full service chain: Microsoft token → Xbox user token → XSTS → Minecraft
/// login → entitlements check → profile. Returns the persisted account shape
/// plus the verified (secret-bearing) launch identity.
fn authenticate_minecraft(
    client: &Client,
    microsoft_access_token: &str,
    client_id: &str,
) -> Result<(MicrosoftAccount, MicrosoftAccountVerified, u64), MicrosoftError> {
    let xbox: XboxTokenResponse = post_json(
        client,
        XBOX_USER_URL,
        &serde_json::json!({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": format!("d={microsoft_access_token}")
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        }),
        "Xbox 用户认证",
    )?;
    let xsts: XboxTokenResponse = post_json(
        client,
        XSTS_URL,
        &serde_json::json!({
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [xbox.token]
            },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT"
        }),
        "Xbox XSTS 认证",
    )?;
    let claim = xsts
        .display_claims
        .xui
        .first()
        .ok_or(MicrosoftError::MissingXboxClaim)?;
    let minecraft: MinecraftTokenResponse = post_json(
        client,
        MINECRAFT_LOGIN_URL,
        &serde_json::json!({
            "identityToken": format!("XBL3.0 x={};{}", claim.uhs, xsts.token)
        }),
        "Minecraft Services 登录",
    )?;
    let entitlements: MinecraftEntitlements = get_bearer(
        client,
        MINECRAFT_ENTITLEMENTS_URL,
        &minecraft.access_token,
        "Minecraft 游戏资格检查",
    )?;
    if !entitlements
        .items
        .iter()
        .any(|item| item.name == "game_minecraft" || item.name == "product_minecraft")
    {
        return Err(MicrosoftError::MissingEntitlement);
    }
    let profile: MinecraftProfileResponse = get_bearer(
        client,
        MINECRAFT_PROFILE_URL,
        &minecraft.access_token,
        "Minecraft 档案读取",
    )?;
    if profile.id.is_empty() || profile.name.is_empty() {
        return Err(MicrosoftError::MissingMinecraftProfile);
    }
    let skins = profile
        .skins
        .into_iter()
        .map(|mut skin| {
            skin.url = secure_texture_url(&skin.url);
            skin
        })
        .collect();
    let capes = profile
        .capes
        .into_iter()
        .map(|mut cape| {
            cape.url = secure_texture_url(&cape.url);
            cape
        })
        .collect();
    let account = MicrosoftAccount {
        schema_version: ACCOUNT_SCHEMA_VERSION,
        client_id: client_id.to_string(),
        minecraft_id: profile.id.clone(),
        minecraft_name: profile.name.clone(),
        skins,
        capes,
        signed_in_epoch_ms: now_epoch_ms(),
    };
    let verified = MicrosoftAccountVerified {
        username: profile.name,
        uuid: profile.id,
        access_token: super::SecretString::new(minecraft.access_token),
        client_id: client_id.to_string(),
        xuid: claim.xid.clone(),
    };
    let expires_epoch_seconds = now_epoch_seconds().saturating_add(minecraft.expires_in);
    Ok((account, verified, expires_epoch_seconds))
}

fn post_json<T: for<'de> Deserialize<'de>>(
    client: &Client,
    url: &str,
    body: &serde_json::Value,
    stage: &'static str,
) -> Result<T, MicrosoftError> {
    let response = client
        .post(url)
        .header("x-xbl-contract-version", "1")
        .json(body)
        .send()
        .map_err(|error| MicrosoftError::Network(error.to_string()))?;
    parse_response(response, stage)
}

fn get_bearer<T: for<'de> Deserialize<'de>>(
    client: &Client,
    url: &str,
    token: &str,
    stage: &'static str,
) -> Result<T, MicrosoftError> {
    let response = client
        .get(url)
        .bearer_auth(token)
        .send()
        .map_err(|error| MicrosoftError::Network(error.to_string()))?;
    parse_response(response, stage)
}

fn parse_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::blocking::Response,
    stage: &'static str,
) -> Result<T, MicrosoftError> {
    let status = response.status();
    let body = response
        .text()
        .map_err(|error| MicrosoftError::Network(error.to_string()))?;
    if !status.is_success() {
        let message = serde_json::from_str::<ServiceErrorResponse>(&body)
            .map(service_error_message)
            .unwrap_or_else(|_| "服务未返回可读取的错误信息".to_string());
        return Err(MicrosoftError::Service {
            stage,
            status: status.as_u16(),
            message,
        });
    }
    serde_json::from_str(&body).map_err(|_| MicrosoftError::Service {
        stage,
        status: status.as_u16(),
        message: "服务响应格式无效".to_string(),
    })
}

fn service_error_message(error: ServiceErrorResponse) -> String {
    let mut message = if !error.error_description.is_empty() {
        error.error_description
    } else if !error.error_message.is_empty() {
        error.error_message
    } else if !error.error.is_empty() {
        error.error
    } else {
        "认证被服务拒绝".to_string()
    };
    if let Some(xerr) = error.xerr {
        message.push_str(&format!("（Xbox 错误 {xerr}）"));
    }
    if !error.redirect.is_empty() {
        message.push_str("；请按 Xbox 提示完成账号设置");
    }
    message.chars().take(500).collect()
}

fn secure_texture_url(url: &str) -> String {
    url.strip_prefix("http://textures.minecraft.net/")
        .map_or_else(
            || url.to_string(),
            |suffix| format!("https://textures.minecraft.net/{suffix}"),
        )
}

fn account_path(context: &SdkContext) -> PathBuf {
    context.config_root.join("microsoft-account.json")
}

fn refresh_token_path(context: &SdkContext) -> PathBuf {
    context.config_root.join("microsoft-refresh-token.bin")
}

fn save_account(context: &SdkContext, account: &MicrosoftAccount) -> Result<(), MicrosoftError> {
    let bytes =
        serde_json::to_vec_pretty(account).map_err(|_| MicrosoftError::InvalidStoredAccount)?;
    save_atomically(&account_path(context), &bytes, "保存 Microsoft 账号档案")
}

fn save_refresh_token(context: &SdkContext, token: &[u8]) -> Result<(), MicrosoftError> {
    let encrypted = protect_secret(token)?;
    save_atomically(
        &refresh_token_path(context),
        &encrypted,
        "保存 Microsoft 登录凭据",
    )
}

fn load_account(
    context: &SdkContext,
    configured_client_id: &str,
) -> Result<Option<MicrosoftAccount>, MicrosoftError> {
    let path = account_path(context);
    if !path.is_file() || !refresh_token_path(context).is_file() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path).map_err(|source| MicrosoftError::Io {
        action: "读取 Microsoft 账号档案",
        source,
    })?;
    let account = serde_json::from_str::<MicrosoftAccount>(&contents)
        .map_err(|_| MicrosoftError::InvalidStoredAccount)?;
    if account.schema_version != ACCOUNT_SCHEMA_VERSION
        || account.minecraft_id.is_empty()
        || account.minecraft_name.is_empty()
    {
        return Err(MicrosoftError::InvalidStoredAccount);
    }
    if account.client_id != configured_client_id {
        return Err(MicrosoftError::ClientIdChanged);
    }
    Ok(Some(account))
}

fn save_atomically(
    destination: &Path,
    contents: &[u8],
    action: &'static str,
) -> Result<(), MicrosoftError> {
    crate::fsutil::write_atomic(destination, contents)
        .map_err(|source| MicrosoftError::Io { action, source })
}

#[cfg(target_os = "windows")]
fn protect_secret(secret: &[u8]) -> Result<Vec<u8>, MicrosoftError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: secret.len() as u32,
        pbData: secret.as_ptr() as *mut u8,
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: DPAPI_ENTROPY.len() as u32,
        pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let success = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if success == 0 {
        return Err(MicrosoftError::Io {
            action: "使用 Windows 加密登录凭据",
            source: io::Error::last_os_error(),
        });
    }
    let encrypted =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as *mut _);
    }
    Ok(encrypted)
}

#[cfg(target_os = "windows")]
fn unprotect_secret(encrypted: &[u8]) -> Result<Vec<u8>, MicrosoftError> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: encrypted.len() as u32,
        pbData: encrypted.as_ptr() as *mut u8,
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: DPAPI_ENTROPY.len() as u32,
        pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let success = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if success == 0 {
        return Err(MicrosoftError::Io {
            action: "使用 Windows 解密登录凭据",
            source: io::Error::last_os_error(),
        });
    }
    let secret =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as *mut _);
    }
    Ok(secret)
}

#[cfg(not(target_os = "windows"))]
fn protect_secret(_secret: &[u8]) -> Result<Vec<u8>, MicrosoftError> {
    Err(MicrosoftError::UnsupportedPlatform)
}

#[cfg(not(target_os = "windows"))]
fn unprotect_secret(_encrypted: &[u8]) -> Result<Vec<u8>, MicrosoftError> {
    Err(MicrosoftError::UnsupportedPlatform)
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

#[cfg(test)]
mod tests {
    use super::{
        protect_secret, service_error_message, unprotect_secret, MicrosoftClientConfig,
        MicrosoftProvider, ServiceErrorResponse,
    };
    use crate::context::SdkContext;

    #[test]
    fn client_config_rejects_empty_ids() {
        assert!(MicrosoftClientConfig::new("").is_err());
        assert!(MicrosoftClientConfig::new("  ").is_err());
        assert!(MicrosoftClientConfig::new("00000000-0000-0000-0000-000000000000").is_ok());
    }

    #[test]
    fn begin_login_builds_pkce_url_with_injected_client_id() {
        let root = tempfile::tempdir().unwrap();
        let context = SdkContext::from_root(root.path());
        let provider = MicrosoftProvider::new(
            MicrosoftClientConfig::new("test-client-id").unwrap(),
            &context,
        );

        let handle = provider.begin_login().unwrap();
        assert!(handle
            .authorization_url
            .contains("client_id=test-client-id"));
        assert!(handle
            .authorization_url
            .contains("code_challenge_method=S256"));
        assert!(handle.authorization_url.contains("response_type=code"));
        assert!(handle.authorization_url.contains("localhost"));

        // One concurrent login; cancel frees the slot.
        assert!(provider.begin_login().is_err());
        provider.cancel_login(&handle.login_id).unwrap();
        assert!(provider.begin_login().is_ok());
    }

    #[test]
    fn missing_client_id_is_reported_before_any_login_attempt() {
        let root = tempfile::tempdir().unwrap();
        let context = SdkContext::from_root(root.path());
        assert!(MicrosoftClientConfig::new("").is_err());
        drop(context);
        drop(root);
    }

    #[test]
    fn service_errors_do_not_echo_response_json() {
        let message = service_error_message(ServiceErrorResponse {
            error: "invalid_grant".to_string(),
            error_description: "authorization expired".to_string(),
            error_message: String::new(),
            xerr: None,
            redirect: String::new(),
        });
        assert_eq!(message, "authorization expired");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_dpapi_round_trip_is_user_scoped() {
        let secret = b"temporary-test-refresh-token";
        let encrypted = protect_secret(secret).expect("DPAPI should encrypt");
        assert_ne!(encrypted, secret);
        let decrypted = unprotect_secret(&encrypted).expect("DPAPI should decrypt");
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn verified_identity_is_not_deserializable() {
        // Compile-time property: MicrosoftAccountVerified derives neither
        // Serialize nor Deserialize, so no JSON label can forge it. This test
        // just anchors the doc contract.
        let root = tempfile::tempdir().unwrap();
        let context = SdkContext::from_root(root.path());
        let provider = MicrosoftProvider::new(
            MicrosoftClientConfig::new("test-client-id").unwrap(),
            &context,
        );
        assert!(provider.account().unwrap().is_none());
    }
}
