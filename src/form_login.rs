//! Form-based login — detect login forms, submit credentials, capture session.
//!
//! Discovers login forms by crawling the target, identifies username/password
//! fields, submits credentials, and captures the resulting session cookie
//! for authenticated scanning.

use reqwest::Client;
use scraper::{Html, Selector};
use tracing::info;

#[derive(Debug, Clone)]
pub struct LoginResult {
    pub success: bool,
    pub cookies: String,
    pub redirect_url: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug)]
struct LoginForm {
    action: String,
    method: String,
    username_field: String,
    password_field: String,
    extra_fields: Vec<(String, String)>,
}

/// Attempt form-based login. Discovers the login form, submits credentials,
/// returns session cookies on success.
pub async fn form_login(
    client: &Client,
    target: &str,
    username: &str,
    password: &str,
    login_url: Option<&str>,
) -> LoginResult {
    // Step 1: Find the login page
    let login_page = if let Some(url) = login_url {
        url.to_string()
    } else {
        match discover_login_page(client, target).await {
            Some(url) => url,
            None => {
                return LoginResult {
                    success: false,
                    cookies: String::new(),
                    redirect_url: None,
                    error: Some("No login page found".into()),
                };
            }
        }
    };

    info!("Login page: {login_page}");

    // Step 2: Fetch the login page and parse the form
    let form = match parse_login_form(client, &login_page).await {
        Some(f) => f,
        None => {
            return LoginResult {
                success: false,
                cookies: String::new(),
                redirect_url: None,
                error: Some("Cannot parse login form".into()),
            };
        }
    };

    info!(
        "Form: action={} method={} user_field={} pass_field={}",
        form.action, form.method, form.username_field, form.password_field
    );

    // Step 3: Build and submit the form
    let action_url = if form.action.starts_with("http") {
        form.action.clone()
    } else if form.action.starts_with('/') {
        let base = url::Url::parse(&login_page).unwrap();
        format!("{}://{}{}", base.scheme(), base.host_str().unwrap_or(""), form.action)
    } else {
        format!("{}/{}", login_page.trim_end_matches('/'), form.action)
    };

    let mut params = vec![
        (form.username_field.clone(), username.to_string()),
        (form.password_field.clone(), password.to_string()),
    ];
    params.extend(form.extra_fields.iter().cloned());

    let resp = if form.method.eq_ignore_ascii_case("POST") {
        client.post(&action_url).form(&params).send().await
    } else {
        client.get(&action_url).query(&params).send().await
    };

    match resp {
        Ok(r) => {
            let status = r.status();
            let final_url = r.url().to_string();
            let headers = r.headers().clone();

            // Collect cookies from Set-Cookie headers
            let cookies: Vec<String> = headers
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(|v| {
                    // Extract just name=value
                    v.split(';').next().unwrap_or("").to_string()
                })
                .filter(|c| !c.is_empty())
                .collect();

            let cookie_str = cookies.join("; ");

            // Determine success:
            // - 302/301 redirect (common after login)
            // - Got session cookies
            // - Didn't redirect back to login page
            let is_redirect = status.is_redirection() || final_url != action_url;
            let got_cookies = !cookies.is_empty();
            let not_login_redirect = !final_url.contains("login") && !final_url.contains("signin");

            let success = got_cookies && (is_redirect || not_login_redirect || status.is_success());

            LoginResult {
                success,
                cookies: cookie_str,
                redirect_url: if final_url != action_url {
                    Some(final_url)
                } else {
                    None
                },
                error: if !success {
                    Some(format!("Login returned HTTP {} — may have failed", status))
                } else {
                    None
                },
            }
        }
        Err(e) => LoginResult {
            success: false,
            cookies: String::new(),
            redirect_url: None,
            error: Some(format!("Request failed: {e}")),
        },
    }
}

/// Try common login page paths.
async fn discover_login_page(client: &Client, target: &str) -> Option<String> {
    let paths = [
        "/login",
        "/signin",
        "/auth/login",
        "/accounts/login",
        "/user/login",
        "/admin/login",
        "/wp-login.php",
        "/Account/Login",
    ];

    for path in &paths {
        let url = format!("{}{}", target.trim_end_matches('/'), path);
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                let body = resp.text().await.unwrap_or_default();
                if body.to_lowercase().contains("password") {
                    return Some(url);
                }
            }
        }
    }
    None
}

/// Parse a login form from HTML — find username + password fields.
async fn parse_login_form(client: &Client, url: &str) -> Option<LoginForm> {
    let resp = client.get(url).send().await.ok()?;
    let body = resp.text().await.ok()?;
    let doc = Html::parse_document(&body);

    let form_sel = Selector::parse("form").ok()?;
    let input_sel = Selector::parse("input").ok()?;

    for form_el in doc.select(&form_sel) {
        let mut username_field = None;
        let mut password_field = None;
        let mut extra_fields = Vec::new();

        for input in form_el.select(&input_sel) {
            let input_type = input.value().attr("type").unwrap_or("text").to_lowercase();
            let name = input.value().attr("name").unwrap_or("").to_string();
            let value = input.value().attr("value").unwrap_or("").to_string();

            if name.is_empty() {
                continue;
            }

            match input_type.as_str() {
                "password" => {
                    password_field = Some(name);
                }
                "email" | "text" => {
                    let name_lower = name.to_lowercase();
                    if username_field.is_none()
                        && (name_lower.contains("user")
                            || name_lower.contains("email")
                            || name_lower.contains("login")
                            || name_lower.contains("name")
                            || name_lower == "j_username"
                            || name_lower == "uid")
                    {
                        username_field = Some(name);
                    }
                }
                "hidden" => {
                    // Capture CSRF tokens and hidden fields
                    extra_fields.push((name, value));
                }
                _ => {}
            }
        }

        if let (Some(user_field), Some(pass_field)) = (username_field, password_field) {
            let action = form_el
                .value()
                .attr("action")
                .unwrap_or("")
                .to_string();
            let method = form_el
                .value()
                .attr("method")
                .unwrap_or("POST")
                .to_string();

            return Some(LoginForm {
                action: if action.is_empty() { url.to_string() } else { action },
                method,
                username_field: user_field,
                password_field: pass_field,
                extra_fields,
            });
        }
    }

    None
}
