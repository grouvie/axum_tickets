use std::env;
use std::sync::LazyLock;

use crate::ctx::Ctx;
use crate::model::model_controller::ModelController;
use crate::web::AUTH_TOKEN;
use crate::{ Error, Result };
use async_trait::async_trait;
use axum::extract::{ FromRequestParts, State };
use axum::http::request::Parts;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use chrono::Utc;
use lazy_regex::regex_captures;
use tower_cookies::cookie::time::Duration;
use tower_cookies::{ Cookie, Cookies, Key };

static MY_KEY: LazyLock<String> = LazyLock::new(|| {
    env::var("SECRET_KEY").expect("No SECRET_KEY for cookie encryption provided.")
});

pub(crate) async fn mw_require_auth<B>(
    ctx: Result<Ctx>,
    req: Request<B>,
    next: Next<B>
) -> Result<Response> {
    println!("->> {:<12} - mw_require_auth - {ctx:?}", "MIDDLEWARE");

    ctx?;

    Ok(next.run(req).await)
}

pub(crate) async fn mw_ctx_resolver<B>(
    _mc: State<ModelController>,
    cookies: Cookies,
    mut req: Request<B>,
    next: Next<B>
) -> Result<Response> {
    println!("->> {:<12} - mw_ctx_resolver", "MIDDLEWARE");

    let key = Key::from(MY_KEY.as_bytes());
    let private_cookies = cookies.private(&key);

    let auth_token = private_cookies.get(AUTH_TOKEN).map(|c| c.value().to_string());

    // Compute Result<Ctx>.
    let result_ctx = match auth_token.ok_or(Error::AuthFailNoAuthTokenCookie).and_then(parse_token) {
        Ok((user_id, exp)) => {
            timestamp_is_valid(&exp).and_then(|_| {
                let timestamp = Utc::now().timestamp();
                let token = format!("user-{}.{}", user_id, timestamp);
                set_private_cookie(cookies.clone(), token)?;
                Ok(Ctx::new(user_id))
            })
        }
        Err(e) => Err(e),
    };

    // Remove the cookie if something went wrong other than NoAuthTokenCookie.
    if result_ctx.is_err() && !matches!(result_ctx, Err(Error::AuthFailNoAuthTokenCookie)) {
        cookies.remove(Cookie::named(AUTH_TOKEN));
    }

    // Store the ctx_result in the request extension.
    req.extensions_mut().insert(result_ctx);

    Ok(next.run(req).await)
}

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for Ctx {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self> {
        println!("->> {:<12} - Ctx", "EXTRACTOR");

        parts.extensions.get::<Result<Ctx>>().ok_or(Error::AuthFailCtxNotInRequestExt)?.clone()
    }
}

/// Parse a token of format `user-[user-id].[expiration]`
/// Returns (user_id, expiration)
fn parse_token(token: String) -> Result<(usize, String)> {
    let (_whole, user_id, exp) = regex_captures!(
        r#"^user-(\d+)\.(.+)"#, // a literal regex
        &token
    ).ok_or(Error::AuthFailTokenWrongFormat)?;

    let user_id: usize = user_id.parse().map_err(|_| Error::AuthFailTokenWrongFormat)?;

    Ok((user_id, exp.to_string()))
}

pub(crate) fn set_private_cookie(cookies: Cookies, token: String) -> Result<()> {
    let key = &Key::from(MY_KEY.as_bytes());

    let private_cookies = cookies.private(key);

    let mut cookie = Cookie::new(AUTH_TOKEN, token);
    cookie.set_path("/");
    // TODO: Set cookie to secure before deployment
    cookie.set_secure(false);
    cookie.set_http_only(true);
    cookie.set_max_age(Duration::hours(1));

    private_cookies.add(cookie);
    Ok(())
}

pub(crate) fn remove_private_cookie(cookies: Cookies) -> Result<()> {
    let key = &Key::from(MY_KEY.as_bytes());

    let private_cookies = cookies.private(key);
    let mut cookie = Cookie::new(AUTH_TOKEN, "");
    cookie.set_path("/");

    private_cookies.remove(cookie);

    Ok(())
}

fn timestamp_is_valid(exp: &str) -> Result<()> {
    // Parse the timestamp string as an integer
    let timestamp = match exp.parse::<i64>() {
        Ok(timestamp) => timestamp,
        Err(_) => {
            return Err(Error::AuthFailInvalidTimestamp);
        }
    };
    let current_timestamp = Utc::now().timestamp();

    let difference = current_timestamp - timestamp;

    // Check if the difference is greater than 1 hour (3600 seconds)
    if difference < 3600 {
        Ok(())
    } else {
        Err(Error::AuthFailExpiredTokenCookie)
    }
}
