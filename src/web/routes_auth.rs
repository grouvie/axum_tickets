use crate::web::mw_auth::{ set_private_cookie, remove_private_cookie };
use crate::{ Error, Result };
use axum::routing::{ get, post };
use axum::{ Json, Router };
use chrono::Utc;
use serde::Deserialize;
use serde_json::{ json, Value };
use tower_cookies::Cookies;

pub fn routes() -> Router {
    Router::new().route("/api/login", post(login)).route("/api/logout", get(logout))
}

async fn login(cookies: Cookies, payload: Json<LoginPayload>) -> Result<Json<Value>> {
    println!("->> {:<12} - api_login", "HANDLER");

    // TODO: Implement real db/auth logic.
    if payload.username != "grouvie" || payload.password != "password" {
        return Err(Error::LoginFail);
    }

    let user_id = 1;

    let timestamp = Utc::now().timestamp();

    let token = format!("user-{}.{}", user_id, timestamp);

    set_private_cookie(cookies, token)?;

    let body = Json(json!({
      "result": {
        "success": true
      }
	  }));

    Ok(body)
}

async fn logout(cookies: Cookies) -> Result<Json<Value>> {
    println!("->> {:<12} - logout", "HANDLER");

    remove_private_cookie(cookies)?;

    let body = Json(json!({
      "result": {
        "success": true
      }
	  }));

    Ok(body)
}

#[derive(Debug, Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}
