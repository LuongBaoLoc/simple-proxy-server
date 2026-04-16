use hyper::{Body, Request, Response, StatusCode, header};
use hyper::upgrade::Upgraded;
use regex::RegexSet;
use tokio::sync::mpsc::UnboundedSender;
use tokio::net::TcpStream;
use reqwest::Client;
use std::convert::Infallible;
use std::sync::Arc;
use futures_util::StreamExt;
use chrono::Local;
pub struct ProxyState {
    pub client: Client,
    pub blacklist: RegexSet,
    pub forbidden_keywords: RegexSet,
    pub log_sender: UnboundedSender<String>,
}

// 1. HÀM GHI NHẬT KÝ (LOGGING SYSTEM) - Chuyển sang Async mpsc
fn send_log(sender: &UnboundedSender<String>, method: &str, url: &str, status: &str) {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    // Format log đẹp mắt để dễ theo dõi trong file .log
    let log_entry = format!("[{}] | {:<7} | {:<50} | Status: {}\n", now, method, url, status);
    
    // Bỏ qua lỗi nếu receiver đã đóng (tức là proxy đang tắt)
    let _ = sender.send(log_entry);
}

pub async fn handle_request(req: Request<Body>, state: Arc<ProxyState>) -> Result<Response<Body>, Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    // 2. CHUẨN HÓA URL & CHỐNG VÒNG LẶP
    let mut url_str = uri.to_string();
    
    // Kiểm tra vòng lặp
    if url_str.contains("127.0.0.1:8888") || url_str.contains("localhost:8888") {
        send_log(&state.log_sender, method.as_str(), &url_str, "400 LOOP DETECTED");
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("🚫 Loop Detected: Proxy cannot call itself!"))
            .unwrap());
    }
    
    // Bổ sung http:// nếu thiếu
    if !url_str.starts_with("http") && method != hyper::Method::CONNECT {
        if let Some(host) = req.headers().get(header::HOST) {
            if let Ok(host_str) = host.to_str() {
                url_str = format!("http://{}{}", host_str, url_str);
            }
        }
    }

    // 3. XỬ LÝ HTTPS (TUNNELING)
    if method == hyper::Method::CONNECT {
        if let Some(addr) = uri.authority().map(|a| a.to_string()) {
            println!("🔌 Establishing Tunnel: {}", addr);
            send_log(&state.log_sender, "CONNECT", &addr, "200 TUNNEL ESTABLISHED");
            
            tokio::task::spawn(async move {
                if let Ok(upgraded) = hyper::upgrade::on(req).await {
                    let _ = tunnel(upgraded, addr).await;
                }
            });
            return Ok(Response::new(Body::empty()));
        }
    }

    // 4. BỘ LỌC TỪ KHÓA (KEYWORD FILTERING) - Lấy từ state thay vì vec cố định
    if state.forbidden_keywords.is_match(&url_str.to_lowercase()) {
        println!("⚠️ Blocked by Keyword Filter");
        send_log(&state.log_sender, method.as_str(), &url_str, "403 KEYWORD BLOCKED");
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("🚫 Access Denied: URL contains forbidden keyword"))
            .unwrap());
    }

    // 5. BỘ LỌC TÊN MIỀN (DOMAIN BLACKLIST)
    if state.blacklist.is_match(&url_str) {
        println!("🚫 Blocked by Domain Filter");
        send_log(&state.log_sender, method.as_str(), &url_str, "403 DOMAIN BLOCKED");
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("🚫 Access Denied by Huy's Secure Proxy"))
            .unwrap());
    }

    println!("🚀 Forwarding: {} {}", method, url_str);

    // 6. CHUYỂN TIẾP & GIẢ MẠO USER-AGENT (SPOOFING)
    let mut forward_req = state.client.request(method.clone(), &url_str);
    
    // Ghi đè User-Agent để ẩn danh người dùng theo chuẩn bảo mật
    forward_req = forward_req.header("User-Agent", "HuySecureProxy/2.0 (CyberSecurity Project; Anonymous Mode)");

    for (key, value) in req.headers() {
        match key.as_str() {
            "host" | "proxy-connection" | "connection" | "user-agent" | "te" | "trailer" | "upgrade" => continue,
            _ => { forward_req = forward_req.header(key, value); }
        }
    }

    match forward_req.body(req.into_body()).send().await {
        Ok(res) => {
            let status = res.status().as_u16();
            send_log(&state.log_sender, method.as_str(), &url_str, &status.to_string());
            
            let mut resp_builder = Response::builder().status(status);
            if let Some(headers) = resp_builder.headers_mut() {
                for (k, v) in res.headers() {
                    headers.insert(k, v.clone());
                }
            }

            let stream = res.bytes_stream().map(|r| {
                r.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            });
            
            Ok(resp_builder.body(Body::wrap_stream(stream)).unwrap())
        }
        Err(e) => {
            send_log(&state.log_sender, method.as_str(), &url_str, &format!("502 ERROR: {}", e));
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("🚫 Gateway Error: Connection failed"))
                .unwrap())
        }
    }
}

async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    let target_addr = if addr.contains(':') { addr } else { format!("{}:443", addr) };
    let server = TcpStream::connect(target_addr).await?;
    let (mut cr, mut cw) = tokio::io::split(upgraded);
    let (mut sr, mut sw) = tokio::io::split(server);

    let _ = tokio::select! {
        res = tokio::io::copy(&mut cr, &mut sw) => res,
        res = tokio::io::copy(&mut sr, &mut cw) => res,
    };
    Ok(())
}