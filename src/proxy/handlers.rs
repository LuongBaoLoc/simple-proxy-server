use hyper::{Body, Request, Response, StatusCode, header};
use hyper::upgrade::Upgraded;
use tokio::net::TcpStream;
use reqwest::Client;
use std::convert::Infallible;
use std::sync::Arc;
use futures_util::StreamExt;
use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;

pub struct ProxyState {
    pub client: Client,
    pub blacklist: Vec<String>,
    pub forbidden_keywords: Vec<String>,
}

// 1. HÀM GHI NHẬT KÝ (LOGGING SYSTEM)
fn log_to_file(method: &str, url: &str, status: &str) {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    // Format log đẹp mắt để dễ theo dõi trong file .log
    let log_entry = format!("[{}] | {:<7} | {:<50} | Status: {}\n", now, method, url, status);
    
    let file_result = OpenOptions::new()
        .create(true)
        .append(true)
        .open("proxy_security.log");

    if let Ok(mut file) = file_result {
        let _ = file.write_all(log_entry.as_bytes());
    }
}

pub async fn handle_request(req: Request<Body>, state: Arc<ProxyState>) -> Result<Response<Body>, Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    // 2. CHUẨN HÓA URL & CHỐNG VÒNG LẶP
    let mut url_str = uri.to_string();
    
    // Kiểm tra vòng lặp
    if url_str.contains("127.0.0.1:8888") || url_str.contains("localhost:8888") {
        log_to_file(method.as_str(), &url_str, "400 LOOP DETECTED");
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
            log_to_file("CONNECT", &addr, "200 TUNNEL ESTABLISHED");
            
            tokio::task::spawn(async move {
                if let Ok(upgraded) = hyper::upgrade::on(req).await {
                    let _ = tunnel(upgraded, addr).await;
                }
            });
            return Ok(Response::new(Body::empty()));
        }
    }

    // 4. BỘ LỌC TỪ KHÓA (KEYWORD FILTERING) - Lấy từ state thay vì vec cố định
    for word in &state.forbidden_keywords {
        if url_str.to_lowercase().contains(&word.to_lowercase()) {
            println!("⚠️ Blocked by Keyword: {}", word);
            log_to_file(method.as_str(), &url_str, "403 KEYWORD BLOCKED");
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(format!("🚫 Access Denied: URL contains forbidden keyword '{}'", word)))
                .unwrap());
        }
    }

    // 5. BỘ LỌC TÊN MIỀN (DOMAIN BLACKLIST)
    for domain in &state.blacklist {
        if url_str.contains(domain) {
            println!("🚫 Blocked by Domain: {}", domain);
            log_to_file(method.as_str(), &url_str, "403 DOMAIN BLOCKED");
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("🚫 Access Denied by Huy's Secure Proxy"))
                .unwrap());
        }
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
            log_to_file(method.as_str(), &url_str, &status.to_string());
            
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
            log_to_file(method.as_str(), &url_str, &format!("502 ERROR: {}", e));
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