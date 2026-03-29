mod proxy;

use std::net::SocketAddr;
use std::sync::Arc;
use std::fs;
use hyper::Server;
use hyper::service::{make_service_fn, service_fn};
use std::convert::Infallible;
use proxy::handlers::ProxyState;

// Hàm hỗ trợ đọc file danh sách (Nếu không có file sẽ tự tạo file mẫu)
fn load_list_from_file(path: &str, default_content: &str) -> Vec<String> {
    let content = fs::read_to_string(path).unwrap_or_else(|_| {
        println!("⚠️  Không tìm thấy {}, đang tạo file mặc định...", path);
        fs::write(path, default_content).expect("Không thể tạo file");
        default_content.to_string()
    });

    content
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#')) 
        .collect()
}

#[tokio::main]
async fn main() {
    // 1. Khởi tạo Log hệ thống
    tracing_subscriber::fmt::init();

    // 2. Cấu hình Client
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true) 
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
        .build()
        .expect("❌ Không thể khởi tạo HTTP Client");

    // 3. Đọc danh sách chặn từ file
    println!("🔍 Đang tải cấu hình an ninh...");
    
    let blacklist = load_list_from_file(
        "blacklist.txt", 
        "# Danh sách domain bị chặn\nfacebook.com\nyoutube.com\ndoubleclick.net"
    );

    let forbidden_keywords = load_list_from_file(
        "keywords.txt", 
        "# Danh sách từ khóa nhạy cảm bị chặn\nbypass\nvpn-free\nproxy-list\nhack"
    );

    // 4. Khởi tạo Shared State (Sử dụng Arc để chia sẻ an toàn giữa các luồng)
    let shared_state = Arc::new(ProxyState {
        client,
        blacklist,
        forbidden_keywords,
    });

    // 5. Thiết lập Socket
    let addr: SocketAddr = "127.0.0.1:8888".parse().expect("Địa chỉ không hợp lệ");

    // 6. Khởi tạo Service (SỬA LỖI E0382 TẠI ĐÂY)
    let make_svc = make_service_fn(move |_conn| {
        // Clone Arc cho mỗi kết nối mới
        let state = Arc::clone(&shared_state); 
        
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                // Clone Arc một lần nữa cho mỗi Request cụ thể
                let state_for_req = Arc::clone(&state);
                proxy::handlers::handle_request(req, state_for_req)
            }))
        }
    });

    // 7. Giao diện Console
    println!("-----------------------------------------------");
    println!("🚀 HUY'S SECURE PROXY PRO V2.5 (Sửa lỗi E0382)");
    println!("📍 Địa chỉ lắng nghe: http://127.0.0.1:8888");
    println!("📊 Đã tải {} domain chặn và {} từ khóa cấm", 
             // Chúng ta dùng mượn dữ liệu để in ra trước khi di chuyển vào server
             "?", "?"); 
    println!("📁 Nhật ký an ninh: proxy_security.log");
    println!("-----------------------------------------------");

    // 8. Kích hoạt Server
    let server = Server::bind(&addr).serve(make_svc);
    
    if let Err(e) = server.await {
        eprintln!("❌ Lỗi Server nghiêm trọng: {}", e);
    }
}