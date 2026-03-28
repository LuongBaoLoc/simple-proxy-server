use std::net::SocketAddr;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server};

async fn handle_request(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    // 1. Logging: In ra yêu cầu mà Proxy nhận được
    println!(">>> Nhận yêu cầu: {} {}", req.method(), req.uri());

    // 2. Chuyển tiếp yêu cầu tới server đích (Forwarding)
    let client = Client::new();
    let resp = client.request(req).await?;

    // 3. Trả phản hồi về cho Client ban đầu
    Ok(resp)
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

    let make_svc = make_service_fn(|_conn: &AddrStream| async {
        Ok::<_, hyper::Error>(service_fn(handle_request))
    });

    let server = Server::bind(&addr).serve(make_svc);

    println!("HTTP Proxy đang chạy tại http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("Lỗi Server: {}", e);
    }
}