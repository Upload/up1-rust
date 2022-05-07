use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ContentLengthLimit, Multipart, Query},
    http::StatusCode,
    response::Redirect,
    routing::{get, get_service, post},
    Extension, Json, Router, Server,
};
use camino::{Utf8Path, Utf8PathBuf};
use clap::Parser;
use config_file::FromConfigFile;
use hmac_sha256::HMAC;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};
use tower_http::services::ServeDir;
use tracing::{debug, info, trace};

#[derive(Parser, Debug)]
struct Args {
    /// Location of config file, must end in .json
    #[clap(short, long, default_value = "./server.json")]
    config: Utf8PathBuf,
}

#[derive(Deserialize, Debug)]
struct Config {
    api_key: String,
    delete_key: String,

    listen: String,

    images: Utf8PathBuf,
    client: Utf8PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let cfg: Arc<Config> =
        Arc::new(Config::from_config_file(args.config).expect("Could not parse config"));

    let addr: SocketAddr = cfg.listen.parse().expect("Could not parse listen value");
    let app = Router::new()
        .route("/up", post(upload))
        .route("/del", get(delete))
        .nest(
            "/i",
            get_service(ServeDir::new(&cfg.images))
                .handle_error(|_| async move { (StatusCode::INTERNAL_SERVER_ERROR, "") }),
        )
        .fallback(
            get_service(
                ServeDir::new(&cfg.client)
                    .precompressed_gzip()
                    .precompressed_br(),
            )
            .handle_error(|_| async move { (StatusCode::INTERNAL_SERVER_ERROR, "") }),
        )
        .layer(Extension(cfg));

    info!("Listening on {addr}");
    Server::bind(&addr)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap()
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
enum UploadResp {
    Ok { delkey: String },
    Err { error: String, code: usize },
}

const UP1_HEADER: &[u8] = b"UP1\0";
async fn upload(
    Extension(cfg): Extension<Arc<Config>>,
    ContentLengthLimit(mut multipart): ContentLengthLimit<Multipart, 50_000_000>,
) -> Json<UploadResp> {
    let mut api_key = String::new();
    let mut ident = String::new();

    let (tmp, tmp_path) = NamedTempFile::new_in(&cfg.images).unwrap().keep().unwrap();
    let mut tmp = File::from_std(tmp);
    tmp.write_all(UP1_HEADER).await.unwrap();

    while let Some(mut field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap();
        if name == "api_key" {
            api_key = field.text().await.unwrap();
        } else if name == "ident" {
            ident = field.text().await.unwrap();
        } else if name == "file" {
            while let Some(chunk) = field.chunk().await.unwrap() {
                tmp.write_all(&chunk).await.unwrap();
            }
        } else {
            fs::remove_file(tmp_path).await.unwrap();
            panic!("Unexpected field name {name}");
        }
    }

    if api_key != cfg.api_key {
        debug!(
            "Attempted to upload '{ident}' but got API key {api_key}, expected {}",
            cfg.api_key
        );
        fs::remove_file(tmp_path).await.unwrap();
        Json(UploadResp::Err {
            error: "API key doesn't match".to_string(),
            code: 2,
        })
    } else {
        let ident_file = Utf8Path::new(&ident);
        let ident_path = cfg.images.join(ident_file.file_name().unwrap());
        fs::rename(tmp_path, ident_path).await.unwrap();

        let delkey = hex::encode(HMAC::mac(&cfg.delete_key, ident_file.as_str()));
        trace!("Uploaded '{ident}' ok, delkey is {delkey}");
        Json(UploadResp::Ok { delkey })
    }
}

#[derive(Deserialize, Debug)]
struct DeleteQueryParams {
    ident: String,
    delkey: String,
}

async fn delete(
    Extension(cfg): Extension<Arc<Config>>,
    Query(params): Query<DeleteQueryParams>,
) -> Redirect {
    let ident = Utf8Path::new(&params.ident);
    let delkey = hex::encode(HMAC::mac(&cfg.delete_key, ident.as_str()));
    if delkey == params.delkey {
        let ident_path = cfg.images.join(ident);
        trace!(
            "Delete from {} with {} ok",
            ident_path.as_str(),
            params.delkey
        );
        fs::remove_file(ident_path).await.unwrap();
    } else {
        debug!(
            "Delete from {ident} with {} failed, expected key {delkey}",
            params.delkey
        );
    }
    Redirect::to("/")
}
