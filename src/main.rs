use std::{net::SocketAddr, sync::Arc};

use anyhow::{bail, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Multipart, Query},
    handler::Handler,
    http::StatusCode,
    response::Redirect,
    routing::{get, post},
    Extension, Json, Router, ServiceExt,
};
use camino::{Utf8Path, Utf8PathBuf};
use clap::Parser;
use config_file::FromConfigFile;
use hmac_sha256::HMAC;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
    net::TcpListener,
};
use tower_http::{services::ServeDir, trace::TraceLayer};
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
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let cfg: Arc<Config> =
        Arc::new(Config::from_config_file(args.config).context("Could not parse config")?);

    let addr: SocketAddr = cfg.listen.parse().context("Could not parse listen value")?;
    let app = Router::new()
        .route(
            "/up",
            post(upload.layer(DefaultBodyLimit::max(300_000_000))),
        )
        .route("/del", get(delete))
        .nest_service("/i", ServeDir::new(&cfg.images))
        .fallback_service(
            ServeDir::new(&cfg.client)
                .precompressed_gzip()
                .precompressed_br(),
        )
        .layer(Extension(cfg));

    info!("Listening on {addr}");
    let listener = TcpListener::bind(addr)
        .await
        .context("Could not listen on {addr}")?;
    axum::serve(listener, app.layer(TraceLayer::new_for_http()))
        .await
        .context("Could not serve HTTP")?;

    Ok(())
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
enum UploadResp {
    Ok { delkey: String },
    Err { error: String, code: usize },
}

#[derive(Error, Debug)]
pub enum APIError {
    #[error("API key does not match, got: {api_key}")]
    APIKeyNoMatch { api_key: String },
    #[error("Unexpected field name: {field_name}")]
    UnexpectedFieldName { field_name: String },
    #[error("Missing field: {field_name}")]
    MissingField { field_name: String },
}

async fn try_upload(
    mut file: File,
    mut multipart: Multipart,
    expected_api_key: &String,
) -> Result<String> {
    let mut maybe_api_key: Option<String> = None;
    let mut maybe_ident: Option<String> = None;

    file.write_all(UP1_HEADER).await?;

    while let Some(mut field) = multipart.next_field().await? {
        match field.name().unwrap().to_string().as_str() {
            "api_key" => maybe_api_key = Some(field.text().await?),
            "ident" => maybe_ident = Some(field.text().await?),
            "file" => {
                while let Some(chunk) = field.chunk().await? {
                    // If the file field is missing it just writes an 0 byte file without error
                    file.write_all(&chunk).await.unwrap();
                }
            }
            name => bail!(APIError::UnexpectedFieldName {
                field_name: name.into()
            }),
        }
    }

    let api_key = match maybe_api_key {
        Some(api_key) => api_key,
        None => bail!(APIError::MissingField {
            field_name: "api_key".into()
        }),
    };

    let ident = match maybe_ident {
        Some(ident) => ident,
        None => bail!(APIError::MissingField {
            field_name: "ident".into()
        }),
    };
    if !api_key.eq(expected_api_key) {
        debug!(
            "Attempted to upload '{ident}' but got API key {api_key}, expected {}",
            expected_api_key
        );
        bail!(APIError::APIKeyNoMatch { api_key });
    }

    Ok(ident)
}

const UP1_HEADER: &[u8] = b"UP1\0";
async fn upload(Extension(cfg): Extension<Arc<Config>>, multipart: Multipart) -> Json<UploadResp> {
    let (tmp, tmp_path) = NamedTempFile::new_in(&cfg.images).unwrap().keep().unwrap();
    match try_upload(File::from_std(tmp), multipart, &cfg.api_key).await {
        Ok(ident) => {
            let ident_file = Utf8Path::new(&ident);
            let ident_path = cfg.images.join(ident_file.file_name().unwrap());
            fs::rename(tmp_path, ident_path).await.unwrap();

            let delkey = hex::encode(HMAC::mac(&cfg.delete_key, ident_file.as_str()));
            trace!("Uploaded '{ident}' ok, delkey is {delkey}");
            Json(UploadResp::Ok { delkey })
        }
        Err(err) => {
            fs::remove_file(tmp_path).await.unwrap();
            match err.downcast_ref::<APIError>() {
                Some(APIError::APIKeyNoMatch { api_key: _ }) => todo!(),
                Some(APIError::UnexpectedFieldName { field_name: _ }) => todo!(),
                Some(APIError::MissingField { field_name: _ }) => todo!(),
                None => Json(UploadResp::Err {
                    error: todo!(),
                    code: todo!(),
                }),
            }
        }
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
