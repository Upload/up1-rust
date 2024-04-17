use std::{net::SocketAddr, sync::Arc};

use anyhow::{bail, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Multipart, Query},
    handler::Handler,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Json, Router,
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
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::{debug, info, trace};

#[derive(Parser, Debug)]
struct Args {
    /// Location of config file, must end in .json
    #[clap(short, long, default_value = "./server.json")]
    server_config: Utf8PathBuf,

    /// Location of client config file
    #[clap(short, long, default_value = "./client/config.js")]
    client_config: Utf8PathBuf,
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
        Arc::new(Config::from_config_file(args.server_config).context("Could not parse config")?);

    let addr: SocketAddr = cfg.listen.parse().context("Could not parse listen value")?;
    let app = Router::new()
        .route(
            "/up",
            post(upload.layer(DefaultBodyLimit::max(300_000_000))),
        )
        .route("/del", get(delete))
        .route_service(
            "/config.js",
            ServeFile::new_with_mime(args.client_config, &mime::APPLICATION_JAVASCRIPT),
        )
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
    #[error("Bad delete key: {delete_key}")]
    BadDeleteKey { delete_key: String },
    #[error("Bad ident length: {length}")]
    BadIdentLen { length: usize },
    #[error("Ident already exists: {ident}")]
    AlreadyExists { ident: String },
}

impl APIError {
    fn to_upload_err(&self) -> UploadResp {
        match self {
            APIError::APIKeyNoMatch { api_key } => UploadResp::Err {
                error: format!("API key '{api_key}' doesn't match"),
                code: 2,
            },
            APIError::UnexpectedFieldName { field_name } => UploadResp::Err {
                error: format!("Unexpected field '{field_name}'"),
                code: 11,
            },
            APIError::MissingField { field_name } => UploadResp::Err {
                error: format!("Missing field '{field_name}'"),
                code: 12,
            },
            APIError::BadIdentLen { length } => UploadResp::Err {
                error: format!("Bad ident len: {length}"),
                code: 3,
            },
            APIError::AlreadyExists { ident } => UploadResp::Err {
                error: format!("Ident '{ident}' already exists"),
                code: 4,
            },
            APIError::BadDeleteKey { delete_key } => UploadResp::Err {
                error: format!("Bad delete key '{delete_key}'"),
                code: 10,
            },
        }
    }
}

impl IntoResponse for &APIError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self.to_upload_err())).into_response()
    }
}

async fn try_upload(
    mut file: File,
    mut multipart: Multipart,
    cfg: &Config,
) -> Result<(String, String)> {
    let mut maybe_api_key: Option<String> = None;
    let mut maybe_ident: Option<String> = None;

    file.write_all(UP1_HEADER).await?;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .context("Getting next multipart field")?
    {
        match field.name().unwrap().to_string().as_str() {
            "api_key" => {
                maybe_api_key = Some(
                    field
                        .text()
                        .await
                        .context("Getting API key from multipart")?,
                )
            }
            "ident" => {
                maybe_ident = Some(field.text().await.context("Getting ident from multipart")?)
            }
            "file" => {
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .context("Getting file chunk from multipart")?
                {
                    // If the file field is missing it just writes an 0 byte file without error
                    file.write_all(&chunk)
                        .await
                        .context("Writing file from multipart")?;
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

    if !api_key.eq(&cfg.api_key) {
        debug!(
            "Attempted to upload '{ident}' but got API key {api_key}, expected {}",
            cfg.api_key
        );
        bail!(APIError::APIKeyNoMatch { api_key });
    }

    if ident.len() != 22 {
        debug!("Attempted to upload {ident}, but length was incorrect");
        bail!(APIError::BadIdentLen {
            length: ident.len()
        });
    }

    if cfg.images.join(&ident).exists() {
        debug!("Attempted to upload {ident}, but that ident already exists");
        bail!(APIError::AlreadyExists { ident });
    }

    let delkey = hex::encode(HMAC::mac(&cfg.delete_key, &ident));
    trace!("Uploaded '{ident}' ok, delkey is {delkey}");

    Ok((ident, delkey))
}

const UP1_HEADER: &[u8] = b"UP1\0";
async fn upload(Extension(cfg): Extension<Arc<Config>>, multipart: Multipart) -> Response {
    let (tmp, tmp_path) = NamedTempFile::new_in(&cfg.images).unwrap().keep().unwrap();
    match try_upload(File::from_std(tmp), multipart, &cfg).await {
        Ok((ident, delkey)) => {
            let ident_file = Utf8Path::new(&ident);

            let ident_path = cfg.images.join(ident_file.file_name().unwrap());
            fs::rename(tmp_path, ident_path).await.unwrap();

            Json(UploadResp::Ok { delkey }).into_response()
        }
        Err(err) => {
            fs::remove_file(tmp_path).await.unwrap();
            err.downcast_ref::<APIError>()
                .map(|x| x.into_response())
                .unwrap_or_else(|| {
                    info!("Unknown error occurred: '{}' '{:?}'", err, err);
                    Json(UploadResp::Err {
                        error: format!("Unknown error: '{err}'"),
                        code: 99,
                    })
                    .into_response()
                })
        }
    }
}

#[derive(Deserialize, Debug)]
struct DeleteQueryParams {
    ident: String,
    delkey: String,
}

async fn try_delete(cfg: &Config, ident: &str, delete_key: &str) -> Result<()> {
    if ident.len() != 22 {
        debug!("Attempted to upload {ident}, but length was incorrect");
        bail!(APIError::BadIdentLen {
            length: ident.len(),
        });
    }

    let expected_delete_key = hex::encode(HMAC::mac(&cfg.delete_key, ident));
    if delete_key != expected_delete_key {
        debug!(
            "Delete from {ident} with {delete_key} failed, expected key {}",
            cfg.delete_key
        );
        bail!(APIError::BadDeleteKey {
            delete_key: delete_key.to_string()
        });
    }

    let ident_path = cfg.images.join(ident);
    trace!("Delete from {ident_path} with {delete_key} ok");
    fs::remove_file(ident_path).await.unwrap();

    Ok(())
}

async fn delete(
    Extension(cfg): Extension<Arc<Config>>,
    Query(params): Query<DeleteQueryParams>,
) -> Response {
    match try_delete(&cfg, &params.ident, &params.delkey).await {
        Ok(_) => Redirect::to("/").into_response(),
        Err(err) => err
            .downcast_ref::<APIError>()
            .map(|x| x.into_response())
            .unwrap_or_else(|| {
                info!("Unknown error occurred: '{}' '{:?}'", err, err);
                Json(UploadResp::Err {
                    error: format!("Unknown error: '{err}'"),
                    code: 99,
                })
                .into_response()
            }),
    }
}
