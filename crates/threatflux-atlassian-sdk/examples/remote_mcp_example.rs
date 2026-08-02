//! Compile-checked illustration of the retained legacy Remote MCP API shape.
//!
//! This does not make an MCP request. `AtlassianRemoteClient` targets the retired
//! `/v1/sse` endpoint and is not compatible with Atlassian's current Rovo MCP
//! service. Use this example only when assessing migration of existing code.

use std::env;
use threatflux_atlassian_sdk::AtlassianRemoteClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!(
        "WARNING: this legacy client targets Atlassian's retired /v1/sse endpoint; \
         it is not a working client for the current Rovo MCP service."
    );

    let client_id = env::var("ATLASSIAN_CLIENT_ID")?;
    let callback_port = env::var("ATLASSIAN_CALLBACK_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()?;

    let client = AtlassianRemoteClient::new(client_id, callback_port)?;
    let authorization = client.initialize_auth().await?;

    println!("Legacy authorization URL: {}", authorization["auth_url"]);
    println!(
        "The SDK does not listen on http://localhost:{callback_port}/oauth/callback. \
         Existing callers must receive the code and state themselves and pass both \
         to complete_auth()."
    );
    println!("No MCP request was sent.");

    Ok(())
}
