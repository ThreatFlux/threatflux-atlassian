use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    threatflux_atlassian_action::run_from_env().await?;
    Ok(())
}
