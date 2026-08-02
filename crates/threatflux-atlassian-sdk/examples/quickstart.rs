use threatflux_atlassian_sdk::AtlassianClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = AtlassianClient::from_env()?;
    let issue = client.get_issue("KAN-123").await?;
    println!("{}: {}", issue.key, issue.fields.summary);
    Ok(())
}
