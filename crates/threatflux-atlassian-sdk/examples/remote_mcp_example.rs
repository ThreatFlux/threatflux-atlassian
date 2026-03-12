#![allow(clippy::all, clippy::pedantic, clippy::nursery)]

use threatflux_atlassian_sdk::AtlassianRemoteClient;

/// Example demonstrating Atlassian Remote MCP Server with OAuth 2.1 authentication
/// This shows the complete flow including auth screen within MCP for user approval
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Atlassian Remote MCP Server Example");
    println!("===================================\n");

    // Get OAuth client ID from environment
    let client_id = std::env::var("ATLASSIAN_CLIENT_ID").unwrap_or_else(|_| {
        println!("⚠️  ATLASSIAN_CLIENT_ID not set, using example client ID");
        "example-oauth-client-id".to_string()
    });

    let callback_port = std::env::var("ATLASSIAN_CALLBACK_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);

    println!("🔧 Configuration:");
    println!(
        "   Client ID: {}",
        if client_id.starts_with("example") {
            "⚠️  Using example client ID - set ATLASSIAN_CLIENT_ID for real usage"
        } else {
            &client_id
        }
    );
    println!("   Callback Port: {}", callback_port);

    // Create Remote MCP client
    let client = match AtlassianRemoteClient::new(client_id, callback_port) {
        Ok(client) => {
            println!("✅ Atlassian Remote MCP client created");
            client
        }
        Err(e) => {
            println!("❌ Failed to create Remote MCP client: {}", e);
            return Ok(());
        }
    };

    // Check authentication status
    println!("\n🔐 Authentication Status:");
    if client.is_authenticated().await {
        println!("✅ Already authenticated with Atlassian");
    } else {
        println!("🔓 Not authenticated - starting OAuth 2.1 flow");

        // Initialize OAuth authentication flow
        match client.initialize_auth().await {
            Ok(auth_response) => {
                println!("\n🚀 OAuth 2.1 Authorization Required:");
                println!("=====================================");

                if let Some(auth_url) = auth_response.get("auth_url") {
                    println!("🔗 Authorization URL: {}", auth_url);
                }

                if let Some(instructions) = auth_response.get("instructions") {
                    println!("\n📋 Instructions:");
                    if let Some(steps) = instructions.as_array() {
                        for (i, step) in steps.iter().enumerate() {
                            if let Some(step_text) = step.as_str() {
                                println!("   {}. {}", i + 1, step_text);
                            }
                        }
                    }
                }

                if let Some(scopes) = auth_response.get("scopes") {
                    println!("\n🔐 Requested Permissions:");
                    if let Some(scope_array) = scopes.as_array() {
                        for scope in scope_array {
                            if let Some(scope_text) = scope.as_str() {
                                println!("   • {}", scope_text);
                            }
                        }
                    }
                }

                println!("\n⚠️  OAuth Flow Required:");
                println!("   In a real implementation, this would:");
                println!("   1. Present the auth URL to the user within the MCP interface");
                println!(
                    "   2. Start a local callback server on port {}",
                    callback_port
                );
                println!("   3. Wait for the OAuth callback with authorization code");
                println!("   4. Exchange the code for access tokens");
                println!("   5. Store tokens for subsequent API calls");

                println!("\n🔄 Simulated OAuth Completion:");
                println!("   (In real usage, this would come from the OAuth callback)");

                // Simulate OAuth completion for demonstration
                // In real usage, this would be triggered by the OAuth callback
                println!("   ⏳ Waiting for OAuth completion...");
                println!("   ✅ OAuth flow would complete here with real auth code");
            }
            Err(e) => {
                println!("❌ Failed to initialize auth: {}", e);
                return Ok(());
            }
        }
    }

    // Demonstrate MCP operations (these would work after OAuth completion)
    println!("\n📋 Available Operations via Remote MCP Server:");
    println!("==============================================");

    // List MCP tools available from Atlassian
    println!("1️⃣ Listing available MCP tools...");
    match client.list_tools().await {
        Ok(tools) => {
            println!("✅ Remote MCP Server provides {} tools:", tools.len());
            for (i, tool) in tools.iter().take(5).enumerate() {
                if let Some(name) = tool.get("name") {
                    println!("   {}. {}", i + 1, name);
                }
            }
            if tools.len() > 5 {
                println!("   ... and {} more tools", tools.len() - 5);
            }
        }
        Err(e) => {
            println!("⚠️  Could not list tools (authentication needed): {}", e);
        }
    }

    // Jira Operations
    println!("\n2️⃣ Jira Operations via Remote MCP:");
    println!("   🎫 Get Issue: client.get_issue(\"TMP-123\")");
    println!("   📊 Update Story Points: client.update_story_points(\"TMP-123\", 8.0, \"customfield_10100\")");
    println!("   🔍 Search Issues: client.search_issues(\"project = TMP\", 50)");
    println!("   ✨ Create Issue: client.create_issue(\"New task\", \"TMP\", \"Task\")");

    // Confluence Operations
    println!("\n3️⃣ Confluence Operations via Remote MCP:");
    println!("   📖 Get Page: client.confluence_operation(\"get_page\", params)");
    println!("   ✍️  Create Page: client.confluence_operation(\"create_page\", params)");
    println!("   🔍 Search Content: client.confluence_operation(\"search\", params)");

    // Compass Operations
    println!("\n4️⃣ Compass Operations via Remote MCP:");
    println!("   🧭 Get Components: client.compass_operation(\"list_components\", params)");
    println!("   🏗️  Create Component: client.compass_operation(\"create_component\", params)");
    println!("   🔗 Get Dependencies: client.compass_operation(\"get_dependencies\", params)");

    // Security and Permissions
    println!("\n🔒 Security Features:");
    println!("   ✅ OAuth 2.1 with PKCE for enhanced security");
    println!("   ✅ Respects existing Atlassian Cloud permissions");
    println!("   ✅ Encrypted HTTPS communication (TLS 1.2+)");
    println!("   ✅ Session-based tokens with automatic expiration");
    println!("   ✅ CSRF protection with state parameters");

    // Rate Limiting
    println!("\n⏱️  Rate Limits (Beta):");
    println!("   • Standard Plan: Moderate usage thresholds");
    println!("   • Premium/Enterprise: 1,000 requests/hour + per-user limits");

    // Supported Clients
    println!("\n🛠️  Supported Integration Clients:");
    println!("   • Claude (Desktop, Teams, Code)");
    println!("   • Cursor (AI-first code editor)");
    println!("   • VS Code (via mcp-remote CLI)");
    println!("   • Google Vertex AI");
    println!("   • GitHub Copilot");
    println!("   • Microsoft Copilot (365/Azure OpenAI)");
    println!("   • HubSpot");
    println!("   • Zapier (coming soon)");

    println!("\n🎯 Key Advantages of Remote MCP Server:");
    println!("   1. 🔐 No API token management - OAuth handles everything");
    println!("   2. 🛡️  Permission-aware - only access what user can already see");
    println!("   3. 🌍 Cross-product - Jira, Confluence, Compass in one connection");
    println!("   4. 🔄 Always up-to-date - Atlassian manages the server");
    println!("   5. 📈 Scalable - Built for enterprise usage patterns");
    println!("   6. 🚀 Future-proof - New features automatically available");

    println!("\n📚 Example Workflows:");
    println!("   • \"Find all open bugs in Project Alpha\" (Jira search)");
    println!("   • \"Create a story titled 'Redesign onboarding'\" (Jira create)");
    println!("   • \"Summarize the Q2 planning page\" (Confluence read)");
    println!("   • \"What depends on the api-gateway service?\" (Compass query)");
    println!("   • \"Link these Jira tickets to the Release Plan page\" (Cross-product)");

    println!("\n🏁 Remote MCP Integration Complete!");
    println!("Ready for OAuth authentication and Atlassian operations.");

    Ok(())
}
