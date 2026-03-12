#![allow(clippy::all, clippy::pedantic, clippy::nursery)]

use std::collections::HashMap;
use threatflux_atlassian_sdk::{
    AtlassianClient, CreateIssueFields, CreateIssueRequest, IssueTypeReference, ProjectReference,
    UserReference,
};

/// Example demonstrating Atlassian SDK Jira operations
/// Based on the Python examples for ticket creation and updates
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Atlassian SDK Jira Example");
    println!("===========================\n");

    // Create client from environment variables
    // Expects: JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN
    let client = match AtlassianClient::from_env() {
        Ok(client) => client,
        Err(e) => {
            println!("❌ Failed to create client: {e}");
            println!("Make sure these environment variables are set:");
            println!("  JIRA_URL=https://company.atlassian.net");
            println!("  JIRA_USERNAME=user@company.com");
            println!("  JIRA_API_TOKEN=your-api-token");
            return Ok(());
        }
    };

    // Example 1: Health check and authentication test
    println!("1. Testing Jira connectivity and authentication...");
    match client.health_check().await {
        Ok(_) => println!("✅ Jira connection successful"),
        Err(e) => {
            println!("❌ Health check failed: {e}");
            return Ok(());
        }
    }

    // Example 2: Get current user (like Python's myself() call)
    println!("\n2. Getting current user information...");
    match client.get_myself().await {
        Ok(user) => {
            println!("✅ Current user: {}", user.display_name.unwrap_or_default());
            if let Some(account_id) = &user.account_id {
                println!("   Account ID: {account_id}");
            }
        }
        Err(e) => println!("❌ Error getting user info: {e}"),
    }

    // Example 3: Get available projects
    println!("\n3. Getting accessible projects...");
    match client.get_projects().await {
        Ok(projects) => {
            println!("✅ Found {} projects:", projects.len());
            for project in projects.iter().take(3) {
                println!(
                    "   • {} ({}) - {}",
                    project.name,
                    project.key,
                    project.description.as_deref().unwrap_or("No description")
                );
            }
            if projects.len() > 3 {
                println!("   ... and {} more", projects.len() - 3);
            }
        }
        Err(e) => println!("❌ Error getting projects: {e}"),
    }

    // Example 4: Get custom fields (like Python field discovery)
    println!("\n4. Finding custom field IDs...");
    let field_names = ["Story Points", "Improvement Area", "Complexity"];
    for field_name in &field_names {
        match client.find_custom_field_id(field_name).await {
            Ok(Some(field_id)) => println!("✅ {field_name}: {field_id}"),
            Ok(None) => println!("⚠️  {field_name}: Not found"),
            Err(e) => println!("❌ Error finding {field_name}: {e}"),
        }
    }

    // Example 5: Search for issues in a project (like Python JQL queries)
    println!("\n5. Searching for recent issues...");
    let jql = "created >= -7d ORDER BY created DESC";
    match client.search_issues(jql, 0, 5).await {
        Ok(results) => {
            println!("✅ Found {} total issues (showing top 5):", results.total);
            for issue in &results.issues {
                println!(
                    "   • {} - {} ({})",
                    issue.key, issue.fields.summary, issue.fields.status.name
                );
            }
        }
        Err(e) => println!("❌ Error searching issues: {e}"),
    }

    // Example 6: Get specific issue (like Python get_issue)
    println!("\n6. Getting specific issue details...");
    // Use the first issue from search results if available
    if let Ok(results) = client.search_issues("ORDER BY created DESC", 0, 1).await {
        if let Some(issue) = results.issues.first() {
            let issue_key = &issue.key;
            println!("Getting details for issue: {issue_key}");

            match client.get_issue(issue_key).await {
                Ok(detailed_issue) => {
                    println!("✅ Issue details:");
                    println!("   Key: {}", detailed_issue.key);
                    println!("   Summary: {}", detailed_issue.fields.summary);
                    println!("   Type: {}", detailed_issue.fields.issue_type.name);
                    println!("   Status: {}", detailed_issue.fields.status.name);
                    if let Some(assignee) = &detailed_issue.fields.assignee {
                        println!(
                            "   Assignee: {}",
                            assignee.display_name.as_deref().unwrap_or("Unknown")
                        );
                    }
                    if let Some(created) = &detailed_issue.fields.created {
                        println!("   Created: {created}");
                    }
                }
                Err(e) => println!("❌ Error getting issue details: {e}"),
            }
        } else {
            println!("⚠️  No issues found to demonstrate with");
        }
    }

    // Example 7: Update issue (like Python update operations)
    println!("\n7. Demonstrating issue update (dry run)...");
    println!("   Example: Update story points for an issue");
    println!("   Code: client.update_story_points(\"PROJ-123\", 8.0, \"customfield_10100\")");
    println!("   Example: Update custom field");
    println!(
        "   Code: client.update_custom_field(\"PROJ-123\", \"customfield_11024\", \"Security\")"
    );
    println!("   (Not executed to avoid modifying real issues)");

    // Example 8: Create issue (like Python create operations)
    println!("\n8. Demonstrating issue creation (dry run)...");
    println!("   Example: Create a new task");

    let example_create_request = CreateIssueRequest {
        fields: CreateIssueFields {
            project: ProjectReference::by_key("TMP"),
            summary: "Example security task".to_string(),
            issue_type: IssueTypeReference::by_name("Task"),
            description: Some("Example task created via Rust SDK".to_string()),
            assignee: Some(UserReference::by_account_id("example-account-id")),
            priority: None,
            labels: Some(vec!["automation".to_string(), "security".to_string()]),
            components: None,
            parent: None,
            custom_fields: {
                let mut fields = HashMap::new();
                fields.insert(
                    "customfield_11024".to_string(), // Improvement Area
                    serde_json::json!({"value": "Security"}),
                );
                fields.insert(
                    "customfield_10100".to_string(), // Story Points
                    serde_json::Value::Number(serde_json::Number::from_f64(3.0).unwrap()),
                );
                fields
            },
        },
    };

    println!("   Create request structure:");
    println!("   Project: TMP");
    println!("   Summary: {}", example_create_request.fields.summary);
    println!("   Type: Task");
    println!("   Custom fields: Improvement Area = Security, Story Points = 3");
    println!("   (Not executed to avoid creating test issues)");

    println!("\n🎉 Atlassian SDK Example Complete!");
    println!("The SDK provides comprehensive Jira operations:");
    println!("✅ Authentication and health checks");
    println!("✅ Issue retrieval and search");
    println!("✅ Custom field discovery and updates");
    println!("✅ Project and user management");
    println!("✅ Issue creation with custom fields");
    println!("✅ Story points and complexity updates");

    Ok(())
}
