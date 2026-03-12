#![allow(clippy::all, clippy::pedantic, clippy::nursery)]

use serde_json::Value;
use std::collections::HashMap;
use threatflux_atlassian_sdk::{AtlassianClient, CreateIssueFields, CreateIssueRequest};
use threatflux_atlassian_sdk::{IssueTypeReference, ProjectReference, UserReference};

/// Ticket management example demonstrating operations from Python examples
/// Includes ticket creation, updates, and bulk operations similar to YAML-based workflows
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("Atlassian SDK - Ticket Management Example");
    println!("==========================================\n");

    // Create client from environment
    let client = AtlassianClient::from_env()?;

    // Health check
    match client.health_check().await {
        Ok(_) => println!("✅ Connected to Jira successfully"),
        Err(e) => {
            println!("❌ Failed to connect to Jira: {e}");
            return Ok(());
        }
    }

    // Get current user for reference
    let current_user = client.get_myself().await?;
    let account_id = current_user.account_id.clone().unwrap_or_default();
    println!(
        "📋 Authenticated as: {}",
        current_user.display_name.unwrap_or_default()
    );

    // Discover custom fields (like Python field discovery)
    println!("\n🔍 Discovering custom field IDs...");
    let story_points_field = client.find_custom_field_id("Story Points").await?;
    let improvement_area_field = client.find_custom_field_id("Improvement Area").await?;
    let complexity_field = client.find_custom_field_id("Complexity").await?;

    println!("Custom Fields Found:");
    if let Some(sp_field) = &story_points_field {
        println!("   • Story Points: {sp_field}");
    }
    if let Some(ia_field) = &improvement_area_field {
        println!("   • Improvement Area: {ia_field}");
    }
    if let Some(c_field) = &complexity_field {
        println!("   • Complexity: {c_field}");
    }

    // Example ticket operations (similar to Python YAML processing)
    println!("\n📝 Ticket Management Operations:");

    // 1. Create Epic (like Python Phase Epic creation)
    println!("\n1️⃣ Creating Epic example (dry run):");
    let epic_request = CreateIssueRequest {
        fields: CreateIssueFields {
            project: ProjectReference::by_key("TMP"),
            summary: "Phase 0: Development Environment Setup".to_string(),
            issue_type: IssueTypeReference::by_name("Epic"),
            description: Some("Epic for development environment setup phase".to_string()),
            assignee: Some(UserReference::by_account_id(&account_id)),
            priority: None,
            labels: Some(vec!["automation".to_string(), "environment".to_string()]),
            components: Some(vec![threatflux_atlassian_sdk::ComponentReference {
                name: Some("Automation".to_string()),
                id: None,
            }]),
            parent: None,
            custom_fields: {
                let mut fields = HashMap::new();
                // Add story points for Epic (from Python example)
                if let Some(sp_field) = &story_points_field {
                    fields.insert(
                        sp_field.clone(),
                        Value::Number(serde_json::Number::from_f64(13.0).unwrap()),
                    );
                }
                fields
            },
        },
    };

    println!("   Epic Creation Request:");
    println!("   • Project: TMP");
    println!("   • Summary: {}", epic_request.fields.summary);
    println!("   • Type: Epic");
    println!("   • Story Points: 13");
    println!("   (Would create: TMP-XXXX)");

    // 2. Create Task under Epic (like Python Task creation)
    println!("\n2️⃣ Creating Task example (dry run):");
    let task_request = CreateIssueRequest {
        fields: CreateIssueFields {
            project: ProjectReference::by_key("TMP"),
            summary: "0.1 MCP Inspector Setup".to_string(),
            issue_type: IssueTypeReference::by_name("Task"),
            description: Some("Configure MCP Inspector for testing and debugging".to_string()),
            assignee: Some(UserReference::by_account_id(&account_id)),
            priority: None,
            labels: Some(vec!["automation".to_string(), "testing".to_string()]),
            components: Some(vec![threatflux_atlassian_sdk::ComponentReference {
                name: Some("Automation".to_string()),
                id: None,
            }]),
            parent: Some(threatflux_atlassian_sdk::IssueReference::by_key("TMP-EPIC")), // Link to Epic
            custom_fields: {
                let mut fields = HashMap::new();
                // Add improvement area (required for TMP Tasks, from Python example)
                if let Some(ia_field) = &improvement_area_field {
                    fields.insert(
                        ia_field.clone(),
                        serde_json::json!({"value": "Development Tools"}),
                    );
                }
                // Add complexity/story points
                if let Some(c_field) = &complexity_field {
                    fields.insert(c_field.clone(), serde_json::json!({"value": "2"}));
                }
                fields
            },
        },
    };

    println!("   Task Creation Request:");
    println!("   • Project: TMP");
    println!("   • Summary: {}", task_request.fields.summary);
    println!("   • Type: Task");
    println!("   • Parent: TMP-EPIC");
    println!("   • Improvement Area: Development Tools");
    println!("   • Complexity: 2");
    println!("   (Would create: TMP-XXXX)");

    // 3. Create Subtask (like Python Subtask creation)
    println!("\n3️⃣ Creating Subtask example (dry run):");
    let subtask_request = CreateIssueRequest {
        fields: CreateIssueFields {
            project: ProjectReference::by_key("TMP"),
            summary: "Subtask 0.1.1: Inspector installation and configuration".to_string(),
            issue_type: IssueTypeReference::by_id("10684"), // Subtask type ID from Python
            description: Some("Install and configure MCP Inspector tool locally".to_string()),
            assignee: Some(UserReference::by_account_id(&account_id)),
            priority: None,
            labels: Some(vec![
                "installation".to_string(),
                "configuration".to_string(),
            ]),
            components: Some(vec![threatflux_atlassian_sdk::ComponentReference {
                name: Some("Automation".to_string()),
                id: None,
            }]),
            parent: Some(threatflux_atlassian_sdk::IssueReference::by_key("TMP-TASK")), // Link to Task
            custom_fields: {
                let mut fields = HashMap::new();
                if let Some(c_field) = &complexity_field {
                    fields.insert(c_field.clone(), serde_json::json!({"value": "1"}));
                }
                fields
            },
        },
    };

    println!("   Subtask Creation Request:");
    println!("   • Project: TMP");
    println!("   • Summary: {}", subtask_request.fields.summary);
    println!("   • Type: Sub-task");
    println!("   • Parent: TMP-TASK");
    println!("   • Complexity: 1");
    println!("   (Would create: TMP-XXXX)");

    // 4. Issue Update Operations (like Python update scripts)
    println!("\n4️⃣ Issue Update Examples:");

    // Story Points Update (from Python story points script)
    println!("   📊 Story Points Update:");
    println!("   Code: client.update_story_points(\"TMP-123\", 8.0, \"customfield_10100\")");
    println!("   Effect: Sets Story Points field to 8.0");

    // Custom Field Update (from Python complexity script)
    println!("\n   🎯 Custom Field Update:");
    println!("   Code: client.update_custom_field(\"TMP-123\", \"customfield_11057\", \"High\")");
    println!("   Effect: Sets Complexity field to High");

    // Bulk Update (like Python bulk operations)
    println!("\n   📦 Bulk Update Example:");
    println!("   // Update multiple fields at once");
    println!("   let mut fields = HashMap::new();");
    println!("   fields.insert(\"summary\".to_string(), Value::String(\"Updated summary\".to_string()));");
    println!("   fields.insert(\"customfield_10100\".to_string(), Value::Number(5.0.into()));");
    println!("   client.update_issue(\"TMP-123\", fields).await?;");

    // 5. Search and Filter Operations
    println!("\n5️⃣ Search and Filter Examples (like Python JQL queries):");

    let search_examples = vec![
        ("Recent Issues", "created >= -7d ORDER BY created DESC"),
        (
            "My Assigned Issues",
            "assignee = currentUser() AND status != Done",
        ),
        ("High Priority Tasks", "priority = High AND type = Task"),
        (
            "TMP Project Issues",
            "project = TMP AND status in ('To Do', 'In Progress')",
        ),
        ("Epic Stories", "type = Epic AND project = TMP"),
    ];

    for (name, jql) in search_examples {
        println!("   🔍 {name}:");
        println!("      JQL: {jql}");
        match client.search_issues(jql, 0, 3).await {
            Ok(results) => {
                println!("      Result: {} issues found", results.total);
                for (i, issue) in results.issues.iter().take(2).enumerate() {
                    println!(
                        "        {}. {} - {}",
                        i + 1,
                        issue.key,
                        issue.fields.summary
                    );
                }
            }
            Err(e) => println!("      Error: {e}"),
        }
    }

    // 6. Field Discovery and Metadata (like Python field introspection)
    println!("\n6️⃣ Field Discovery Operations:");
    match client.get_fields().await {
        Ok(fields) => {
            let custom_fields: Vec<_> = fields.iter().filter(|f| f.custom).collect();
            println!(
                "   📋 Found {} total fields ({} custom)",
                fields.len(),
                custom_fields.len()
            );

            println!("   🔧 Key Custom Fields:");
            for field in custom_fields.iter().take(5) {
                println!("      • {} ({})", field.name, field.id);
            }
        }
        Err(e) => println!("   ❌ Error getting fields: {e}"),
    }

    println!("\n🎯 Common Workflow Patterns:");
    println!("1. **Epic Creation**: Create phase/feature epics with story points");
    println!("2. **Task Management**: Create tasks under epics with improvement areas");
    println!("3. **Subtask Breakdown**: Break tasks into manageable subtasks");
    println!("4. **Bulk Updates**: Update multiple issues with story points/complexity");
    println!("5. **Progress Tracking**: Search and filter issues by status/assignee");
    println!("6. **Field Management**: Discover and update custom fields dynamically");

    println!("\n📚 Key SDK Capabilities:");
    println!("✅ Full CRUD operations for Jira issues");
    println!("✅ Custom field support (Story Points, Improvement Area, Complexity)");
    println!("✅ Authentication with API tokens");
    println!("✅ SSL/TLS support for corporate environments");
    println!("✅ Comprehensive error handling with retry logic");
    println!("✅ JQL search with pagination");
    println!("✅ Project and user management");

    Ok(())
}
