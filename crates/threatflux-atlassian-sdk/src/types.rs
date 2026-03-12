//! Data structures for Jira API objects
//!
//! This module contains comprehensive data structures for Jira issues, projects,
//! users, and other API objects used throughout the Atlassian SDK.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Jira issue representation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct JiraIssue {
    /// Issue key (e.g., "PROJ-123")
    pub key: String,
    /// Issue ID (numeric)
    pub id: String,
    /// Issue fields containing all the data
    pub fields: IssueFields,
    /// Self URL for the issue
    #[serde(rename = "self")]
    pub self_url: Option<String>,
}

/// Issue fields containing all issue data
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct IssueFields {
    /// Issue summary/title
    pub summary: String,
    /// Issue description
    pub description: Option<String>,
    /// Issue type information
    #[serde(rename = "issuetype")]
    pub issue_type: IssueType,
    /// Issue status
    pub status: IssueStatus,
    /// Issue priority
    pub priority: Option<IssuePriority>,
    /// Assignee information
    pub assignee: Option<JiraUser>,
    /// Reporter information
    pub reporter: Option<JiraUser>,
    /// Project information
    pub project: Project,
    /// Creation timestamp (ISO 8601 format)
    pub created: Option<String>,
    /// Last updated timestamp (ISO 8601 format)
    pub updated: Option<String>,
    /// Resolution timestamp (ISO 8601 format)
    #[serde(rename = "resolutiondate")]
    pub resolution_date: Option<String>,
    /// Issue labels
    pub labels: Vec<String>,
    /// Components
    pub components: Vec<Component>,
    /// Parent issue (for subtasks)
    pub parent: Option<Box<JiraIssue>>,
    /// Custom fields (using HashMap for flexibility)
    #[serde(flatten)]
    pub custom_fields: HashMap<String, serde_json::Value>,
}

/// Issue type information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct IssueType {
    /// Issue type ID
    pub id: String,
    /// Issue type name (e.g., "Task", "Bug", "Epic")
    pub name: String,
    /// Issue type description
    pub description: Option<String>,
    /// Icon URL
    #[serde(rename = "iconUrl")]
    pub icon_url: Option<String>,
    /// Whether this is a subtask type
    pub subtask: bool,
}

/// Issue status information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct IssueStatus {
    /// Status ID
    pub id: String,
    /// Status name (e.g., "To Do", "In Progress", "Done")
    pub name: String,
    /// Status description
    pub description: Option<String>,
    /// Status category
    pub category: Option<StatusCategory>,
}

/// Status category information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct StatusCategory {
    /// Category ID
    pub id: i32,
    /// Category key (e.g., "new", "indeterminate", "done")
    pub key: String,
    /// Category name
    pub name: String,
    /// Color name for UI
    #[serde(rename = "colorName")]
    pub color_name: String,
}

/// Issue priority information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct IssuePriority {
    /// Priority ID
    pub id: String,
    /// Priority name (e.g., "High", "Medium", "Low")
    pub name: String,
    /// Priority description
    pub description: Option<String>,
    /// Icon URL
    #[serde(rename = "iconUrl")]
    pub icon_url: Option<String>,
}

/// Jira user information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct JiraUser {
    /// Account ID (for cloud instances)
    #[serde(rename = "accountId")]
    pub account_id: Option<String>,
    /// Username (for server instances)
    pub name: Option<String>,
    /// Display name
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    /// Email address
    #[serde(rename = "emailAddress")]
    pub email_address: Option<String>,
    /// Avatar URLs
    #[serde(rename = "avatarUrls")]
    pub avatar_urls: Option<HashMap<String, String>>,
    /// Whether the user is active
    pub active: Option<bool>,
}

/// Project information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Project {
    /// Project ID
    pub id: String,
    /// Project key (e.g., "PROJ")
    pub key: String,
    /// Project name
    pub name: String,
    /// Project description
    pub description: Option<String>,
    /// Project type key
    #[serde(rename = "projectTypeKey")]
    pub project_type_key: Option<String>,
    /// Avatar URLs
    #[serde(rename = "avatarUrls")]
    pub avatar_urls: Option<HashMap<String, String>>,
}

/// Component information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Component {
    /// Component ID
    pub id: String,
    /// Component name
    pub name: String,
    /// Component description
    pub description: Option<String>,
}

/// Request structure for creating new issues
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreateIssueRequest {
    /// Issue fields to set
    pub fields: CreateIssueFields,
}

/// Fields for creating a new issue
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CreateIssueFields {
    /// Project key or ID
    pub project: ProjectReference,
    /// Issue summary
    pub summary: String,
    /// Issue type
    #[serde(rename = "issuetype")]
    pub issue_type: IssueTypeReference,
    /// Issue description (optional)
    pub description: Option<String>,
    /// Assignee (optional)
    pub assignee: Option<UserReference>,
    /// Priority (optional)
    pub priority: Option<PriorityReference>,
    /// Labels (optional)
    pub labels: Option<Vec<String>>,
    /// Components (optional)
    pub components: Option<Vec<ComponentReference>>,
    /// Parent issue for subtasks (optional)
    pub parent: Option<IssueReference>,
    /// Custom fields
    #[serde(flatten)]
    pub custom_fields: HashMap<String, serde_json::Value>,
}

/// Request structure for updating issues
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UpdateIssueRequest {
    /// Fields to update
    pub fields: HashMap<String, serde_json::Value>,
}

/// Response wrapper for listing available transitions on an issue
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct IssueTransitionsResponse {
    /// Collection of transitions that can be applied to the issue
    pub transitions: Vec<IssueTransition>,
}

/// Jira workflow transition metadata
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct IssueTransition {
    /// Unique identifier for the transition (required when executing it)
    pub id: String,
    /// Human readable name (e.g., "Start Progress", "Done")
    pub name: String,
    /// Destination status once the transition is applied
    pub to: IssueStatus,
    /// Whether a transition screen is displayed
    #[serde(rename = "hasScreen", default)]
    pub has_screen: Option<bool>,
    /// Whether the transition is global (available from any status)
    #[serde(rename = "isGlobal", default)]
    pub is_global: Option<bool>,
    /// Whether this transition is the initial workflow step
    #[serde(rename = "isInitial", default)]
    pub is_initial: Option<bool>,
    /// Additional metadata fields, when present
    #[serde(default)]
    pub fields: Option<HashMap<String, serde_json::Value>>,
    /// API URL for the transition resource
    #[serde(rename = "self", default)]
    pub self_url: Option<String>,
}

/// Reference to a project (by key or ID)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ProjectReference {
    /// Project key (preferred)
    pub key: Option<String>,
    /// Project ID
    pub id: Option<String>,
}

/// Reference to an issue type
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct IssueTypeReference {
    /// Issue type name (preferred)
    pub name: Option<String>,
    /// Issue type ID
    pub id: Option<String>,
}

/// Reference to a user
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct UserReference {
    /// Account ID (for cloud)
    #[serde(rename = "accountId")]
    pub account_id: Option<String>,
    /// Username (for server)
    pub name: Option<String>,
}

/// Reference to a priority
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PriorityReference {
    /// Priority name
    pub name: Option<String>,
    /// Priority ID
    pub id: Option<String>,
}

/// Reference to a component
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ComponentReference {
    /// Component name
    pub name: Option<String>,
    /// Component ID
    pub id: Option<String>,
}

/// Reference to an issue
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct IssueReference {
    /// Issue key
    pub key: Option<String>,
    /// Issue ID
    pub id: Option<String>,
}

/// Custom field value wrapper for complex fields
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct CustomFieldValue {
    /// Field value (for select/option fields)
    pub value: Option<String>,
    /// Field ID (for nested objects)
    pub id: Option<String>,
}

/// Search result wrapper for issue queries
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct IssueSearchResult {
    /// Total number of issues found
    pub total: u32,
    /// Index of first result
    #[serde(rename = "startAt")]
    pub start_at: u32,
    /// Maximum number of results returned
    #[serde(rename = "maxResults")]
    pub max_results: u32,
    /// List of issues
    pub issues: Vec<JiraIssue>,
}

/// Jira field metadata for introspection
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct JiraField {
    /// Field ID
    pub id: String,
    /// Field name
    pub name: String,
    /// Whether the field is custom
    pub custom: bool,
    /// Field schema information
    pub schema: Option<FieldSchema>,
}

/// Field schema information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FieldSchema {
    /// Field type (e.g., "string", "number", "array")
    #[serde(rename = "type")]
    pub field_type: String,
    /// Field system type
    pub system: Option<String>,
    /// Items type for array fields
    pub items: Option<String>,
}

impl ProjectReference {
    /// Create a project reference by key
    pub fn by_key(key: impl Into<String>) -> Self {
        ProjectReference {
            key: Some(key.into()),
            id: None,
        }
    }

    /// Create a project reference by ID
    pub fn by_id(id: impl Into<String>) -> Self {
        ProjectReference {
            key: None,
            id: Some(id.into()),
        }
    }
}

impl IssueTypeReference {
    /// Create an issue type reference by name
    pub fn by_name(name: impl Into<String>) -> Self {
        IssueTypeReference {
            name: Some(name.into()),
            id: None,
        }
    }

    /// Create an issue type reference by ID
    pub fn by_id(id: impl Into<String>) -> Self {
        IssueTypeReference {
            name: None,
            id: Some(id.into()),
        }
    }
}

impl UserReference {
    /// Create a user reference by account ID (cloud)
    pub fn by_account_id(account_id: impl Into<String>) -> Self {
        UserReference {
            account_id: Some(account_id.into()),
            name: None,
        }
    }

    /// Create a user reference by username (server)
    pub fn by_name(name: impl Into<String>) -> Self {
        UserReference {
            account_id: None,
            name: Some(name.into()),
        }
    }
}

impl IssueReference {
    /// Create an issue reference by key
    pub fn by_key(key: impl Into<String>) -> Self {
        IssueReference {
            key: Some(key.into()),
            id: None,
        }
    }

    /// Create an issue reference by ID
    pub fn by_id(id: impl Into<String>) -> Self {
        IssueReference {
            key: None,
            id: Some(id.into()),
        }
    }
}

impl CustomFieldValue {
    /// Create a custom field value
    pub fn new(value: impl Into<String>) -> Self {
        CustomFieldValue {
            value: Some(value.into()),
            id: None,
        }
    }

    /// Create a custom field value with ID
    pub fn with_id(id: impl Into<String>) -> Self {
        CustomFieldValue {
            value: None,
            id: Some(id.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_project_reference() {
        let proj_by_key = ProjectReference::by_key("TEST");
        assert_eq!(proj_by_key.key, Some("TEST".to_string()));
        assert_eq!(proj_by_key.id, None);

        let proj_by_id = ProjectReference::by_id("12345");
        assert_eq!(proj_by_id.id, Some("12345".to_string()));
        assert_eq!(proj_by_id.key, None);
    }

    #[test]
    fn test_issue_type_reference() {
        let issue_type = IssueTypeReference::by_name("Bug");
        assert_eq!(issue_type.name, Some("Bug".to_string()));
        assert_eq!(issue_type.id, None);
    }

    #[test]
    fn test_user_reference() {
        let user_cloud = UserReference::by_account_id("account123");
        assert_eq!(user_cloud.account_id, Some("account123".to_string()));
        assert_eq!(user_cloud.name, None);

        let user_server = UserReference::by_name("jdoe");
        assert_eq!(user_server.name, Some("jdoe".to_string()));
        assert_eq!(user_server.account_id, None);
    }

    #[test]
    fn test_custom_field_value() {
        let field_value = CustomFieldValue::new("Test Value");
        assert_eq!(field_value.value, Some("Test Value".to_string()));

        let field_with_id = CustomFieldValue::with_id("option123");
        assert_eq!(field_with_id.id, Some("option123".to_string()));
    }

    #[test]
    fn test_issue_serialization() {
        let issue = JiraIssue {
            key: "TEST-123".to_string(),
            id: "12345".to_string(),
            self_url: Some("https://test.atlassian.net/rest/api/2/issue/12345".to_string()),
            fields: IssueFields {
                summary: "Test issue".to_string(),
                description: Some("Test description".to_string()),
                issue_type: IssueType {
                    id: "1".to_string(),
                    name: "Task".to_string(),
                    description: Some("A task issue type".to_string()),
                    icon_url: None,
                    subtask: false,
                },
                status: IssueStatus {
                    id: "1".to_string(),
                    name: "To Do".to_string(),
                    description: Some("Initial status".to_string()),
                    category: None,
                },
                priority: None,
                assignee: None,
                reporter: None,
                project: Project {
                    id: "10001".to_string(),
                    key: "TEST".to_string(),
                    name: "Test Project".to_string(),
                    description: None,
                    project_type_key: None,
                    avatar_urls: None,
                },
                created: None,
                updated: None,
                resolution_date: None,
                labels: vec![],
                components: vec![],
                parent: None,
                custom_fields: HashMap::new(),
            },
        };

        let serialized = serde_json::to_string(&issue);
        assert!(serialized.is_ok());

        let deserialized: JiraIssue = serde_json::from_str(&serialized.unwrap()).unwrap();
        assert_eq!(deserialized.key, issue.key);
        assert_eq!(deserialized.fields.summary, issue.fields.summary);
    }
}
