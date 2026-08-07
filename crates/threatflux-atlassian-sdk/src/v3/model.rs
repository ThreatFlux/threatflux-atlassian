//! The v3 request and response model.
//!
//! Every type here is parallel to something in [`crate::types`] rather than a
//! replacement for it. See the [module documentation](super) for why the two
//! models coexist.
//!
//! # Three rules this model keeps and the v2 model cannot
//!
//! **An unset optional is absent from the request, never `null`.** Jira rejects
//! `"parent": null` on any issue type that is not a subtask, and a `null` for a
//! field the project's create screen does not expose fails the same way, so
//! every optional on [`V3CreateIssueFields`] carries `skip_serializing_if` --
//! including the ones nested inside a reference, which is where the v2 model
//! still spells an unset member as an explicit `null`.
//!
//! **Every field of a response is optional.** `GET /rest/api/3/issue/{key}`
//! answers a narrowed `fields=summary` request with a `fields` object holding
//! exactly `summary`. [`crate::types::IssueFields`] requires `issuetype`,
//! `status` and `project`, so it fails such a response outright with
//! `missing field`; [`V3IssueFields`] reads it, and anything it does not model
//! lands in [`other`](V3IssueFields::other) rather than being dropped.
//!
//! **A custom field cannot impersonate a modelled member.**
//! [`V3CreateIssueFields::custom_fields`] is flattened into the same JSON object
//! as `summary` and `description`, so an id that collides with one of them would
//! be written twice and read once -- as the custom value. That is a bypass of
//! the ADF write gate rather than a merge, so a colliding id is refused where it
//! is set and refused again where the body is built.

use std::collections::{BTreeMap, HashMap};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::adf::RichText;
use crate::client::{preview, Idempotency};
use crate::error::{AtlassianError, Result};

/// The Jira field ids [`V3CreateIssueFields`] models as members of its own.
///
/// A custom field may not carry one of these. [`custom_fields`] is
/// `#[serde(flatten)]`, so a colliding id is emitted *beside* the modelled
/// member rather than instead of it: the rendered string holds the key twice,
/// and every JSON reader that keeps the last write -- `serde_json::Map` and
/// Jira both -- takes the custom one. That makes the collision a bypass rather
/// than a duplicate. Setting `description` this way would put an arbitrary
/// caller-supplied value on the wire as JSON structure without
/// [`AdfDocument::validate`](crate::adf::AdfDocument::validate) ever seeing it,
/// which is the one thing the v3 write gate exists to prevent, and setting
/// `summary`, `project` or `issuetype` this way would silently create a
/// different issue than the builder describes.
///
/// [`custom_fields`]: V3CreateIssueFields::custom_fields
const MODELLED_CREATE_FIELD_IDS: [&str; 9] = [
    "assignee",
    "components",
    "description",
    "issuetype",
    "labels",
    "parent",
    "priority",
    "project",
    "summary",
];

/// Refuses a custom field id that a modelled member already owns.
///
/// The id reaches the message through [`preview`] for the same reason every
/// other caller-supplied value does. It is bounded by construction here -- a
/// rejected id is always one of [`MODELLED_CREATE_FIELD_IDS`] -- but the bound
/// is applied at the sink rather than argued about at each call site.
fn reject_modelled_field_id(field_id: &str) -> Result<()> {
    if MODELLED_CREATE_FIELD_IDS.contains(&field_id) {
        return Err(AtlassianError::validation(format!(
            "the custom field id {} is a modelled member of a v3 create and would \
             override it on the wire; set it through the typed builder instead",
            preview(field_id)
        )));
    }
    Ok(())
}

/// A project, referenced by key or by id.
///
/// A write sets exactly one of them -- [`by_key`](Self::by_key) or
/// [`by_id`](Self::by_id) -- and the other is omitted from the body rather than
/// sent as `null`. A read fills in whatever Jira returned.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3ProjectRef {
    /// Numeric project id, as a string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Project key, such as `KAN`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Human-readable project name. Returned on a read; never needed on a write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl V3ProjectRef {
    /// References the project with this key.
    pub fn by_key(key: impl Into<String>) -> Self {
        Self {
            id: None,
            key: Some(key.into()),
            name: None,
        }
    }

    /// References the project with this id.
    pub fn by_id(id: impl Into<String>) -> Self {
        Self {
            id: Some(id.into()),
            key: None,
            name: None,
        }
    }
}

/// A Jira resource this crate references by id or by name.
///
/// One type stands in for an issue type, a priority, a resolution and a
/// component because on the wire they are the same two-member object, and this
/// crate never needs more of any of them than the identity.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3NamedRef {
    /// Numeric id, as a string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Name, such as `Task`, `High` or `Done`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl V3NamedRef {
    /// References the resource with this id.
    ///
    /// Prefer an id over a name wherever the caller has one: a name is
    /// tenant-configurable and can be renamed out from under a workflow.
    pub fn by_id(id: impl Into<String>) -> Self {
        Self {
            id: Some(id.into()),
            name: None,
        }
    }

    /// References the resource with this name.
    pub fn by_name(name: impl Into<String>) -> Self {
        Self {
            id: None,
            name: Some(name.into()),
        }
    }
}

/// An issue, referenced by key or by id -- a `parent`, a link target.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3IssueRef {
    /// Numeric issue id, as a string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Issue key, such as `KAN-12`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

impl V3IssueRef {
    /// References the issue with this key.
    pub fn by_key(key: impl Into<String>) -> Self {
        Self {
            id: None,
            key: Some(key.into()),
        }
    }

    /// References the issue with this id.
    pub fn by_id(id: impl Into<String>) -> Self {
        Self {
            id: Some(id.into()),
            key: None,
        }
    }
}

/// A Jira user.
///
/// On a write only [`account_id`](Self::account_id) is meaningful, and
/// [`by_account_id`](Self::by_account_id) is the constructor that says so: the
/// remaining members are omitted from the body. On a read Jira fills in as much
/// as the caller's browse permissions and the tenant's privacy settings allow,
/// which is why all of them are optional.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3User {
    /// Atlassian account id -- the only stable identifier, and the only member a
    /// write may set.
    #[serde(rename = "accountId", default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// Display name, when the tenant discloses it.
    #[serde(
        rename = "displayName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub display_name: Option<String>,
    /// Email address, when the tenant discloses it.
    #[serde(
        rename = "emailAddress",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub email_address: Option<String>,
    /// Whether the account is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
}

impl V3User {
    /// References the account with this Atlassian account id.
    pub fn by_account_id(account_id: impl Into<String>) -> Self {
        Self {
            account_id: Some(account_id.into()),
            display_name: None,
            email_address: None,
            active: None,
        }
    }
}

/// The workflow status of an issue.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3Status {
    /// Numeric status id, as a string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Status name, such as `To Do`. Tenant-configurable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The category the status belongs to.
    ///
    /// The category is what a caller should branch on: its
    /// [`key`](V3StatusCategory::key) is one of `new`, `indeterminate` or
    /// `done` on every tenant, whereas [`name`](Self::name) is whatever the
    /// project administrator called it.
    #[serde(
        rename = "statusCategory",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub status_category: Option<V3StatusCategory>,
}

/// The tenant-independent category a [`V3Status`] belongs to.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3StatusCategory {
    /// Numeric category id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// Category key: `new`, `indeterminate` or `done`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Category name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Colour name used by the Jira UI.
    #[serde(rename = "colorName", default, skip_serializing_if = "Option::is_none")]
    pub color_name: Option<String>,
}

/// The fields of an issue as v3 returns them.
///
/// Deliberately lean and entirely optional. Two consequences worth stating:
///
/// - A narrowed read is legal. `fields=summary,labels` yields a value whose
///   other members are `None`, and `None` means *not requested, not returned, or
///   returned as `null`* -- never *empty*. A caller that needs to tell "no
///   labels" from "labels were not requested" gets that distinction from
///   `Option<Vec<String>>` and would not from a defaulted `Vec<String>`. What it
///   does not get is *absent* versus *`null`*; see below.
/// - Every field is preserved except the two cases named next. Fields this crate
///   does not model -- every custom field, every field Atlassian adds later --
///   land in [`other`](Self::other), keyed by their Jira field id, `null` values
///   included: `"customfield_10010": null` round-trips as
///   `"customfield_10010": null`.
///
/// # The two things a round trip does not preserve
///
/// Neither costs this crate anything, because this crate never sends a `fields`
/// object it read. Both would cost a caller that did, which is why they are
/// named rather than summarized as "nothing is lost".
///
/// - **Members inside a modelled reference.** An unmodelled key on, say,
///   `status` is dropped, because [`V3Status`] models the members this crate
///   uses and nothing else.
/// - **An explicit `null` on a modelled member.** A real
///   `GET /rest/api/3/issue/{key}` response is full of them -- `"assignee":
///   null`, `"resolution": null`, `"parent": null` -- and every modelled
///   optional here carries `skip_serializing_if = "Option::is_none"`, so `null`
///   reads as [`None`] and re-serializes as an *absent key*. On a read that
///   distinction carries no information: Jira means the same thing by an
///   unassigned issue whether it writes `null` or omits the field. On a write it
///   means the opposite of itself -- `"assignee": null` clears the assignee and
///   an absent `assignee` leaves it alone -- so the asymmetry only bites a
///   caller that echoes this type back as a request body.
///
/// **Do not do that.** [`V3IssueFields`] is a read model, and echoing one as a
/// write body is broken for a larger reason than the nulls: it would carry
/// `created`, `updated` and `status`, which Jira rejects as not editable through
/// this route. A write names the fields it changes, through
/// [`V3UpdateIssueRequest`] -- which *can* express an explicit clear, as
/// `with_field("assignee", Value::Null)`, precisely because its map holds a
/// `Value` and never collapses one into `None`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3IssueFields {
    /// Issue summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Issue description.
    ///
    /// v3 answers with an ADF document, so this is normally
    /// [`RichText::Adf`]. An issue whose description was last written through
    /// v2 can still answer with a bare string, which reads back as
    /// [`RichText::Text`]; anything else survives as
    /// [`RichText::Unknown`] rather than failing the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<RichText>,
    /// Issue type.
    #[serde(rename = "issuetype", default, skip_serializing_if = "Option::is_none")]
    pub issue_type: Option<V3NamedRef>,
    /// Workflow status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<V3Status>,
    /// Resolution, or `None` while the issue is unresolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<V3NamedRef>,
    /// Resolution timestamp, ISO 8601.
    #[serde(
        rename = "resolutiondate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resolution_date: Option<String>,
    /// Priority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<V3NamedRef>,
    /// Assignee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<V3User>,
    /// Reporter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reporter: Option<V3User>,
    /// The project the issue belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<V3ProjectRef>,
    /// Parent issue, for a subtask or a child of an epic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<V3IssueRef>,
    /// Labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// Creation timestamp, ISO 8601.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    /// Last-updated timestamp, ISO 8601.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
    /// Every field this crate does not model, keyed by Jira field id.
    ///
    /// A [`BTreeMap`] rather than a [`HashMap`] so that serializing a value read
    /// from Jira is byte-stable, which is what makes a golden snapshot of a
    /// response worth asserting on.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

/// An issue as `GET /rest/api/3/issue/{key}` returns it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3Issue {
    /// Numeric issue id, as a string.
    pub id: String,
    /// Issue key, such as `KAN-12`.
    pub key: String,
    /// API URL of the issue.
    #[serde(rename = "self", default, skip_serializing_if = "Option::is_none")]
    pub self_url: Option<String>,
    /// The fields Jira returned, which is only the requested ones on a narrowed
    /// read.
    #[serde(default)]
    pub fields: V3IssueFields,
}

/// The fields of a `POST /rest/api/3/issue` request.
///
/// Build one with [`new`](Self::new) and the `with_*` methods rather than a
/// struct literal: the type is `#[non_exhaustive]`, so a field added later is an
/// additive change instead of a compile break at every construction site.
///
/// ```
/// use threatflux_atlassian_sdk::v3::{V3CreateIssueFields, V3NamedRef, V3ProjectRef};
/// use serde_json::json;
///
/// let fields = V3CreateIssueFields::new(
///     V3ProjectRef::by_key("KAN"),
///     "Upgrade openssl",
///     V3NamedRef::by_name("Task"),
/// );
///
/// // Nothing that was not set appears at all -- no `"parent": null`, and no
/// // `"id": null` inside the project reference either.
/// assert_eq!(
///     serde_json::to_value(&fields)?,
///     json!({
///         "project": {"key": "KAN"},
///         "summary": "Upgrade openssl",
///         "issuetype": {"name": "Task"}
///     })
/// );
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3CreateIssueFields {
    /// The project to create the issue in.
    pub project: V3ProjectRef,
    /// Issue summary.
    pub summary: String,
    /// Issue type.
    #[serde(rename = "issuetype")]
    pub issue_type: V3NamedRef,
    /// Issue description.
    ///
    /// Held as a [`RichText`] and normalized to ADF on the way out, so a caller
    /// may pass a `&str` and still never send a plain string to a v3 endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<RichText>,
    /// Assignee.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<V3User>,
    /// Priority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<V3NamedRef>,
    /// Labels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// Components.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<V3NamedRef>>,
    /// Parent issue, required by Jira for a subtask and rejected by it for
    /// anything else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<V3IssueRef>,
    /// Custom fields, keyed by Jira field id such as `customfield_10010`.
    ///
    /// A [`BTreeMap`] so a request body is byte-stable across runs: with a
    /// [`HashMap`] the same set of custom fields serializes in a different order
    /// every process, and no golden snapshot of a request can be asserted on.
    /// Flattened, so an empty map contributes nothing to the body and needs no
    /// `skip_serializing_if` of its own.
    ///
    /// **A key that names a modelled member is refused, not merged.** Flattening
    /// puts these entries in the same JSON object as `summary`, `description`
    /// and the rest, so a colliding id would be emitted twice and the custom
    /// value -- written last -- would be the one Jira reads. Setting
    /// `description` here would therefore step straight past the ADF write gate.
    /// [`with_custom_field`](Self::with_custom_field) rejects such an id at the
    /// construction site, and the request builder rejects it a second time when
    /// the body is assembled, because this field is public and can be populated
    /// without going through the builder at all.
    #[serde(flatten)]
    pub custom_fields: BTreeMap<String, Value>,
}

impl V3CreateIssueFields {
    /// The three fields Jira requires on every create.
    pub fn new(project: V3ProjectRef, summary: impl Into<String>, issue_type: V3NamedRef) -> Self {
        Self {
            project,
            summary: summary.into(),
            issue_type,
            description: None,
            assignee: None,
            priority: None,
            labels: None,
            components: None,
            parent: None,
            custom_fields: BTreeMap::new(),
        }
    }

    /// Sets the description.
    ///
    /// Accepts anything [`RichText`] accepts: a `&str` or `String` (upgraded to
    /// ADF when the request is built) or an
    /// [`AdfDocument`](crate::adf::AdfDocument).
    #[must_use]
    pub fn with_description(mut self, description: impl Into<RichText>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the assignee.
    #[must_use]
    pub fn with_assignee(mut self, assignee: V3User) -> Self {
        self.assignee = Some(assignee);
        self
    }

    /// Sets the priority.
    #[must_use]
    pub fn with_priority(mut self, priority: V3NamedRef) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Sets the labels, replacing any already set.
    #[must_use]
    pub fn with_labels(mut self, labels: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.labels = Some(labels.into_iter().map(Into::into).collect());
        self
    }

    /// Sets the components, replacing any already set.
    #[must_use]
    pub fn with_components(mut self, components: impl IntoIterator<Item = V3NamedRef>) -> Self {
        self.components = Some(components.into_iter().collect());
        self
    }

    /// Sets the parent issue.
    #[must_use]
    pub fn with_parent(mut self, parent: V3IssueRef) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Sets one custom field, keyed by its Jira field id.
    ///
    /// The one fallible builder on this type, and the reason is the flattening:
    /// a `field_id` that names a modelled member -- `description`, `summary`,
    /// `project`, `issuetype` or any other of them -- would not be *merged* into
    /// the body, it would be emitted next to the modelled value and win, because
    /// the collision is resolved by whichever key was written last. There are
    /// only bad ways to express that in an infallible signature: dropping the
    /// value silently loses a field the caller asked for, and panicking turns a
    /// configuration typo into a crash. So it is refused, and the caller is told
    /// which id it was.
    ///
    /// ```
    /// use threatflux_atlassian_sdk::AtlassianError;
    /// use threatflux_atlassian_sdk::v3::{V3CreateIssueFields, V3NamedRef, V3ProjectRef};
    ///
    /// let fields = V3CreateIssueFields::new(
    ///     V3ProjectRef::by_key("KAN"),
    ///     "Upgrade openssl",
    ///     V3NamedRef::by_name("Task"),
    /// );
    ///
    /// // An id of this crate's own is refused ...
    /// assert!(matches!(
    ///     fields.clone().with_custom_field("description", "smuggled"),
    ///     Err(AtlassianError::Validation { .. })
    /// ));
    ///
    /// // ... and every other id is a custom field.
    /// let fields = fields.with_custom_field("customfield_10010", 7)?;
    /// assert_eq!(fields.custom_fields["customfield_10010"], 7);
    /// # Ok::<(), AtlassianError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`AtlassianError::Validation`] if `field_id` names a member this type
    /// models. Nothing is inserted in that case.
    pub fn with_custom_field(
        mut self,
        field_id: impl Into<String>,
        value: impl Into<Value>,
    ) -> Result<Self> {
        let field_id = field_id.into();
        reject_modelled_field_id(&field_id)?;
        self.custom_fields.insert(field_id, value.into());
        Ok(self)
    }

    /// Normalizes every rich-text member into the one v3 wire form.
    ///
    /// A [`RichText::Text`] description is upgraded to ADF, a
    /// [`RichText::Adf`] one is validated, and a [`RichText::Unknown`] one is
    /// refused -- see [`RichText::into_wire`]. Nothing else changes.
    ///
    /// The custom fields are re-checked for a collision with a modelled member
    /// first. [`with_custom_field`](Self::with_custom_field) already refuses
    /// one, but [`custom_fields`](Self::custom_fields) is public, so the
    /// builder is a courtesy and this is the gate: it is the last point before
    /// a body exists, and every v3 create passes through it.
    fn into_wire(mut self) -> Result<Self> {
        for field_id in self.custom_fields.keys() {
            reject_modelled_field_id(field_id)?;
        }

        self.description = self
            .description
            .map(RichText::into_wire)
            .transpose()?
            .map(RichText::Adf);
        Ok(self)
    }
}

/// A `POST /rest/api/3/issue` request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3CreateIssueRequest {
    /// The fields to set on the new issue.
    pub fields: V3CreateIssueFields,
}

impl V3CreateIssueRequest {
    /// A create request for `fields`.
    pub const fn new(fields: V3CreateIssueFields) -> Self {
        Self { fields }
    }

    /// Normalizes every rich-text member into the one v3 wire form.
    pub(crate) fn into_wire(self) -> Result<Self> {
        Ok(Self {
            fields: self.fields.into_wire()?,
        })
    }
}

impl From<V3CreateIssueFields> for V3CreateIssueRequest {
    fn from(fields: V3CreateIssueFields) -> Self {
        Self::new(fields)
    }
}

/// What `POST /rest/api/3/issue` answers with.
///
/// All three members are kept, `self_url` included. The v2 create response type
/// discards everything but the key, which costs a caller the issue id -- the
/// only identifier that is stable across a project key rename, and the one
/// `reconcileIssues` takes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3CreatedIssue {
    /// Numeric issue id, as a string.
    pub id: String,
    /// Issue key, such as `KAN-12`.
    pub key: String,
    /// API URL of the created issue.
    #[serde(rename = "self", default, skip_serializing_if = "Option::is_none")]
    pub self_url: Option<String>,
}

/// A `PUT /rest/api/3/issue/{key}` request.
///
/// Jira accepts two ways of changing a field and they are not interchangeable:
/// [`fields`](Self::fields) *sets* a value outright, while
/// [`update`](Self::update) applies named operations (`add`, `remove`, `set`,
/// `edit`) to it. Only the second can append, which is why an update carrying
/// operations is tagged as an unsafe write and a `fields`-only one is not --
/// see the replay tag this crate records for each.
///
/// ```
/// use threatflux_atlassian_sdk::v3::V3UpdateIssueRequest;
/// use serde_json::json;
///
/// let request = V3UpdateIssueRequest::new()
///     .with_field("summary", "Upgrade openssl to 3.5.4")
///     .with_update("labels", json!([{"add": "jira-automation-gh-42-7"}]));
///
/// assert_eq!(
///     serde_json::to_value(&request)?,
///     json!({
///         "fields": {"summary": "Upgrade openssl to 3.5.4"},
///         "update": {"labels": [{"add": "jira-automation-gh-42-7"}]}
///     })
/// );
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub struct V3UpdateIssueRequest {
    /// Values to set outright, keyed by Jira field id.
    ///
    /// A [`BTreeMap`] for the same reason the create request uses one: a
    /// byte-stable body is a body a golden snapshot can pin.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    /// Field operations, keyed by Jira field id. Each value is an array of
    /// single-key operation objects, such as `[{"add": "a-label"}]`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub update: BTreeMap<String, Value>,
}

impl V3UpdateIssueRequest {
    /// An update that changes nothing yet.
    pub const fn new() -> Self {
        Self {
            fields: BTreeMap::new(),
            update: BTreeMap::new(),
        }
    }

    /// Sets `field_id` to `value`, replacing any value already staged for it.
    #[must_use]
    pub fn with_field(mut self, field_id: impl Into<String>, value: impl Into<Value>) -> Self {
        self.fields.insert(field_id.into(), value.into());
        self
    }

    /// Stages `operations` against `field_id`, replacing any already staged.
    ///
    /// `operations` is the array Jira expects, such as
    /// `json!([{"remove": "a-label"}])`.
    #[must_use]
    pub fn with_update(
        mut self,
        field_id: impl Into<String>,
        operations: impl Into<Value>,
    ) -> Self {
        self.update.insert(field_id.into(), operations.into());
        self
    }

    /// Whether this request would change nothing.
    ///
    /// A `PUT` with an empty body is refused before it is sent: Jira answers it
    /// with a 400, and a write that cannot succeed should not consume a retry
    /// budget or a rate-limit token.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.update.is_empty()
    }

    /// Whether replaying this request could duplicate a server-side effect.
    ///
    /// A `fields`-only update is `Idempotency::Safe`: it sets values, so a
    /// replay converges on the same issue. An update carrying operations is
    /// `Idempotency::UnsafeWrite`, because `{"comment": [{"add": ...}]}` is a
    /// legal member of that map and replaying it posts a second comment. The
    /// distinction is per-request rather than per-method, which is the whole
    /// reason the tag is computed here instead of being hard-coded at the call
    /// site.
    pub(crate) fn idempotency(&self) -> Idempotency {
        if self.update.is_empty() {
            Idempotency::Safe
        } else {
            Idempotency::UnsafeWrite
        }
    }
}

/// What a read may narrow or widen on `GET /rest/api/3/issue/{key}`.
///
/// The default requests nothing at all, which is Jira's own default: every
/// navigable field, no expansions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct V3GetIssueOptions {
    /// Field ids to return, such as `summary` or `customfield_10010`.
    ///
    /// Sent as one comma-joined `fields` parameter. Jira's selector syntax
    /// passes through unchanged, so `*all` and `-description` work as they do in
    /// the REST API.
    pub fields: Vec<String>,
    /// `expand` values, such as `renderedFields` or `changelog`.
    pub expand: Vec<String>,
}

impl V3GetIssueOptions {
    /// Options that narrow nothing and expand nothing.
    pub const fn new() -> Self {
        Self {
            fields: Vec::new(),
            expand: Vec::new(),
        }
    }

    /// Requests only these fields, replacing any already requested.
    #[must_use]
    pub fn with_fields(mut self, fields: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.fields = fields.into_iter().map(Into::into).collect();
        self
    }

    /// Requests these expansions, replacing any already requested.
    #[must_use]
    pub fn with_expand(mut self, expand: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.expand = expand.into_iter().map(Into::into).collect();
        self
    }

    /// The query parameters these options describe.
    ///
    /// An empty selector contributes no parameter at all, so a default read is
    /// byte-identical on the wire to one that never mentioned options.
    pub(crate) fn query(&self) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if !self.fields.is_empty() {
            params.insert("fields".to_string(), self.fields.join(","));
        }
        if !self.expand.is_empty() {
            params.insert("expand".to_string(), self.expand.join(","));
        }
        params
    }
}

#[cfg(test)]
mod tests {
    use super::{
        V3CreateIssueFields, V3CreateIssueRequest, V3CreatedIssue, V3GetIssueOptions, V3Issue,
        V3IssueFields, V3IssueRef, V3NamedRef, V3ProjectRef, V3UpdateIssueRequest, V3User,
        MODELLED_CREATE_FIELD_IDS,
    };
    use crate::adf::RichText;
    use crate::client::Idempotency;
    use crate::error::AtlassianError;
    use serde_json::{json, Value};
    use std::collections::BTreeSet;

    fn minimal_fields() -> V3CreateIssueFields {
        V3CreateIssueFields::new(
            V3ProjectRef::by_key("KAN"),
            "Upgrade openssl",
            V3NamedRef::by_name("Task"),
        )
    }

    #[test]
    fn every_unset_optional_is_absent_from_a_create_body() {
        // `"parent": null` is rejected by Jira on any issue type that is not a
        // subtask, and a null for a field the create screen does not expose
        // fails the same way. The nested references have to be as strict as the
        // outer struct, which is where the v2 model still emits `"id": null`.
        let body = serde_json::to_value(minimal_fields()).expect("serializes");

        assert_eq!(
            body,
            json!({
                "project": {"key": "KAN"},
                "summary": "Upgrade openssl",
                "issuetype": {"name": "Task"}
            })
        );
        assert!(
            !body.to_string().contains("null"),
            "an unset optional reached the body as a null: {body}"
        );
    }

    #[test]
    fn a_set_optional_survives() {
        let body = serde_json::to_value(
            minimal_fields()
                .with_description("body text")
                .with_assignee(V3User::by_account_id("account-123"))
                .with_priority(V3NamedRef::by_name("High"))
                .with_labels(["jira-automation-gh-42-7"])
                .with_components([V3NamedRef::by_name("backend")])
                .with_parent(V3IssueRef::by_key("KAN-1"))
                .with_custom_field("customfield_10010", "value")
                .expect("a custom field id is not a modelled one"),
        )
        .expect("serializes");

        assert_eq!(body["description"], json!("body text"));
        assert_eq!(body["assignee"], json!({"accountId": "account-123"}));
        assert_eq!(body["priority"], json!({"name": "High"}));
        assert_eq!(body["labels"], json!(["jira-automation-gh-42-7"]));
        assert_eq!(body["components"], json!([{"name": "backend"}]));
        assert_eq!(body["parent"], json!({"key": "KAN-1"}));
        assert_eq!(body["customfield_10010"], json!("value"));
    }

    #[test]
    fn custom_fields_serialize_in_a_stable_order() {
        // The point of the `BTreeMap`: a golden snapshot of a request body is
        // only assertable if the same set of custom fields always serializes the
        // same way. Insertion order here is deliberately reverse-sorted.
        let fields = minimal_fields()
            .with_custom_field("customfield_10030", 3)
            .and_then(|fields| fields.with_custom_field("customfield_10010", 1))
            .and_then(|fields| fields.with_custom_field("customfield_10020", 2))
            .expect("no custom field id is a modelled one");

        let rendered = serde_json::to_string(&fields).expect("serializes");
        let first = rendered.find("customfield_10010").expect("field 10010");
        let second = rendered.find("customfield_10020").expect("field 10020");
        let third = rendered.find("customfield_10030").expect("field 10030");

        assert!(
            first < second && second < third,
            "custom fields are not in key order: {rendered}"
        );
    }

    #[test]
    fn a_custom_field_may_not_take_the_id_of_a_modelled_member() {
        // Not a naming quibble: the map is flattened, so the collision is a
        // *bypass*. `description` is the dangerous one -- it would carry an
        // unvalidated document past the ADF write gate -- but `summary`,
        // `project` and `issuetype` decide what issue gets created at all.
        for field_id in MODELLED_CREATE_FIELD_IDS {
            let error = minimal_fields()
                .with_custom_field(field_id, json!("smuggled"))
                .expect_err("a modelled field id must not be settable as a custom field");

            assert!(
                matches!(error, AtlassianError::Validation { .. }),
                "{field_id} answered {error:?} instead of a validation error"
            );
            assert!(
                error.to_string().contains(field_id),
                "the rejection does not name the id it refused: {error}"
            );
        }
    }

    #[test]
    fn the_refused_id_list_is_exactly_the_set_of_modelled_members() {
        // The maintenance test. A member added to this struct later is a new
        // collision target, and nothing else in the suite would notice that the
        // list had fallen behind -- the hole reopens silently for exactly the
        // one field that was added last.
        let populated = serde_json::to_value(
            minimal_fields()
                .with_description("body text")
                .with_assignee(V3User::by_account_id("account-123"))
                .with_priority(V3NamedRef::by_name("High"))
                .with_labels(["a-label"])
                .with_components([V3NamedRef::by_name("backend")])
                .with_parent(V3IssueRef::by_key("KAN-1")),
        )
        .expect("serializes");

        let on_the_wire: BTreeSet<&str> = populated
            .as_object()
            .expect("a create body is an object")
            .keys()
            .map(String::as_str)
            .collect();
        let refused: BTreeSet<&str> = MODELLED_CREATE_FIELD_IDS.into_iter().collect();

        assert_eq!(
            on_the_wire, refused,
            "the refused-id list and the modelled members have drifted apart"
        );
    }

    #[test]
    fn a_shadowing_custom_field_planted_directly_is_refused_when_the_body_is_built() {
        // `custom_fields` is public, so the builder's rejection is a courtesy
        // and `into_wire` is the gate. A document Jira would have accepted and
        // this crate could never have built: version 9, and a node it does not
        // model.
        let smuggled = json!({
            "type": "doc",
            "version": 9,
            "content": [{"type": "mediaSingle", "attrs": {"x": 1}}]
        });
        let mut fields = minimal_fields().with_description("legitimate text");
        fields
            .custom_fields
            .insert("description".to_string(), smuggled.clone());

        // What the rejection prevents, pinned so the reason cannot rot: the
        // rendered body carries `description` twice, and every reader that keeps
        // the last write -- `serde_json::Map` included, which is what the
        // request body is built through -- resolves it to the smuggled one.
        let rendered = serde_json::to_string(&fields).expect("serializes");
        assert_eq!(
            rendered.matches("\"description\"").count(),
            2,
            "the shadowing mechanism this test relies on changed: {rendered}"
        );
        assert_eq!(
            serde_json::to_value(&fields).expect("serializes")["description"],
            smuggled,
            "the shadowing mechanism this test relies on changed"
        );

        let error = V3CreateIssueRequest::new(fields)
            .into_wire()
            .expect_err("a shadowed modelled member must not reach a request body");
        assert!(
            matches!(error, AtlassianError::Validation { .. }),
            "expected a validation error, got {error:?}"
        );
    }

    #[test]
    fn a_custom_field_that_shadows_nothing_still_reaches_the_body() {
        // The rejection is exactly as wide as the modelled set: `customfield_*`
        // is the ordinary case, and so is any field id Jira knows that this
        // crate does not model -- `duedate` here -- because those merge without
        // colliding.
        let request = V3CreateIssueRequest::new(
            minimal_fields()
                .with_custom_field("customfield_10010", 7)
                .and_then(|fields| fields.with_custom_field("duedate", "2026-01-31"))
                .expect("neither id is a modelled member"),
        )
        .into_wire()
        .expect("writable");

        let body = serde_json::to_value(&request.fields).expect("serializes");
        assert_eq!(body["customfield_10010"], json!(7));
        assert_eq!(body["duedate"], json!("2026-01-31"));
    }

    #[test]
    fn a_plain_text_description_becomes_adf_on_the_wire() {
        let request =
            V3CreateIssueRequest::new(minimal_fields().with_description("first line\nsecond line"))
                .into_wire()
                .expect("plain text is always writable");

        assert_eq!(
            serde_json::to_value(&request.fields).expect("serializes")["description"],
            json!({
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "first line"},
                        {"type": "hardBreak"},
                        {"type": "text", "text": "second line"}
                    ]
                }]
            })
        );
    }

    #[test]
    fn an_unwritable_description_is_refused_before_a_body_exists() {
        let description: RichText =
            serde_json::from_value(json!({"type": "richTextV4"})).expect("parses");
        let error = V3CreateIssueRequest::new(minimal_fields().with_description(description))
            .into_wire()
            .expect_err("an `Unknown` description must not be writable");

        assert!(
            matches!(error, AtlassianError::Validation { .. }),
            "expected a validation error, got {error:?}"
        );
    }

    #[test]
    fn a_description_with_no_description_stays_absent() {
        let request = V3CreateIssueRequest::new(minimal_fields())
            .into_wire()
            .expect("writable");

        assert!(
            serde_json::to_value(&request.fields).expect("serializes")["description"].is_null(),
            "normalization invented a description"
        );
    }

    #[test]
    fn narrowed_response_fields_parse() {
        // What today's `IssueFields` cannot do: `fields=summary` returns a
        // `fields` object with no `issuetype`, no `status` and no `project`, and
        // a model that requires any of them fails the whole read.
        let fields: V3IssueFields =
            serde_json::from_value(json!({"summary": "only this"})).expect("parses");

        assert_eq!(fields.summary.as_deref(), Some("only this"));
        assert!(fields.issue_type.is_none());
        assert!(fields.status.is_none());
        assert!(fields.project.is_none());
        assert!(fields.labels.is_none(), "absent must not read as empty");
    }

    #[test]
    fn an_empty_fields_object_parses() {
        let fields: V3IssueFields = serde_json::from_value(json!({})).expect("parses");
        assert_eq!(fields, V3IssueFields::default());
    }

    #[test]
    fn an_issue_with_no_fields_member_parses() {
        let issue: V3Issue = serde_json::from_value(json!({
            "id": "10077",
            "key": "KAN-77"
        }))
        .expect("parses");

        assert_eq!(issue.key, "KAN-77");
        assert_eq!(issue.fields, V3IssueFields::default());
        assert!(issue.self_url.is_none());
    }

    #[test]
    fn unmodelled_fields_survive_a_round_trip() {
        let raw = json!({
            "id": "10077",
            "key": "KAN-77",
            "self": "https://example.atlassian.net/rest/api/3/issue/10077",
            "fields": {
                "summary": "Upgrade openssl",
                "customfield_10010": {"value": "Security"},
                "timetracking": {"remainingEstimate": "3h"}
            }
        });

        let issue: V3Issue = serde_json::from_value(raw.clone()).expect("parses");

        assert_eq!(
            issue.fields.other.get("customfield_10010"),
            Some(&json!({"value": "Security"}))
        );
        assert_eq!(
            serde_json::to_value(&issue).expect("serializes"),
            raw,
            "a field this crate does not model was dropped or rewritten"
        );
    }

    #[test]
    fn an_explicit_null_survives_for_an_unmodelled_field_and_is_dropped_for_a_modelled_one() {
        // A real `GET /rest/api/3/issue/{key}` response is full of explicit
        // nulls; the fixture in `unmodelled_fields_survive_a_round_trip` has
        // none, which is how this asymmetry went unnoticed. It is documented
        // rather than removed: on a *read* `null` and absent mean the same
        // thing, and this crate never echoes a `fields` object it read back as a
        // request body. This test is what stops the documentation from quietly
        // ceasing to be true -- in either direction, since a modelled member
        // that started preserving its null would also land here.
        let raw = json!({
            "id": "10077",
            "key": "KAN-77",
            "fields": {
                "summary": "Upgrade openssl",
                "description": null,
                "assignee": null,
                "resolution": null,
                "resolutiondate": null,
                "parent": null,
                "labels": null,
                "customfield_10010": null,
                "timetracking": null
            }
        });

        let issue: V3Issue = serde_json::from_value(raw).expect("explicit nulls parse");

        // A modelled member: `null` is indistinguishable from never-returned.
        assert!(issue.fields.description.is_none());
        assert!(issue.fields.assignee.is_none());
        assert!(issue.fields.resolution.is_none());
        assert!(issue.fields.resolution_date.is_none());
        assert!(issue.fields.parent.is_none());
        assert!(issue.fields.labels.is_none());
        assert!(
            !issue.fields.other.contains_key("assignee"),
            "a modelled member's null was captured as an unmodelled field"
        );

        // An unmodelled one keeps the null itself.
        assert_eq!(
            issue.fields.other.get("customfield_10010"),
            Some(&Value::Null)
        );
        assert_eq!(issue.fields.other.get("timetracking"), Some(&Value::Null));

        assert_eq!(
            serde_json::to_value(&issue).expect("serializes"),
            json!({
                "id": "10077",
                "key": "KAN-77",
                "fields": {
                    "summary": "Upgrade openssl",
                    "customfield_10010": null,
                    "timetracking": null
                }
            }),
            "the documented round-trip exception changed shape"
        );
    }

    #[test]
    fn an_update_body_keeps_an_explicit_null_because_that_is_how_a_field_is_cleared() {
        // The other half of the null story, and the reason the read model's
        // asymmetry is documentable rather than dangerous: a write says what it
        // means. `null` here reaches Jira as `null` and clears the field, and a
        // field that is not staged is not in the body at all.
        let body = serde_json::to_value(
            V3UpdateIssueRequest::new()
                .with_field("assignee", Value::Null)
                .with_field("summary", "Upgrade openssl to 3.5.4"),
        )
        .expect("serializes");

        assert_eq!(
            body,
            json!({"fields": {
                "assignee": null,
                "summary": "Upgrade openssl to 3.5.4"
            }})
        );
        assert!(
            body["fields"]["priority"].is_null() && body["fields"].get("priority").is_none(),
            "an unstaged field reached the body: {body}"
        );
    }

    #[test]
    fn a_v2_era_string_description_reads_back_as_text() {
        let fields: V3IssueFields =
            serde_json::from_value(json!({"description": "written through v2"})).expect("parses");

        assert_eq!(
            fields.description,
            Some(RichText::Text("written through v2".to_string()))
        );
    }

    #[test]
    fn an_adf_description_reads_back_as_adf() {
        let fields: V3IssueFields = serde_json::from_value(json!({
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{"type": "paragraph", "content": [{"type": "text", "text": "hi"}]}]
            }
        }))
        .expect("parses");

        assert!(matches!(fields.description, Some(RichText::Adf(_))));
    }

    #[test]
    fn a_status_carries_its_tenant_independent_category() {
        let fields: V3IssueFields = serde_json::from_value(json!({
            "status": {
                "id": "10002",
                "name": "Shipped",
                "statusCategory": {"id": 3, "key": "done", "name": "Done", "colorName": "green"}
            }
        }))
        .expect("parses");

        let category = fields
            .status
            .and_then(|status| status.status_category)
            .expect("the category parses");
        assert_eq!(category.key.as_deref(), Some("done"));
        assert_eq!(category.id, Some(3));
    }

    #[test]
    fn a_create_response_keeps_the_id_and_the_self_url() {
        // The v2 response type discards both. The id is the identifier that
        // survives a project key rename, so throwing it away costs a caller the
        // only handle Jira's own reconciliation parameter accepts.
        let created: V3CreatedIssue = serde_json::from_value(json!({
            "id": "10077",
            "key": "KAN-77",
            "self": "https://example.atlassian.net/rest/api/3/issue/10077"
        }))
        .expect("parses");

        assert_eq!(created.id, "10077");
        assert_eq!(created.key, "KAN-77");
        assert_eq!(
            created.self_url.as_deref(),
            Some("https://example.atlassian.net/rest/api/3/issue/10077")
        );
    }

    #[test]
    fn an_update_is_empty_until_something_is_staged() {
        assert!(V3UpdateIssueRequest::new().is_empty());
        assert!(!V3UpdateIssueRequest::new()
            .with_field("summary", "x")
            .is_empty());
        assert!(!V3UpdateIssueRequest::new()
            .with_update("labels", json!([{"add": "x"}]))
            .is_empty());
    }

    #[test]
    fn an_update_carrying_operations_is_tagged_as_an_unsafe_write() {
        // `{"update": {"comment": [{"add": ...}]}}` is a legal update body, and
        // replaying it posts a second comment. A `fields`-only update sets
        // values and converges on replay, so the two cannot share one tag.
        assert_eq!(
            V3UpdateIssueRequest::new()
                .with_field("summary", "x")
                .idempotency(),
            Idempotency::Safe
        );
        assert_eq!(
            V3UpdateIssueRequest::new()
                .with_update("comment", json!([{"add": {"body": "hi"}}]))
                .idempotency(),
            Idempotency::UnsafeWrite
        );
    }

    #[test]
    fn an_update_body_omits_the_half_that_is_empty() {
        assert_eq!(
            serde_json::to_value(V3UpdateIssueRequest::new().with_field("summary", "x"))
                .expect("serializes"),
            json!({"fields": {"summary": "x"}})
        );
        assert_eq!(
            serde_json::to_value(V3UpdateIssueRequest::new()).expect("serializes"),
            json!({})
        );
    }

    #[test]
    fn update_fields_serialize_in_a_stable_order() {
        let rendered = serde_json::to_string(
            &V3UpdateIssueRequest::new()
                .with_field("summary", "x")
                .with_field("description", Value::Null)
                .with_field("assignee", Value::Null),
        )
        .expect("serializes");

        let assignee = rendered.find("assignee").expect("assignee");
        let description = rendered.find("description").expect("description");
        let summary = rendered.find("summary").expect("summary");
        assert!(
            assignee < description && description < summary,
            "update fields are not in key order: {rendered}"
        );
    }

    #[test]
    fn default_read_options_ask_for_nothing() {
        assert!(V3GetIssueOptions::new().query().is_empty());
        assert_eq!(V3GetIssueOptions::default(), V3GetIssueOptions::new());
    }

    #[test]
    fn read_options_join_their_selectors_with_commas() {
        let query = V3GetIssueOptions::new()
            .with_fields(["summary", "description"])
            .with_expand(["renderedFields"])
            .query();

        assert_eq!(
            query.get("fields").map(String::as_str),
            Some("summary,description")
        );
        assert_eq!(
            query.get("expand").map(String::as_str),
            Some("renderedFields")
        );
    }
}
