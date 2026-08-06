//! A scriptable Jira mock with a request journal.
//!
//! Two things the plain `wiremock` idiom does not give a retry or
//! reconciliation test: a *sequence* of responses for one endpoint, so attempt 1
//! can 429 and attempt 2 can succeed; and an exact call count, so a test that
//! returns the right issue key while silently creating two issues fails. Both
//! are here — sequencing through per-step priorities, counting through the
//! server's own request journal.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// One response in a scripted sequence.
#[derive(Debug, Clone)]
pub struct Step {
    status: u16,
    body: Option<(Vec<u8>, String)>,
    headers: Vec<(String, String)>,
    delay: Option<Duration>,
}

impl Step {
    /// A response with a status and no body.
    pub const fn status(status: u16) -> Self {
        Self {
            status,
            body: None,
            headers: Vec::new(),
            delay: None,
        }
    }

    /// A JSON response.
    pub fn json(status: u16, body: &Value) -> Self {
        Self::json_str(status, &body.to_string())
    }

    /// A JSON response from already-serialized text, such as a fixture.
    pub fn json_str(status: u16, body: &str) -> Self {
        Self {
            status,
            body: Some((body.as_bytes().to_vec(), "application/json".to_string())),
            headers: Vec::new(),
            delay: None,
        }
    }

    /// A response with a raw body and an explicit content type.
    pub fn raw(status: u16, body: &[u8], content_type: &str) -> Self {
        Self {
            status,
            body: Some((body.to_vec(), content_type.to_string())),
            headers: Vec::new(),
            delay: None,
        }
    }

    /// Adds a response header, such as `Retry-After`.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Delays the response, for driving a client-side timeout.
    #[must_use]
    pub const fn delay(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }

    fn template(self) -> ResponseTemplate {
        let mut template = ResponseTemplate::new(self.status);
        if let Some((body, content_type)) = self.body {
            template = template.set_body_raw(body, &content_type);
        }
        for (name, value) in self.headers {
            template = template.insert_header(name.as_str(), value.as_str());
        }
        if let Some(delay) = self.delay {
            template = template.set_delay(delay);
        }
        template
    }
}

/// One request the mock server received.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    /// Uppercase HTTP method.
    pub method: String,
    /// Request path, without the query string.
    pub path: String,
    /// Raw query string, if the request carried one.
    pub query: Option<String>,
    /// Request headers. A repeated name keeps its last value.
    pub headers: BTreeMap<String, String>,
    /// Raw request body.
    pub body: Vec<u8>,
}

impl RecordedRequest {
    fn from_request(request: &Request) -> Self {
        Self {
            method: request.method.as_str().to_ascii_uppercase(),
            path: request.url.path().to_string(),
            query: request.url.query().map(ToString::to_string),
            headers: request
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_string(),
                        value.to_str().unwrap_or_default().to_string(),
                    )
                })
                .collect(),
            body: request.body.clone(),
        }
    }

    /// Parses the body as JSON, or returns `None` if it is not JSON.
    pub fn body_json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// Returns the body as text, replacing invalid UTF-8.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A Jira mock server with response scripting and a request journal.
#[derive(Debug)]
pub struct JiraMock {
    server: MockServer,
}

impl JiraMock {
    /// Starts a mock server on a loopback port.
    pub async fn start() -> Self {
        Self {
            server: MockServer::start().await,
        }
    }

    /// Returns the server's base URL.
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Returns an absolute URL for `endpoint` on this server.
    pub fn url(&self, endpoint: &str) -> String {
        format!("{}/{}", self.uri(), endpoint.trim_start_matches('/'))
    }

    /// Returns the underlying server, for matchers this type does not wrap.
    pub const fn server(&self) -> &MockServer {
        &self.server
    }

    /// Mounts one unbounded response for `method` and `endpoint`.
    pub async fn stub(&self, http_method: &str, endpoint: &str, step: Step) {
        self.script(http_method, endpoint, vec![step]).await;
    }

    /// Mounts a response per attempt for `method` and `endpoint`.
    ///
    /// Step *i* answers attempt *i*; the last step answers every attempt after
    /// it, so a two-step script is "fail once, then succeed forever" rather than
    /// "fail once, then 404".
    ///
    /// # Panics
    ///
    /// Panics if `steps` is empty or longer than 255, which is the number of
    /// distinct priorities `wiremock` can order.
    pub async fn script(&self, http_method: &str, endpoint: &str, steps: Vec<Step>) {
        assert!(!steps.is_empty(), "a script needs at least one step");
        assert!(
            u8::try_from(steps.len()).is_ok(),
            "a script is limited to {} steps",
            u8::MAX
        );

        let last = steps.len() - 1;
        for (index, step) in steps.into_iter().enumerate() {
            let priority = u8::try_from(index + 1).expect("step count is bounded by u8::MAX");
            let mut mock = Mock::given(method(http_method))
                .and(path(endpoint))
                .respond_with(step.template())
                .with_priority(priority);
            if index != last {
                mock = mock.up_to_n_times(1);
            }
            mock.mount(&self.server).await;
        }
    }

    /// Returns every request the server received, in order.
    ///
    /// # Panics
    ///
    /// Panics if request recording was disabled on the server.
    pub async fn journal(&self) -> Vec<RecordedRequest> {
        self.server
            .received_requests()
            .await
            .expect("request recording should be enabled")
            .iter()
            .map(RecordedRequest::from_request)
            .collect()
    }

    /// Counts the requests received for `method` and `endpoint`.
    pub async fn call_count(&self, http_method: &str, endpoint: &str) -> usize {
        self.journal()
            .await
            .iter()
            .filter(|request| {
                request.method.eq_ignore_ascii_case(http_method) && request.path == endpoint
            })
            .count()
    }

    /// Asserts the exact number of requests for `method` and `endpoint`.
    ///
    /// # Panics
    ///
    /// Panics naming the expected and actual counts.
    pub async fn assert_call_count(&self, http_method: &str, endpoint: &str, expected: usize) {
        let actual = self.call_count(http_method, endpoint).await;
        assert_eq!(
            actual, expected,
            "{http_method} {endpoint} was called {actual} times, expected {expected}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{JiraMock, Step};
    use crate::fixtures;

    const SEARCH: &str = "/rest/api/3/search/jql";
    const CREATE: &str = "/rest/api/3/issue";

    #[tokio::test]
    async fn script_answers_one_step_per_attempt_then_repeats_the_last() {
        let mock = JiraMock::start().await;
        mock.script(
            "GET",
            SEARCH,
            vec![
                Step::status(429).header("Retry-After", "2"),
                Step::json_str(200, fixtures::jira_body("search-empty")),
            ],
        )
        .await;

        let client = reqwest::Client::new();
        let url = mock.url(SEARCH);

        let first = client.get(&url).send().await.expect("first attempt");
        assert_eq!(first.status().as_u16(), 429);
        assert_eq!(
            first
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("2")
        );

        for _ in 0..2 {
            let retry = client.get(&url).send().await.expect("retry");
            assert_eq!(retry.status().as_u16(), 200);
            let body: serde_json::Value = retry.json().await.expect("json body");
            assert_eq!(body["total"], 0);
        }

        mock.assert_call_count("GET", SEARCH, 3).await;
    }

    #[tokio::test]
    async fn journal_records_method_path_query_and_body() {
        let mock = JiraMock::start().await;
        mock.stub(
            "POST",
            CREATE,
            Step::json_str(201, fixtures::jira_body("create-issue-response")),
        )
        .await;

        let response = reqwest::Client::new()
            .post(format!("{}?updateHistory=false", mock.url(CREATE)))
            .json(&serde_json::json!({"fields": {"summary": "Bump foo"}}))
            .send()
            .await
            .expect("create");
        assert_eq!(response.status().as_u16(), 201);

        let journal = mock.journal().await;
        assert_eq!(journal.len(), 1);
        assert_eq!(journal[0].method, "POST");
        assert_eq!(journal[0].path, CREATE);
        assert_eq!(journal[0].query.as_deref(), Some("updateHistory=false"));
        assert_eq!(
            journal[0].body_json().expect("json body")["fields"]["summary"],
            "Bump foo"
        );
        assert_eq!(
            journal[0].headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
    }

    #[tokio::test]
    async fn call_count_distinguishes_endpoints_and_methods() {
        let mock = JiraMock::start().await;
        mock.stub("GET", SEARCH, Step::json_str(200, r#"{"issues":[]}"#))
            .await;
        mock.stub("POST", CREATE, Step::status(201)).await;

        let client = reqwest::Client::new();
        client.get(mock.url(SEARCH)).send().await.expect("search");
        client.get(mock.url(SEARCH)).send().await.expect("search");
        client.post(mock.url(CREATE)).send().await.expect("create");

        mock.assert_call_count("GET", SEARCH, 2).await;
        mock.assert_call_count("POST", CREATE, 1).await;
        assert_eq!(mock.call_count("POST", SEARCH).await, 0);
    }

    #[tokio::test]
    #[should_panic(expected = "a script needs at least one step")]
    async fn empty_script_is_rejected() {
        let mock = JiraMock::start().await;
        mock.script("GET", SEARCH, Vec::new()).await;
    }
}
