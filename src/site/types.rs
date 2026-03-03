use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub site_key: Uuid,
    pub secret_key: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}
