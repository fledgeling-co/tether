use crate::storage::ServiceKind;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSummary {
    pub id: String,
    pub kind: ServiceKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStatus {
    pub services: Vec<ServiceSummary>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OwnerInspection {
    pub app_id: String,
    pub host_id: String,
    pub services: Vec<ServiceSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PairingStatus {
    pub open: bool,
    pub expires_in_seconds: u64,
    pub attempts_remaining: u8,
}
