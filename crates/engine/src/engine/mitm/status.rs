//! What `mitm.moduleStatus` answers: each module the profile names and how it stands.

use concord_config::mitm::module::{ModuleOff, NetworkDef, ResourceKind};
use concord_config::mitm::modules::{AppliedModule, ModuleProblem, RefusedRule, host_network};
use serde::Serialize;

use super::store::ModuleResources;
pub use super::store::{FailureReason, FetchFailure, ResourceState};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleStatus {
    pub name: String,
    pub enabled: bool,
    pub in_force: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<ModuleProblem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub off: Option<ModuleOff>,
    pub resources: Vec<ResourceStatus>,
    /// Rules left out of the profile, by the module line that wrote them.
    pub refused_rules: Vec<RefusedRule>,
    /// What of the module's network requests the host carries out.
    pub host_network: NetworkDef,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceStatus {
    pub url: String,
    pub kind: ResourceKind,
    pub lines: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub state: ResourceState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<FetchFailure>,
}

pub(super) fn module_status(module: &AppliedModule, resources: &ModuleResources) -> ModuleStatus {
    ModuleStatus {
        name: module.spec.name.clone(),
        enabled: module.spec.enabled,
        in_force: module.in_force(),
        problem: module.problem.clone(),
        off: module.def.off.clone(),
        resources: module
            .def
            .resources
            .iter()
            .map(|resource| {
                let (state, error) = resources.state(&resource.url);
                ResourceStatus {
                    url: resource.url.clone(),
                    kind: resource.kind,
                    lines: resource.lines.clone(),
                    file: resources.stored(&resource.url),
                    state,
                    error,
                }
            })
            .collect(),
        refused_rules: module.refused_rules.clone(),
        host_network: host_network(std::slice::from_ref(module)),
    }
}
