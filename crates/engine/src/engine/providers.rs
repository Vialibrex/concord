use std::sync::Arc;
use std::time::SystemTime;

use concord_group::{FetchErrorKind, Outbounds, ProviderError, ProxyProvider};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::Engine;
use crate::error::{BoxError, Failure, ResourceError};
use crate::resources::{RuleProvider, RuleProviders, behavior_of};
use crate::views::{ProviderView, SubscriptionInfo};

/// The proxy and rule providers of the config in force.
pub struct Providers<'a> {
    pub(super) engine: &'a Engine,
}

impl Providers<'_> {
    fn rule_providers(&self) -> Option<Arc<RuleProviders>> {
        self.engine.shared.rule_providers.load_full()
    }

    fn outbounds(&self) -> Option<Arc<Outbounds>> {
        self.engine.outbounds()
    }

    pub fn list(&self) -> Vec<ProviderView> {
        let mut views: Vec<ProviderView> = Vec::new();
        if let Some(outbounds) = self.outbounds() {
            for provider in outbounds.providers() {
                if provider.is_external() {
                    views.push(proxy_provider_view(&provider));
                }
            }
        }
        if let Some(rules) = self.rule_providers() {
            for provider in &rules.list {
                if provider.is_listed() {
                    views.push(rule_provider_view(provider));
                }
            }
        }
        views.sort_by(|a, b| a.name.cmp(&b.name));
        views
    }

    pub fn get(&self, name: &str) -> Option<ProviderView> {
        if let Some(rules) = self.rule_providers()
            && let Some(provider) = rules.get(name)
        {
            return provider.is_listed().then(|| rule_provider_view(provider));
        }
        let provider = self.outbounds()?.provider(name)?;
        provider
            .is_external()
            .then(|| proxy_provider_view(&provider))
    }

    pub async fn update(&self, name: &str) -> Result<(), Failure> {
        if let Some(rules) = self.rule_providers()
            && let Some(provider) = rules.get(name)
        {
            let provider: Arc<RuleProvider> = provider.clone();
            if !rules.claim(&provider) {
                return Err(updating_failure(name));
            }
            let outcome = rules.reported(&provider, rules.pull(&provider)).await;
            rules.release(&provider);
            outcome.map_err(|err| request_failure(err, Some(name)))?;
            self.refresh_route();
            return Ok(());
        }
        self.proxy_provider(name)?
            .update()
            .await
            .map_err(|err| proxy_update_failure(name, err))?;
        self.refresh_route();
        Ok(())
    }

    /// Tests every node of a proxy provider at its own URL, as its timer would.
    pub async fn health_check(&self, name: &str) -> Result<(), Failure> {
        let provider = self.proxy_provider(name)?;
        let outbounds = self.outbounds().ok_or_else(|| not_found(name))?;
        provider.health_check(&outbounds).await;
        Ok(())
    }

    pub async fn side_load(&self, name: &str, data: String) -> Result<(), Failure> {
        if let Some(rules) = self.rule_providers()
            && let Some(provider) = rules.get(name)
        {
            if !provider.is_listed() {
                return Err(update_failure(name, "not external provider"));
            }
            let provider: Arc<RuleProvider> = provider.clone();
            if !rules.claim(&provider) {
                return Err(updating_failure(name));
            }
            let outcome = rules.side_load(&provider, data.into_bytes()).await;
            rules.release(&provider);
            outcome.map_err(|err| update_failure(name, err))?;
            self.refresh_route();
            return Ok(());
        }
        self.proxy_provider(name)?
            .side_load(data.as_bytes())
            .await
            .map_err(|err| match err {
                ProviderError::Updating => updating_failure(name),
                other => update_failure(name, other),
            })?;
        self.refresh_route();
        Ok(())
    }

    fn proxy_provider(&self, name: &str) -> Result<Arc<ProxyProvider>, Failure> {
        self.outbounds()
            .and_then(|outbounds| outbounds.provider(name))
            .ok_or_else(|| not_found(name))
    }

    fn refresh_route(&self) {
        if let Some(outbounds) = self.outbounds() {
            outbounds.refresh_picks();
        }
    }
}

fn time_text(at: Option<SystemTime>) -> String {
    at.and_then(|at| OffsetDateTime::from(at).format(&Rfc3339).ok())
        .unwrap_or_else(|| "0001-01-01T00:00:00Z".to_string())
}

fn proxy_provider_view(provider: &ProxyProvider) -> ProviderView {
    ProviderView {
        name: provider.name().to_string(),
        kind: "Proxy",
        vehicle_type: provider.vehicle_type().as_str(),
        count: provider.count(),
        path: provider.path(),
        update_at: time_text(provider.updated_at()),
        subscription_info: provider.subscription_info().map(|info| SubscriptionInfo {
            upload: info.upload,
            download: info.download,
            total: info.total,
            expire: info.expire,
        }),
        test_url: provider.health_check_url().to_string(),
        expected_status: provider.expected_text().to_string(),
        behavior: "",
        format: "",
    }
}

fn rule_provider_view(provider: &RuleProvider) -> ProviderView {
    ProviderView {
        name: provider.def.name.clone(),
        kind: "Rule",
        vehicle_type: provider.vehicle(),
        count: provider.handle.count(),
        path: provider.path_text(),
        update_at: time_text(provider.updated_at()),
        subscription_info: None,
        test_url: String::new(),
        expected_status: String::new(),
        behavior: behavior_of(provider.def.behavior).name(),
        format: concord_rules::Format::from(provider.def.format).name(),
    }
}

fn updating_failure(name: &str) -> Failure {
    Failure::ProviderUpdating {
        provider: name.to_string(),
    }
}

fn not_found(name: &str) -> Failure {
    Failure::ProviderNotFound {
        provider: name.to_string(),
    }
}

fn update_failure(name: &str, source: impl Into<BoxError>) -> Failure {
    Failure::ProviderUpdate {
        provider: name.to_string(),
        source: source.into(),
    }
}

/// A download that failed, for the provider named, if any.
pub(super) fn request_failure(err: ResourceError, provider: Option<&str>) -> Failure {
    let timed_out = match &err {
        ResourceError::Status(_) => false,
        ResourceError::Fetch(fetch) => fetch.kind == FetchErrorKind::Timeout,
        ResourceError::Other(_) | ResourceError::Load(_) => match provider {
            Some(name) => return update_failure(name, err),
            None => return Failure::core(err.to_string()),
        },
    };
    Failure::Request {
        provider: provider.map(str::to_string),
        timed_out,
        source: err.into(),
    }
}

fn proxy_update_failure(name: &str, err: ProviderError) -> Failure {
    let timed_out = match &err {
        ProviderError::NotFound => return not_found(name),
        ProviderError::Updating => return updating_failure(name),
        ProviderError::Status(_) => false,
        ProviderError::Fetch(fetch) => fetch.kind == FetchErrorKind::Timeout,
        ProviderError::Content(_) | ProviderError::Io(_) => return update_failure(name, err),
    };
    Failure::Request {
        provider: Some(name.to_string()),
        timed_out,
        source: err.into(),
    }
}
