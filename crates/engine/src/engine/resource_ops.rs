use std::sync::Arc;

use super::providers::request_failure;
use super::{Engine, NOT_INITIALIZED};
use crate::error::Failure;
use crate::ops::{self, RuleSetSource};
use crate::resources;
use crate::views::RuleSetInfo;

impl Engine {
    pub async fn compile_rule_set(&self, name: &str, url: &str) -> Result<RuleSetInfo, Failure> {
        let home = self.home().ok_or_else(|| Failure::core(NOT_INITIALIZED))?;
        let valid = !name.is_empty()
            && !name.starts_with('.')
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
        if !valid {
            return Err(Failure::InvalidArguments(
                "invalid rule set name".to_string(),
            ));
        }
        let source = home.join("providers").join("rules").join(name);
        let downloaded = !url.is_empty();
        let from = if downloaded {
            RuleSetSource::Downloaded(
                resources::download(&*self.shared.fetcher, resources::rule_set_request(url))
                    .await
                    .map_err(|err| request_failure(err, None))?,
            )
        } else {
            RuleSetSource::Local(source.clone())
        };
        let (bytes, compiled) = ops::compile_rule_set(from).await?;
        if downloaded {
            home.write_atomic(&source, &bytes)?;
        }
        if let Some(mrs) = &compiled.mrs {
            let mut target = source.clone().into_os_string();
            target.push(".mrs");
            home.write_atomic(std::path::PathBuf::from(target), mrs)?;
        }
        Ok(RuleSetInfo {
            behavior: compiled.info.behavior.name(),
            format: compiled.info.format.name(),
        })
    }

    pub fn geo_update(self: &Arc<Self>, kind: &str) -> Result<(), Failure> {
        let file =
            resources::geo_file_of(kind).ok_or_else(|| Failure::UnknownGeo(kind.to_string()))?;
        let claim = self
            .shared
            .geo
            .claim(file)
            .ok_or_else(|| Failure::GeoUpdating(kind.to_string()))?;
        self.shared
            .geo
            .spawn_update(claim, self.shared.fetcher.clone(), &self.tasks);
        Ok(())
    }
}
