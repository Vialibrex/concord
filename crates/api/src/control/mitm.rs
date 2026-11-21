use concord_common::exchange_query::{ContentKind, ExchangeFilter, ExchangeQuery, StatusClass};
use concord_engine::{Engine, Failure};
use concord_proto::ApiError;
use concord_proto::types::*;

use super::{Control, core_error};

impl Control {
    fn mitm_enabled(&self) -> Result<(), ApiError> {
        if self.engine.capabilities().features.mitm {
            Ok(())
        } else {
            Err(ApiError::unsupported_capability(
                "mitm",
                "this build has no MITM",
            ))
        }
    }

    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Engine) -> Result<T, Failure> + Send + 'static,
    ) -> Result<T, ApiError> {
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || work(&engine))
            .await
            .map_err(|err| ApiError::internal(err.to_string()))?
            .map_err(core_error)
    }

    pub(super) async fn mitm_certificate(
        &self,
        _params: Empty,
    ) -> Result<MitmCertificate, ApiError> {
        self.mitm_enabled()?;
        let certificate = self.blocking(|engine| engine.mitm().certificate()).await?;
        Ok(MitmCertificate { certificate })
    }

    pub(super) async fn mitm_generate_certificate(
        &self,
        _params: Empty,
    ) -> Result<MitmCertificate, ApiError> {
        self.mitm_enabled()?;
        let certificate = self
            .blocking(|engine| engine.mitm().generate_certificate())
            .await?;
        Ok(MitmCertificate {
            certificate: Some(certificate),
        })
    }

    pub(super) async fn mitm_validate(
        &self,
        params: MitmValidateParams,
    ) -> Result<MitmValidateResult, ApiError> {
        self.mitm_enabled()?;
        let validation = self
            .blocking(move |engine| engine.mitm().validate(params.config))
            .await?;
        serde_json::from_value(validation).map_err(|err| ApiError::internal(err.to_string()))
    }

    pub(super) async fn mitm_read_module(
        &self,
        params: MitmModuleReadParams,
    ) -> Result<MitmModuleView, ApiError> {
        self.mitm_enabled()?;
        let view = self
            .blocking(move |engine| {
                engine.mitm().read_module(
                    &params.text,
                    &params.arguments,
                    &params.attachments,
                    params.language,
                )
            })
            .await?;
        serde_json::from_value(view).map_err(|err| ApiError::internal(err.to_string()))
    }

    pub(super) async fn mitm_module_status(
        &self,
        _params: Empty,
    ) -> Result<MitmModuleStatusList, ApiError> {
        self.mitm_enabled()?;
        let status = self.engine.mitm().module_status().map_err(core_error)?;
        serde_json::from_value(status).map_err(|err| ApiError::internal(err.to_string()))
    }

    pub(super) async fn mitm_fetch_module(
        &self,
        params: MitmFetchModuleParams,
    ) -> Result<Empty, ApiError> {
        self.mitm_enabled()?;
        self.engine
            .mitm()
            .fetch_module(params.name)
            .map_err(core_error)?;
        Ok(Empty {})
    }

    pub(super) async fn mitm_issue_certificate(
        &self,
        params: MitmIssueParams,
    ) -> Result<MitmPem, ApiError> {
        self.mitm_enabled()?;
        if params.host.is_empty() {
            return Err(ApiError::invalid_field("host", "host must not be empty"));
        }
        let pem = self
            .blocking(move |engine| engine.mitm().issue_certificate(&params.host))
            .await?;
        Ok(MitmPem { pem })
    }

    pub(super) async fn mitm_run_script(
        &self,
        params: MitmScriptParams,
    ) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let result = self
            .engine
            .mitm()
            .run_script(&params.name)
            .await
            .map_err(core_error)?;
        Ok(MitmResult { result })
    }

    pub(super) async fn mitm_exchanges(
        &self,
        params: MitmExchangesParams,
    ) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let id = self
            .engine
            .connection_id(params.connection)
            .ok_or_else(|| ApiError::not_found("connection", params.connection.to_string()))?;
        let result = self.engine.mitm().exchanges(&id).map_err(core_error)?;
        Ok(MitmResult { result })
    }

    pub(super) async fn mitm_query(
        &self,
        params: MitmQueryParams,
    ) -> Result<MitmQueryAnswer, ApiError> {
        self.mitm_enabled()?;
        let query = exchange_query(params)?;
        let answer = self.engine.mitm().query(&query).map_err(core_error)?;
        serde_json::from_value(answer)
            .map_err(|err| ApiError::internal(format!("the capture's answer: {err}")))
    }

    pub(super) async fn mitm_exchange(
        &self,
        params: MitmExchangeParams,
    ) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let result = self.engine.mitm().exchange(params.id).map_err(core_error)?;
        Ok(MitmResult { result })
    }

    pub(super) async fn mitm_body(&self, params: MitmBodyParams) -> Result<MitmResult, ApiError> {
        self.mitm_enabled()?;
        let result = self
            .engine
            .mitm()
            .body(params.id, params.response)
            .map_err(core_error)?;
        Ok(MitmResult { result })
    }
}

/// A page of `mitm.query` holds at most this many summaries, and this many when the
/// host names no `limit`.
const PAGE_LIMIT: u32 = 64;
/// Longer than any URL the capture can hold, so a longer `text` would match nothing.
const TEXT_LIMIT: usize = 8192 + 4096 * 100;
/// Values one filter list may name.
const LIST_LIMIT: usize = 64;

fn exchange_query(params: MitmQueryParams) -> Result<ExchangeQuery, ApiError> {
    let filter = params.filter;
    let limit = params.limit.unwrap_or(PAGE_LIMIT);
    if !(1..=PAGE_LIMIT).contains(&limit) {
        return Err(ApiError::invalid_params(format!(
            "limit must be from 1 to {PAGE_LIMIT}"
        )));
    }
    for (name, value) in [
        ("before", params.before),
        ("slowMs", filter.slow_ms),
        ("from", filter.from),
        ("to", filter.to),
        ("rateFrom", params.rate_from),
    ] {
        if value.is_some_and(|value| value < 0) {
            return Err(ApiError::invalid_params(format!(
                "{name} must not be negative"
            )));
        }
    }
    if let (Some(from), Some(to)) = (filter.from, filter.to)
        && from > to
    {
        return Err(ApiError::invalid_params("from must not be after to"));
    }
    for (name, list) in [
        ("methods", &filter.methods),
        ("hosts", &filter.hosts),
        ("apps", &filter.apps),
    ] {
        if list.len() > LIST_LIMIT || list.iter().any(|value| value.len() > TEXT_LIMIT) {
            return Err(ApiError::invalid_params(format!(
                "{name} holds at most {LIST_LIMIT} values of at most {TEXT_LIMIT} bytes"
            )));
        }
    }
    if filter
        .text
        .as_ref()
        .is_some_and(|text| text.len() > TEXT_LIMIT)
    {
        return Err(ApiError::invalid_params(format!(
            "text holds at most {TEXT_LIMIT} bytes"
        )));
    }
    Ok(ExchangeQuery {
        filter: ExchangeFilter {
            statuses: filter.statuses.into_iter().map(status_class).collect(),
            methods: filter.methods,
            kinds: filter.kinds.into_iter().map(content_kind).collect(),
            hosts: filter.hosts,
            apps: filter.apps,
            rewritten: filter.rewritten,
            slow_ms: filter.slow_ms,
            text: filter.text,
            from_ms: filter.from,
            to_ms: filter.to,
        },
        before: params.before,
        limit: Some(limit as usize),
        since: params.since,
        facets: params.facets,
        rate_from_ms: params.rate_from,
    })
}

fn status_class(status: MitmStatus) -> StatusClass {
    match status {
        MitmStatus::Informational => StatusClass::Informational,
        MitmStatus::Success => StatusClass::Success,
        MitmStatus::Redirect => StatusClass::Redirect,
        MitmStatus::ClientError => StatusClass::ClientError,
        MitmStatus::ServerError => StatusClass::ServerError,
        MitmStatus::Failed => StatusClass::Failed,
        MitmStatus::Pending => StatusClass::Pending,
    }
}

fn content_kind(kind: MitmKind) -> ContentKind {
    match kind {
        MitmKind::Json => ContentKind::Json,
        MitmKind::Html => ContentKind::Html,
        MitmKind::Script => ContentKind::Script,
        MitmKind::Css => ContentKind::Css,
        MitmKind::Image => ContentKind::Image,
        MitmKind::Font => ContentKind::Font,
        MitmKind::Media => ContentKind::Media,
        MitmKind::Text => ContentKind::Text,
        MitmKind::Other => ContentKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use concord_proto::ErrorData;

    use super::*;

    fn refused(params: MitmQueryParams) -> String {
        match exchange_query(params) {
            Err(ApiError {
                data: ErrorData::InvalidParams { .. },
                message,
                ..
            }) => message,
            other => panic!("not refused as invalid params: {other:?}"),
        }
    }

    fn with_filter(filter: MitmFilter) -> MitmQueryParams {
        MitmQueryParams {
            filter,
            ..MitmQueryParams::default()
        }
    }

    #[test]
    fn every_part_of_the_params_reaches_the_query() {
        let query = exchange_query(MitmQueryParams {
            filter: MitmFilter {
                statuses: vec![MitmStatus::ServerError, MitmStatus::Failed],
                methods: vec!["post".into()],
                kinds: vec![MitmKind::Json, MitmKind::Media],
                hosts: vec!["a.test".into()],
                apps: vec!["chrome".into()],
                rewritten: Some(true),
                slow_ms: Some(500),
                text: Some("搜索".into()),
                from: Some(1),
                to: Some(2),
            },
            before: Some(9),
            limit: Some(3),
            since: Some(4),
            facets: true,
            rate_from: Some(5),
        })
        .unwrap();
        let filter = &query.filter;
        assert_eq!(
            filter.statuses,
            [StatusClass::ServerError, StatusClass::Failed]
        );
        assert_eq!(filter.kinds, [ContentKind::Json, ContentKind::Media]);
        assert_eq!(
            (&filter.methods, &filter.hosts, &filter.apps),
            (
                &vec!["post".to_string()],
                &vec!["a.test".to_string()],
                &vec!["chrome".to_string()]
            )
        );
        assert_eq!(
            (filter.rewritten, filter.slow_ms, filter.text.as_deref()),
            (Some(true), Some(500), Some("搜索"))
        );
        assert_eq!((filter.from_ms, filter.to_ms), (Some(1), Some(2)));
        assert_eq!(
            (
                query.before,
                query.limit,
                query.since,
                query.facets,
                query.rate_from_ms
            ),
            (Some(9), Some(3), Some(4), true, Some(5))
        );
    }

    #[test]
    fn a_page_without_a_limit_holds_the_page_limit_and_one_outside_it_is_refused() {
        let query = exchange_query(MitmQueryParams::default()).unwrap();
        assert_eq!(query.limit, Some(PAGE_LIMIT as usize));
        for limit in [0, PAGE_LIMIT + 1] {
            let message = refused(MitmQueryParams {
                limit: Some(limit),
                ..MitmQueryParams::default()
            });
            assert!(message.contains("limit"), "{message}");
        }
    }

    #[test]
    fn negative_values_crossed_times_and_oversized_filters_are_refused() {
        refused(MitmQueryParams {
            before: Some(-1),
            ..MitmQueryParams::default()
        });
        refused(MitmQueryParams {
            rate_from: Some(-1),
            ..MitmQueryParams::default()
        });
        for filter in [
            MitmFilter {
                slow_ms: Some(-1),
                ..MitmFilter::default()
            },
            MitmFilter {
                from: Some(-5),
                ..MitmFilter::default()
            },
            MitmFilter {
                from: Some(10),
                to: Some(9),
                ..MitmFilter::default()
            },
            MitmFilter {
                hosts: vec!["a.test".into(); LIST_LIMIT + 1],
                ..MitmFilter::default()
            },
            MitmFilter {
                apps: vec!["a".repeat(TEXT_LIMIT + 1)],
                ..MitmFilter::default()
            },
            MitmFilter {
                text: Some("a".repeat(TEXT_LIMIT + 1)),
                ..MitmFilter::default()
            },
        ] {
            refused(with_filter(filter));
        }
        assert!(
            exchange_query(with_filter(MitmFilter {
                from: Some(9),
                to: Some(9),
                ..MitmFilter::default()
            }))
            .is_ok()
        );
    }
}
