use concord_config::filter::{Matcher, compile_pattern};
use concord_config::group::PriorityRule;

#[cfg(test)]
std::thread_local! {
    static MATCH_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn take_match_calls() -> usize {
    MATCH_CALLS.with(|calls| calls.replace(0))
}

pub(crate) fn normalize_factor(factor: f64) -> f64 {
    if factor.is_finite() && factor > 0.0 {
        factor
    } else {
        1.0
    }
}

enum Pattern {
    Regex(Matcher),
    Substring(String),
}

impl Pattern {
    fn is_match(&self, name: &str) -> bool {
        #[cfg(test)]
        MATCH_CALLS.with(|calls| calls.set(calls.get() + 1));
        match self {
            Pattern::Regex(matcher) => matcher.is_match(name),
            Pattern::Substring(text) => name.contains(text.as_str()),
        }
    }
}

#[derive(Default)]
pub struct Priority {
    rules: Vec<(Pattern, f64)>,
}

impl Priority {
    /// A pattern that is not a regex matches as a plain substring, as vernesong's core does.
    pub fn compile(rules: &[PriorityRule]) -> Priority {
        Priority {
            rules: rules
                .iter()
                .map(|rule| {
                    let pattern = match compile_pattern(&rule.pattern, false) {
                        Ok(matcher) => Pattern::Regex(matcher),
                        Err(_) => Pattern::Substring(rule.pattern.clone()),
                    };
                    (pattern, rule.factor)
                })
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn factor(&self, name: &str) -> f64 {
        self.rules
            .iter()
            .find(|(pattern, _)| pattern.is_match(name))
            .map_or(1.0, |(_, factor)| *factor)
    }
}
