use concord_config::filter::{Matcher, compile_pattern};
use concord_config::group::PriorityRule;

enum Pattern {
    Regex(Matcher),
    Substring(String),
}

impl Pattern {
    fn is_match(&self, name: &str) -> bool {
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

    pub fn factor(&self, name: &str) -> f64 {
        self.rules
            .iter()
            .find(|(pattern, _)| pattern.is_match(name))
            .map_or(1.0, |(_, factor)| *factor)
    }

    pub fn score(&self, name: &str, delay: u16) -> f64 {
        f64::from(delay) / self.factor(name)
    }
}
