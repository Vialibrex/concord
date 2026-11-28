//! Summaries of repeated trials and the test that decides whether two cores differ.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use serde::Serialize;

const RESAMPLES: usize = 4000;
/// Below this relative difference two medians count as equal however tight the
/// interval: a few percent is within what a machine drifts between runs.
pub const NOISE_FLOOR: f64 = 0.02;

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub n: usize,
    pub median: f64,
    pub mean: f64,
    pub stddev: f64,
    /// Coefficient of variation, stddev over mean.
    pub cv: f64,
    pub min: f64,
    pub max: f64,
    /// 95% bootstrap interval of the median.
    pub ci: [f64; 2],
}

pub fn summarize(samples: &[f64], seed: u64) -> Option<Summary> {
    let mut sorted: Vec<f64> = samples.iter().copied().filter(|v| v.is_finite()).collect();
    if sorted.is_empty() {
        return None;
    }
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    let mean = sorted.iter().sum::<f64>() / n as f64;
    let variance = if n > 1 {
        sorted.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    let stddev = variance.sqrt();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut medians: Vec<f64> = (0..RESAMPLES)
        .map(|_| median_of(&resample(&sorted, &mut rng)))
        .collect();
    medians.sort_by(f64::total_cmp);
    Some(Summary {
        n,
        median: median_sorted(&sorted),
        mean,
        stddev,
        cv: if mean != 0.0 {
            stddev / mean.abs()
        } else {
            0.0
        },
        min: sorted[0],
        max: sorted[n - 1],
        ci: [quantile(&medians, 0.025), quantile(&medians, 0.975)],
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct Comparison {
    /// `subject / reference` of the medians.
    pub ratio: f64,
    pub ci: [f64; 2],
    /// Two-sided Mann-Whitney U.
    pub p: f64,
    pub verdict: Verdict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Better,
    Worse,
    Same,
    /// Too few samples on one side to say.
    Unknown,
}

pub fn compare(
    subject: &[f64],
    reference: &[f64],
    higher_is_better: bool,
    seed: u64,
) -> Comparison {
    let a = finite_sorted(subject);
    let b = finite_sorted(reference);
    if !a.is_empty() && !b.is_empty() && a.iter().chain(&b).all(|v| *v == 0.0) {
        return Comparison {
            ratio: 1.0,
            ci: [1.0; 2],
            p: 1.0,
            verdict: Verdict::Same,
        };
    }
    if a.is_empty() || b.is_empty() || median_sorted(&b) == 0.0 {
        return Comparison {
            ratio: f64::NAN,
            ci: [f64::NAN; 2],
            p: 1.0,
            verdict: Verdict::Unknown,
        };
    }
    let ratio = median_sorted(&a) / median_sorted(&b);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut ratios: Vec<f64> = (0..RESAMPLES)
        .filter_map(|_| {
            let base = median_of(&resample(&b, &mut rng));
            (base != 0.0).then(|| median_of(&resample(&a, &mut rng)) / base)
        })
        .collect();
    ratios.sort_by(f64::total_cmp);
    let ci = [quantile(&ratios, 0.025), quantile(&ratios, 0.975)];
    let p = mann_whitney(&a, &b);
    let verdict = if a.len() < 2 || b.len() < 2 {
        Verdict::Unknown
    } else if (ratio - 1.0).abs() < NOISE_FLOOR || (ci[0] <= 1.0 && ci[1] >= 1.0) || p >= 0.05 {
        Verdict::Same
    } else if (ratio > 1.0) == higher_is_better {
        Verdict::Better
    } else {
        Verdict::Worse
    };
    Comparison {
        ratio,
        ci,
        p,
        verdict,
    }
}

/// Exact permutation distribution of U for small groups, where the normal
/// approximation is poor; the normal approximation with tie correction above that.
pub fn mann_whitney(a: &[f64], b: &[f64]) -> f64 {
    let (n1, n2) = (a.len(), b.len());
    if n1 == 0 || n2 == 0 {
        return 1.0;
    }
    let pooled: Vec<f64> = a.iter().chain(b).copied().collect();
    let ranks = ranks(&pooled);
    let u_of = |members: &[usize]| -> f64 {
        let sum: f64 = members.iter().map(|&i| ranks[i]).sum();
        sum - (n1 * (n1 + 1)) as f64 / 2.0
    };
    let observed = u_of(&(0..n1).collect::<Vec<_>>());
    let center = (n1 * n2) as f64 / 2.0;
    let distance = (observed - center).abs();
    if n1 + n2 <= 20 {
        let mut extreme = 0u64;
        let mut total = 0u64;
        for_each_combination(n1 + n2, n1, &mut |members| {
            total += 1;
            if (u_of(members) - center).abs() >= distance - 1e-9 {
                extreme += 1;
            }
        });
        return extreme as f64 / total as f64;
    }
    let n = (n1 + n2) as f64;
    let mut ties = 0.0;
    let mut sorted = pooled.clone();
    sorted.sort_by(f64::total_cmp);
    let mut i = 0;
    while i < sorted.len() {
        let mut j = i;
        while j + 1 < sorted.len() && sorted[j + 1] == sorted[i] {
            j += 1;
        }
        let t = (j - i + 1) as f64;
        ties += t * t * t - t;
        i = j + 1;
    }
    let variance = (n1 * n2) as f64 / 12.0 * ((n + 1.0) - ties / (n * (n - 1.0)));
    if variance <= 0.0 {
        return 1.0;
    }
    let z = (distance - 0.5).max(0.0) / variance.sqrt();
    (2.0 * (1.0 - normal_cdf(z))).clamp(0.0, 1.0)
}

/// Lowest-rank-first quantile of an ascending slice.
pub fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let position = q.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let low = position.floor() as usize;
    let high = position.ceil() as usize;
    sorted[low] + (sorted[high] - sorted[low]) * (position - low as f64)
}

/// Jain's fairness index: 1 when every flow got the same share, 1/n when one got all.
pub fn jain(values: &[f64]) -> f64 {
    let sum: f64 = values.iter().sum();
    let squares: f64 = values.iter().map(|v| v * v).sum();
    if squares == 0.0 {
        return 0.0;
    }
    sum * sum / (values.len() as f64 * squares)
}

pub fn cv(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if mean == 0.0 {
        return 0.0;
    }
    let variance =
        values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
    variance.sqrt() / mean
}

fn finite_sorted(values: &[f64]) -> Vec<f64> {
    let mut sorted: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    sorted.sort_by(f64::total_cmp);
    sorted
}

fn resample(values: &[f64], rng: &mut StdRng) -> Vec<f64> {
    (0..values.len())
        .map(|_| values[rng.random_range(0..values.len())])
        .collect()
}

fn median_of(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    median_sorted(&sorted)
}

fn median_sorted(sorted: &[f64]) -> f64 {
    quantile(sorted, 0.5)
}

fn ranks(values: &[f64]) -> Vec<f64> {
    let mut order: Vec<usize> = (0..values.len()).collect();
    order.sort_by(|&x, &y| values[x].total_cmp(&values[y]));
    let mut ranks = vec![0.0; values.len()];
    let mut i = 0;
    while i < order.len() {
        let mut j = i;
        while j + 1 < order.len() && values[order[j + 1]] == values[order[i]] {
            j += 1;
        }
        let shared = (i + j) as f64 / 2.0 + 1.0;
        for &index in &order[i..=j] {
            ranks[index] = shared;
        }
        i = j + 1;
    }
    ranks
}

fn for_each_combination(n: usize, k: usize, visit: &mut impl FnMut(&[usize])) {
    let mut chosen: Vec<usize> = (0..k).collect();
    loop {
        visit(&chosen);
        let Some(i) = (0..k).rev().find(|&i| chosen[i] != i + n - k) else {
            return;
        };
        chosen[i] += 1;
        for j in i + 1..k {
            chosen[j] = chosen[j - 1] + 1;
        }
    }
}

/// Abramowitz and Stegun 7.1.26, good to about 1e-7.
fn normal_cdf(z: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.327_591_1 * z.abs() / std::f64::consts::SQRT_2);
    let poly = t
        * (0.254_829_592
            + t * (-0.284_496_736
                + t * (1.421_413_741 + t * (-1.453_152_027 + t * 1.061_405_429))));
    let erf = 1.0 - poly * (-(z * z) / 2.0).exp();
    if z >= 0.0 {
        0.5 * (1.0 + erf)
    } else {
        0.5 * (1.0 - erf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separated_groups_are_significant_and_overlapping_ones_are_not() {
        let fast = [10.0, 10.2, 9.9, 10.1, 10.05];
        let slow = [8.0, 8.1, 7.9, 8.05, 8.2];
        let c = compare(&fast, &slow, true, 1);
        assert_eq!(c.verdict, Verdict::Better);
        assert!(c.p < 0.05);
        assert!(c.ci[0] > 1.0);
        let same = compare(&fast, &[10.1, 9.95, 10.0, 10.2, 9.9], true, 1);
        assert_eq!(same.verdict, Verdict::Same);
    }

    #[test]
    fn lower_is_better_flips_the_verdict() {
        let c = compare(&[1.0, 1.1, 1.05, 1.02], &[2.0, 2.1, 2.05, 2.02], false, 3);
        assert_eq!(c.verdict, Verdict::Better);
    }

    #[test]
    fn zero_on_both_sides_is_the_same() {
        let c = compare(&[0.0; 4], &[0.0; 4], false, 3);
        assert_eq!((c.ratio, c.verdict), (1.0, Verdict::Same));
    }

    #[test]
    fn three_rounds_a_side_can_never_be_significant() {
        let p = mann_whitney(&[1.0, 2.0, 3.0], &[4.0, 5.0, 6.0]);
        assert!((p - 0.1).abs() < 1e-12);
    }

    #[test]
    fn exact_mann_whitney_matches_the_table() {
        // Complete separation of 5 against 5: p = 2 / C(10, 5).
        let p = mann_whitney(&[1.0, 2.0, 3.0, 4.0, 5.0], &[6.0, 7.0, 8.0, 9.0, 10.0]);
        assert!((p - 2.0 / 252.0).abs() < 1e-12);
    }

    #[test]
    fn the_interval_holds_the_median() {
        let s = summarize(&[3.0, 1.0, 2.0, 5.0, 4.0], 7).unwrap();
        assert_eq!(s.median, 3.0);
        assert!(s.ci[0] <= 3.0 && s.ci[1] >= 3.0);
    }

    #[test]
    fn jain_is_one_for_equal_shares() {
        assert!((jain(&[2.0, 2.0, 2.0]) - 1.0).abs() < 1e-12);
        assert!((jain(&[1.0, 0.0, 0.0, 0.0]) - 0.25).abs() < 1e-12);
    }
}
