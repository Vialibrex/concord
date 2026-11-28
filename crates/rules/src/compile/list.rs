//! Rule-list compilation: grouping adjacent same-class rules into runs and lowering lone rules.

use std::borrow::Borrow;
use std::net::IpAddr;

use concord_config::rule::{Cond, RuleDef};

use super::{Cx, Loc, check_target, node_for_def, regex, url_regex};
use crate::eval::Node;
use crate::kind::RuleKind;
use crate::payload::rule_payload;
use crate::prog::{Op, Prog, host_match};
use crate::program::CompileError;
use crate::runs::{CompiledUrl, DomainItem, DomainRun, IpRun, UrlRun};
use crate::table::TableBuilder;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Domain(bool),
    Ip { src: bool, resolves: bool },
    Url,
    Other,
}

fn class_of(def: &RuleDef) -> Class {
    match &def.cond {
        Cond::Domain(_)
        | Cond::DomainSuffix(_)
        | Cond::DomainKeyword(_)
        | Cond::DomainWildcard(_)
        | Cond::DomainRegex(_) => Class::Domain(def.extended),
        Cond::IpCidr(_) | Cond::IpCidr6(_) => Class::Ip {
            src: def.src,
            resolves: !def.no_resolve && !def.src,
        },
        Cond::SrcIpCidr(_) => Class::Ip {
            src: true,
            resolves: false,
        },
        Cond::UrlRegex(_) => Class::Url,
        _ => Class::Other,
    }
}

/// Same-class rules as they are read. Domain and IP runs stay definitions until long
/// enough to merge (so at most `merge_min` are held however long the list is), while
/// URL-REGEX rules compile eagerly so a bad pattern fails where a lone rule would.
struct OpenRun<D> {
    class: Class,
    start: usize,
    count: usize,
    held: Vec<D>,
    domains: Vec<(u32, DomainItem)>,
    nets: Vec<(u32, IpAddr, u8)>,
    urls: Vec<(u32, CompiledUrl)>,
    url_lines: Vec<Box<str>>,
}

impl<D: Borrow<RuleDef>> OpenRun<D> {
    fn new(class: Class, start: usize, cx: &mut Cx<'_>) -> Self {
        if class == Class::Url {
            cx.demands.http = true;
        }
        OpenRun {
            class,
            start,
            count: 0,
            held: Vec::new(),
            domains: Vec::new(),
            nets: Vec::new(),
            urls: Vec::new(),
            url_lines: Vec::new(),
        }
    }

    fn add(&mut self, def: D, merge_min: usize, section: &str) -> Result<(), CompileError> {
        let index = self.start + self.count;
        self.count += 1;
        if self.class == Class::Url || self.count > merge_min {
            return self.add_item(def.borrow(), index, section);
        }
        self.held.push(def);
        if self.count == merge_min {
            for (i, def) in std::mem::take(&mut self.held).iter().enumerate() {
                self.add_item(def.borrow(), self.start + i, section)?;
            }
        }
        Ok(())
    }

    fn add_item(&mut self, def: &RuleDef, index: usize, section: &str) -> Result<(), CompileError> {
        match &def.cond {
            Cond::IpCidr(net) | Cond::IpCidr6(net) | Cond::SrcIpCidr(net) => {
                self.nets.push((index as u32, net.addr, net.prefix));
            }
            Cond::UrlRegex(pattern) => {
                let loc = Loc {
                    section,
                    index,
                    line: &def.text,
                };
                self.urls.push((index as u32, url_regex(pattern, &loc)?));
                self.url_lines.push(def.text.as_str().into());
            }
            _ => {
                if let Some(item) = domain_item(def, index, section)? {
                    self.domains.push((index as u32, item));
                }
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct ListBuilder {
    table: TableBuilder,
    ops: Vec<Op>,
    nodes: Vec<Node>,
    domain_runs: Vec<DomainRun>,
    ip_runs: Vec<IpRun>,
    url_runs: Vec<UrlRun>,
}

impl ListBuilder {
    fn leaf(
        &mut self,
        cx: &mut Cx<'_>,
        def: &RuleDef,
        index: usize,
        section: &str,
    ) -> Result<(), CompileError> {
        let idx = index as u32;
        if let Some(how) = host_match(def, self.table.payload(idx)) {
            cx.demands.domain = true;
            self.ops.push(Op::host(idx, how, def.extended));
            return Ok(());
        }
        let loc = Loc {
            section,
            index,
            line: &def.text,
        };
        self.nodes
            .push(Node::extended(node_for_def(cx, def, &loc)?, def.extended));
        self.ops.push(Op::Leaf {
            idx,
            node: self.nodes.len() as u32 - 1,
        });
        Ok(())
    }

    fn close<D: Borrow<RuleDef>>(
        &mut self,
        cx: &mut Cx<'_>,
        run: OpenRun<D>,
        merge_min: usize,
        section: &str,
    ) -> Result<(), CompileError> {
        let (start, end) = (run.start as u32, (run.start + run.count) as u32);
        if run.class == Class::Url {
            if run.count < merge_min {
                for ((idx, url), line) in run.urls.into_iter().zip(run.url_lines) {
                    let loc = Loc {
                        section,
                        index: idx as usize,
                        line: &line,
                    };
                    self.nodes.push(Node::Url(cx.add_url_leaf(url, &loc)?));
                    self.ops.push(Op::Leaf {
                        idx,
                        node: self.nodes.len() as u32 - 1,
                    });
                }
            } else {
                let built = UrlRun::build(start, end, run.urls).map_err(|err| {
                    let line = run
                        .url_lines
                        .get(err.index.saturating_sub(start as usize))
                        .map_or("", Box::as_ref)
                        .to_string();
                    CompileError::Invalid {
                        section: section.to_string(),
                        index: err.index,
                        line,
                        message: err.message,
                    }
                })?;
                self.url_runs.push(built);
                self.ops.push(Op::Url(self.url_runs.len() as u32 - 1));
            }
            return Ok(());
        }
        if run.count < merge_min {
            for (i, def) in run.held.iter().enumerate() {
                self.leaf(cx, def.borrow(), run.start + i, section)?;
            }
            return Ok(());
        }
        match run.class {
            Class::Domain(extended) => {
                cx.demands.domain = true;
                let built = DomainRun::build(start, end, extended, run.domains, &self.table);
                self.domain_runs.push(built);
                self.ops.push(Op::Domain(self.domain_runs.len() as u32 - 1));
            }
            Class::Ip { src, resolves } => {
                if !src {
                    cx.demands.ip = true;
                    cx.demands.resolve_ip |= resolves;
                }
                self.ip_runs
                    .push(IpRun::build(start, end, src, resolves, &run.nets));
                self.ops.push(Op::Ip(self.ip_runs.len() as u32 - 1));
            }
            Class::Url | Class::Other => {}
        }
        Ok(())
    }
}

pub(super) fn compile_list<D: Borrow<RuleDef>>(
    cx: &mut Cx<'_>,
    defs: impl Iterator<Item = Result<D, CompileError>>,
    section: &str,
) -> Result<Prog, CompileError> {
    let merge_min = cx.env.merge_min.max(1);
    let mut list = ListBuilder::default();
    let mut open: Option<OpenRun<D>> = None;
    for (index, def) in defs.enumerate() {
        let def = def?;
        let rule = def.borrow();
        let loc = Loc {
            section,
            index,
            line: &rule.text,
        };
        let target = cx.intern(&rule.target)?;
        if cx.check_targets {
            check_target(cx, rule, &loc)?;
        }
        list.table.push(
            RuleKind::of(&rule.cond, rule.src),
            target,
            &rule_payload(rule),
        );
        let class = class_of(rule);
        if let Some(run) = open.take_if(|run| run.class != class) {
            list.close(cx, run, merge_min, section)?;
        }
        if class == Class::Other {
            list.leaf(cx, rule, index, section)?;
        } else {
            open.get_or_insert_with(|| OpenRun::new(class, index, cx))
                .add(def, merge_min, section)?;
        }
    }
    if let Some(run) = open {
        list.close(cx, run, merge_min, section)?;
    }
    Ok(Prog {
        table: list.table.finish(),
        ops: list.ops.into_boxed_slice(),
        nodes: list.nodes.into_boxed_slice(),
        domain_runs: list.domain_runs.into_boxed_slice(),
        ip_runs: list.ip_runs.into_boxed_slice(),
        url_runs: list.url_runs.into_boxed_slice(),
    })
}

fn domain_item(
    def: &RuleDef,
    index: usize,
    section: &str,
) -> Result<Option<DomainItem>, CompileError> {
    Ok(Some(match &def.cond {
        Cond::Domain(_) => DomainItem::Exact,
        Cond::DomainSuffix(_) => DomainItem::Suffix,
        Cond::DomainKeyword(_) => DomainItem::Keyword,
        Cond::DomainWildcard(_) => DomainItem::Wildcard,
        Cond::DomainRegex(pattern) => {
            let loc = Loc {
                section,
                index,
                line: &def.text,
            };
            DomainItem::Regex(regex(pattern, &loc)?)
        }
        _ => return Ok(None),
    }))
}
