#![no_main]

use concord_rules::cidr_set;
use concord_rules::domain_set::DomainSet;
use concord_rules::mrs::{self, MrsBehavior};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = mrs::decode(data, MrsBehavior::Domain);
    let _ = mrs::decode(data, MrsBehavior::IpCidr);
    let _ = cidr_set::read_bin(data);
    let _ = DomainSet::read_bin(data);
});
