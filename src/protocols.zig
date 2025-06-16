//! Parsers & Functions for various Network Protocols

pub const dhcp = @import("protocols/dhcp.zig");
pub const dns = @import("protocols/dns.zig");
pub const sae = @import("protocols/sae.zig");
pub const wpa = @import("protocols/wpa.zig");

test "protocols" {
    @setEvalBranchQuota(10_000);
    @import("std").testing.refAllDeclsRecursive(@This());
}
