//! WiFi Channels


pub const Channels = struct {
    // 2.4GHz Channels
    pub const band_2G: []const usize = band2G: {
        var channels: [14]usize = undefined;
        for (1..15) |ch| {
            if (!validateChannel(ch)) continue;
            channels[ch - 1] = ch;
        }
        const ch_out = channels;
        break :band2G ch_out[0..];
    };
    // 5GHz Channels (20 MHz only)
    pub const band_5G: []const usize = band5G: {
        var channels: [43]usize = undefined;
        var idx = 0;
        for (33..200) |ch| {
            if (!validateChannel(ch)) continue;
            channels[idx] = ch;
            idx += 1;
        }
        const ch_out = channels;
        break :band5G ch_out[0..];
    };
    pub const all: []const usize = band_2G ++ band_5G;
};

pub const Frequencies = struct {
    pub const band_2G: []const usize = band2G: {
        var freqs: [14]usize = undefined;
        for (Channels.band_2G[0..], 0..) |ch, idx| 
            freqs[idx] = freqFromChannel(ch) catch @compileError("Unknown WiFi Channel");
        const freq_out = freqs;
        break :band2G freq_out[0..];
    };
    pub const band_5G: []const usize = band5G: {
        var freqs: [43]usize = undefined;
        for (Channels.band_5G[0..], 0..) |ch, idx| 
            freqs[idx] = freqFromChannel(ch) catch @compileError("Unknown WiFi Channel");
        const freq_out = freqs;
        break :band5G freq_out[0..];
    };
    pub const all: []const usize = band_2G ++ band_5G;
};


/// Get the corresponding Channel of the provided Frequency (`freq_mhz`).
pub fn channelFromFreq(freq_mhz: usize) !usize {
    const channel = switch (freq_mhz) {
        0...2483 => (freq_mhz -| 2407) / 5,
        2484 => 14,
        5000...6000 => (freq_mhz -| 5000) / 5,
        else => return error.UnknownChannel,
    };
    if (!validateChannel(channel)) return error.InvalidChannel;
    return channel;
}
/// Get the corresponding Frequency of the provided `channel`.
pub fn freqFromChannel(channel: usize) !usize {
    if (!validateChannel(channel)) return error.InvalidFrequency;
    return switch (channel) {
        1...14 => 2407 + (5 * channel),
        else => 5000 + (5 * channel),
    };
}
/// Validate a `channel`.
pub fn validateChannel(channel: usize) bool {
    return switch (channel) {
        1...14 => true,
        32...144,
        184...196 => channel % 4 == 0 or (channel >= 135 and channel <= 138),
        149...177 => channel % 4 == 1,
        else => false,
    };
}
/// Validate a Frequency (`freq`).
pub fn validateFreq(freq: usize) bool {
    return if (channelFromFreq(freq)) |_| true else |_| false;
}
