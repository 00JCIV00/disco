//! File Hosting Servers

const std = @import("std");
const atomic = std.atomic;
const enums = std.enums;
const fmt = std.fmt;
const fs = std.fs;
const json = std.json;
const log = std.log.scoped(.serve);
const mem = std.mem;
const net = std.net;
const os = std.os;
const posix = std.posix;
const time = std.time;

const utils = @import("../utils.zig");
const c = utils.toStruct;

const netdata = @import("../netdata.zig");
const address = netdata.address;
const IPF = address.IPFormatter;

const err_max: usize = 10;

pub const Protocol = enum {
    http,
    tftp,
    all,
};

pub const Config = struct {
    ip: [4]u8 = .{ 0, 0, 0, 0 },
    port: u16 = 12070,
    /// This field is just for easier JSON parsing.
    ip_port: ?[]const u8 = null,
    serve_path: []const u8 = ".",
    protocols: []const Protocol = &.{ .all },
};

pub const Context = struct {
    conf: *Config,
    thread_pool: *std.Thread.Pool,
    wait_group: *std.Thread.WaitGroup,

    pub fn init(alloc: mem.Allocator) !@This() {
        var self: @This() = undefined;
        self.conf = conf: {
            const conf = try alloc.create(Config);
            conf.* = Config{};
            break :conf conf;
        };
        self.thread_pool = threadPool: {
            const pool = try alloc.create(std.Thread.Pool);
            break :threadPool pool;
        };
        self.wait_group = waitGroup: {
            const group = try alloc.create(std.Thread.WaitGroup);
            group.* = std.Thread.WaitGroup{};
            break :waitGroup group;
        };
        return self;
    }

    pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
        //self.thread_pool.deinit();
        alloc.destroy(self.thread_pool);
        alloc.destroy(self.wait_group);
        alloc.destroy(self.conf);
    }
};

pub fn serveDir(
    alloc: mem.Allocator, 
    ctx: *Context, 
    active: *const atomic.Value(bool),
) void {
    const conf: *Config = ctx.conf;
    if (conf.protocols.len == 0) {
        log.err("At least one Protocol must be provided for the Server.", .{});
        return; //error.NoProtocolProvided;
    }
    // Threads Spawned
    var http_thread_spawned: bool = false;
    var tftp_thread_spawned: bool = false;
    // Create TCP socket for HTTP
    const tcp_addr = tcpAddr: {
        if (conf.ip_port) |ip_port| {
            break :tcpAddr parseIP(ip_port, conf) catch |err| {
                log.warn("Could not parse Config 'IP:Port': {s}", .{ @errorName(err) });
                break :tcpAddr net.Address.initIp4(conf.ip, conf.port);
            };
        }
        break :tcpAddr net.Address.initIp4(conf.ip, conf.port);
    };
    const tcp_sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |err| {
        log.err("Could not create TCP Socket: {s}", .{ @errorName(err) });
        return;
    };
    defer if (http_thread_spawned) posix.close(tcp_sock);
    posix.bind(tcp_sock, &tcp_addr.any, tcp_addr.getOsSockLen()) catch |err| {
        log.err("Could not bind to TCP Socket: {s}", .{ @errorName(err) });
        return;
    };
    posix.listen(tcp_sock, 0) catch |err| {
        log.err("Could not listen on TCP Socket: {s}", .{ @errorName(err) });
        return;
    };
    // Create UDP socket for TFTP
    const udp_addr = udpAddr: {
        if (conf.ip_port) |ip_port| {
            break :udpAddr parseIP(ip_port, conf) catch |err| {
                log.warn("Could not parse Config 'IP:Port': {s}", .{ @errorName(err) });
                break :udpAddr net.Address.initIp4(conf.ip, conf.port);
            };
        }
        break :udpAddr net.Address.initIp4(conf.ip, conf.port);
    };
    const udp_sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch |err| {
        log.err("Could not create UDP Socket: {s}", .{ @errorName(err) });
        return;
    };
    defer if (tftp_thread_spawned) posix.close(udp_sock);
    posix.bind(udp_sock, &udp_addr.any, udp_addr.getOsSockLen()) catch |err| {
        log.err("Could not bind to UDP Socket: {s}", .{ @errorName(err) });
        return;
    };
    log.info("Serving '{s}' on '{s}:{d}'...", .{ conf.serve_path, IPF{ .bytes = conf.ip[0..] }, conf.port });
    // Set up event loop for both protocols
    const serve_path = if (mem.endsWith(u8, conf.serve_path, "/")) conf.serve_path[0..(conf.serve_path.len - 1)] else conf.serve_path;
    const job_count = jobCount: {
        if (mem.indexOfScalar(Protocol, conf.protocols, .all)) |_|
            break :jobCount enums.values(Protocol).len - 1;
        var job_count: usize = 0;
        for (conf.protocols) |proto| {
            if (proto == .all) continue;
            job_count += 1;
        }
        break :jobCount job_count;
    };
    ctx.thread_pool.init(.{ .allocator = alloc, .n_jobs = @truncate(job_count) }) catch |err| {
        log.err("File Server Error: {s}. Terminating Tracking!", .{ @errorName(err) });
        return;
    };
    if (mem.indexOfAny(Protocol, conf.protocols, &.{ .all, .http }) != null) {
        ctx.thread_pool.spawnWg(
            ctx.wait_group,
            listenHTTP,
            .{
                tcp_sock,
                serve_path,
                active,
            },
        );
        http_thread_spawned = true;
    }
    if (mem.indexOfAny(Protocol, conf.protocols, &.{ .all, .tftp }) != null) {
        ctx.thread_pool.spawnWg(
            ctx.wait_group,
            listenTFTP,
            .{
                udp_sock,
                serve_path,
                active,
            },
        );
        tftp_thread_spawned = true;
    }
    ctx.thread_pool.waitAndWork(ctx.wait_group);
    //const http_thread = try std.Thread.spawn(.{}, listenHTTP, .{ tcp_sock, serve_path, active });
    //http_thread.detach();
    //const tftp_thread = try std.Thread.spawn(.{}, listenTFTP, .{ udp_sock, serve_path, active });
    //tftp_thread_spawned = true;
    //tftp_thread.detach();
}

/// Listen f/ HTTP
pub fn listenHTTP(http_sock: posix.socket_t, serve_dir: []const u8, active: *const atomic.Value(bool)) void {
    defer posix.close(http_sock);
    while (active.load(.acquire)) {
        // Handle TCP connections (HTTP)
        var addr: posix.sockaddr = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        const conn = posix.accept(http_sock, &addr, &addr_len, 0) catch |err| {
            log.err("HTTP File Server Error: {s}", .{ @errorName(err) });
            continue;
        };
        // Spawn thread to handle HTTP request
        const http_thread = std.Thread.spawn(.{}, handleHTTP, .{ conn, serve_dir, active }) catch |err| {
            log.err("HTTP File Server Error: {s}", .{ @errorName(err) });
            continue;
        };
        http_thread.detach();
    }
}

/// Listen f/ TFTP Requests
pub fn listenTFTP(udp_sock: posix.socket_t, serve_dir: []const u8, active: *const atomic.Value(bool)) void {
    defer posix.close(udp_sock);
    var err_count: u8 = 0;
    while (active.load(.acquire) and err_count < err_max) {
        // Handle UDP packets (TFTP)
        var recv_buf: [1024]u8 = undefined;
        var client_addr: posix.sockaddr = undefined;
        var client_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        const bytes_received = posix.recvfrom(
            udp_sock,
            recv_buf[0..],
            0,
            &client_addr,
            &client_addr_len,
        ) catch |err| {
            log.err("TFTP File Server Error: {s}", .{ @errorName(err) });
            err_count += 1;
            continue;
        };
        if (bytes_received == 0) continue;
        // Handle TFTP request in separate thread
        const tftp_thread = std.Thread.spawn(.{}, handleTFTP, .{
            udp_sock,
            recv_buf,
            bytes_received,
            client_addr,
            client_addr_len,
            serve_dir,
            active,
        }) catch |err| {
            log.err("TFTP File Server Error: {s}", .{ @errorName(err) });
            err_count += 1;
            continue;
        };
        tftp_thread.detach();
    }
    if (err_count >= err_max) log.err("TFTP File Serving ran into too many issues to continue.", .{});
}

/// Handle HTTP Requests
pub fn handleHTTP(http_sock: posix.socket_t, serve_dir: []const u8, active: *const atomic.Value(bool)) !void {
    var http_buf: [4096]u8 = undefined;
    const bytes_read = try posix.recv(http_sock, http_buf[0..], 0);
    const request = http_buf[0..bytes_read];
    // Parse HTTP request (simple implementation)
    var lines = mem.split(u8, request, "\r\n");
    const first_line = lines.first();
    var parts = mem.split(u8, first_line, " ");
    _ = parts.next(); // Skip method
    const req_path_raw = parts.next() orelse "";
    const req_path = if (mem.startsWith(u8, req_path_raw, "/")) req_path_raw[1..] else req_path_raw;
    // Sanitize and build file path
    var path_buf: [fs.MAX_PATH_BYTES]u8 = undefined;
    const full_path = try fmt.bufPrint(path_buf[0..], "{s}/{s}", .{ serve_dir, req_path });
    log.info("HTTP: Serving File '{s}'...", .{ full_path });
    // Try to read file
    const file = fs.openFileAbsolute(full_path, .{}) catch {
        log.warn("HTTP: Could not find File '{s}'!", .{ full_path });
        // File not found response
        const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
        _ = try posix.send(http_sock, not_found, 0);
        return;
    };
    defer file.close();
    defer log.info("HTTP: Served File '{s}'.", .{ full_path });
    // Send file contents
    const file_size = try file.getEndPos();
    var header_buf: [128]u8 = undefined;
    const header = try fmt.bufPrint(header_buf[0..], "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n", .{ file_size });
    _ = try posix.send(http_sock, header, 0);
    // Send file in chunks
    var read_buf: [8192]u8 = undefined;
    while (active.load(.acquire)) {
        const bytes = try file.read(read_buf[0..]);
        if (bytes == 0) break;
        _ = posix.send(http_sock, read_buf[0..bytes], 0) catch |err| switch (err) {
            error.ConnectionResetByPeer => {
                log.warn("HTTP: Connection Reset. The File '{s}' may already exist on the Client.", .{ full_path });
                break;
            },
            else => return err,
        };
    }
}

const TFTPOpCode = enum(u16) {
    RRQ = 1,
    WRQ = 2,
    DATA = 3,
    ACK = 4,
    ERROR = 5,
};

/// Handle TFTP Requests
pub fn handleTFTP(
    tftp_sock: posix.socket_t,
    req_buf: [1024]u8,
    req_len: usize,
    client_addr: posix.sockaddr,
    client_addr_len: posix.socklen_t,
    serve_dir: []const u8,
    active: *const atomic.Value(bool),
) !void {
    if (req_len < 4) return;
    const request = req_buf[0..req_len];
    const opcode = mem.bigToNative(u16, mem.bytesToValue(u16, request[0..2]));
    switch (@as(TFTPOpCode, @enumFromInt(opcode))) {
        .RRQ => {
            // Parse filename from request
            const filename = mem.sliceTo(request[2..], 0);
            // Sanitize and build file path
            var path_buf: [fs.MAX_PATH_BYTES]u8 = undefined;
            const full_path = try fmt.bufPrint(path_buf[0..], "{s}/{s}", .{ serve_dir, filename });
            log.info("TFTP: Serving File '{s}'...", .{ full_path });
            // Try to open file
            const file = fs.openFileAbsolute(full_path, .{}) catch {
                log.warn("TFTP: Could not find File '{s}'!", .{ full_path });
                // Send error packet
                const error_packet = [_]u8{
                    0, 5, // ERROR opcode
                    0, 1, // Error code: File not found
                    'F', 'i', 'l', 'e', ' ', 'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd', 0,
                };
                _ = try posix.sendto(
                    tftp_sock,
                    error_packet[0..],
                    0,
                    &client_addr,
                    client_addr_len,
                );
                return;
            };
            defer file.close();
            defer log.info("TFTP: Served File '{s}'.", .{ full_path });
            // Send file in blocks
            var block_num: u16 = 1;
            var resp_buf: [516]u8 = undefined; // 2 bytes opcode + 2 bytes block + 512 bytes data
            while (active.load(.acquire)) {
                mem.writeInt(u16, resp_buf[0..2], c(TFTPOpCode).DATA, .big);
                mem.writeInt(u16, resp_buf[2..4], block_num, .big);
                const bytes_read = try file.read(resp_buf[4..]);
                if (bytes_read == 0) break;
                _ = try posix.sendto(
                    tftp_sock,
                    resp_buf[0..(bytes_read + 4)],
                    0,
                    &client_addr,
                    client_addr_len,
                );
                // Wait for ACK
                //var ack_buf: [4]u8 = undefined;
                //var ack_addr: posix.sockaddr = undefined;
                //var ack_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
                //_ = try posix.recvfrom(
                //    tftp_sock, 
                //    ack_buf[0..], 
                //    0, 
                //    &ack_addr, 
                //    &ack_addr_len
                //);
                //const ack_block = mem.bytesToValue(u16, ack_buf[2..4]);
                //if (mem.bigToNative(u16, ack_block) != block_num) break;
                time.sleep(100 * time.ns_per_us);
                block_num += 1;
                if (bytes_read < 512) break;
            }
        },
        .WRQ => {
            // Send error - write not supported
            const error_packet = [_]u8{
                0, 5, // ERROR opcode
                0, 2, // Error code: Access violation
                'W', 'r', 'i', 't', 'e', ' ', 'n', 'o', 't', ' ',
                's', 'u', 'p', 'p', 'o', 'r', 't', 'e', 'd', 0,
            };
            _ = try posix.sendto(
                tftp_sock, 
                error_packet[0..], 
                0, 
                &client_addr, 
                client_addr_len
            );
        },
        else => {},
    }
}

fn parseIP(addr: []const u8, conf: *Config) !net.Address {
    var iter = mem.splitScalar(u8, addr, ':');
    const ip = net.Address.parseIp(
        iter.first(),
        try fmt.parseInt(u16, iter.next() orelse "-", 10)
    ) catch |err| {
        log.err("The provided destination address '{s}' is invalid.", .{ addr });
        return err;
    };
    conf.ip = mem.toBytes(ip.in.sa.addr);
    conf.port = ip.in.getPort();
    return ip;
}
