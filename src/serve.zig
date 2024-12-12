//! File Hosting Servers

const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const log = std.log;
const mem = std.mem;
const net = std.net;
const os = std.os;
const posix = std.posix;


pub fn serveDir(port: u16, serve_dir: []const u8, active: *const bool) !void {
    // Threads Spawned
    var http_thread_spawned: bool = false;
    var tftp_thread_spawned: bool = false;
    // Create TCP socket for HTTP
    const tcp_addr = try net.Address.parseIp("0.0.0.0", port);
    const tcp_sock = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    errdefer if (!http_thread_spawned) posix.close(tcp_sock);
    try posix.bind(tcp_sock, &tcp_addr.any, tcp_addr.getOsSockLen());
    try posix.listen(tcp_sock, 0);
    // Create UDP socket for TFTP
    const udp_addr = try net.Address.parseIp("0.0.0.0", port);
    const udp_sock = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    errdefer if (!tftp_thread_spawned) posix.close(udp_sock);
    try posix.bind(udp_sock, &udp_addr.any, udp_addr.getOsSockLen());
    log.info("Serving '{s}' on '0.0.0.0:{d}'...", .{ serve_dir, port });
    // Set up event loop for both protocols
    const http_thread = try std.Thread.spawn(.{}, listenHTTP, .{ tcp_sock, serve_dir, active });
    http_thread_spawned = true;
    http_thread.detach();
    const tftp_thread = try std.Thread.spawn(.{}, listenTFTP, .{ udp_sock, serve_dir, active });
    tftp_thread_spawned = true;
    tftp_thread.detach();
}

/// Listen f/ HTTP
pub fn listenHTTP(http_sock: posix.socket_t, serve_dir: []const u8, active: *const bool) !void {
    defer posix.close(http_sock);
    while (active.*) {
        // Handle TCP connections (HTTP)
        var addr: posix.sockaddr = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        const conn = try posix.accept(http_sock, &addr, &addr_len, 0);
        // Spawn thread to handle HTTP request
        const http_thread = try std.Thread.spawn(.{}, handleHTTP, .{ conn, serve_dir, active });
        http_thread.detach();
    }
}

/// Listen f/ TFTP Requests
pub fn listenTFTP(udp_sock: posix.socket_t, serve_dir: []const u8, active: *const bool) !void {
    defer posix.close(udp_sock);
    while (active.*) {
        // Handle UDP packets (TFTP)
        var recv_buf: [1024]u8 = undefined;
        var client_addr: posix.sockaddr = undefined;
        var client_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        const bytes_received = try posix.recvfrom(
            udp_sock,
            recv_buf[0..],
            0,
            &client_addr,
            &client_addr_len,
        );
        if (bytes_received > 0) {
            // Handle TFTP request in separate thread
            const tftp_thread = try std.Thread.spawn(.{}, handleTFTP, .{
                udp_sock,
                recv_buf,
                bytes_received,
                client_addr,
                client_addr_len,
                serve_dir,
                active,
            });
            tftp_thread.detach();
        }
    }
}

/// Handle HTTP Requests
pub fn handleHTTP(http_sock: posix.socket_t, serve_dir: []const u8, active: *const bool) !void {
    var http_buf: [4096]u8 = undefined;
    const bytes_read = try posix.recv(http_sock, http_buf[0..], 0);
    const request = http_buf[0..bytes_read];
    // Parse HTTP request (simple implementation)
    var lines = mem.split(u8, request, "\r\n");
    const first_line = lines.first();
    var parts = mem.split(u8, first_line, " ");
    _ = parts.next(); // Skip method
    const request_path = parts.next() orelse "/";
    // Sanitize and build file path
    var path_buf: [fs.MAX_PATH_BYTES]u8 = undefined;
    const full_path = try fmt.bufPrint(path_buf[0..], "{s}/{s}", .{ serve_dir, request_path });
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
    while (active.*) {
        const bytes = try file.read(read_buf[0..]);
        if (bytes == 0) break;
        _ = try posix.send(http_sock, read_buf[0..bytes], 0);
    }
}

const TftpOpcode = enum(u16) {
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
    active: *const bool,
) !void {
    if (req_len < 4) return;
    const request = req_buf[0..req_len];
    const opcode = mem.bigToNative(u16, mem.bytesToValue(u16, request[0..2]));
    switch (@as(TftpOpcode, @enumFromInt(opcode))) {
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
                //const error_packet: []const u8 = 
                //    &.{ 0, 5 } ++
                //    &.{ 0, 1 } ++
                //    "File note found" ++
                //    &.{ 0 };
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
            while (active.*) {
                resp_buf[0] = 0;
                resp_buf[1] = 3; // DATA opcode
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
