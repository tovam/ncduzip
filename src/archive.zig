// SPDX-FileCopyrightText: 2026 ncdu contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const main = @import("main.zig");
const model = @import("model.zig");
const archive_zip = @import("archive_zip.zig");

const Archive = struct {
    arena: std.heap.ArenaAllocator,
    root: *model.Dir,
    file_size: u64,
    mtime: i128,
};

const BuildNode = struct {
    name: []const u8,
    is_dir: bool,
    own_packed: u64 = 0,
    own_unpacked: u64 = 0,
    packed_size: u64 = 0,
    unpacked_size: u64 = 0,
    items: u32 = 0,
    children: std.StringHashMapUnmanaged(*BuildNode) = .empty,
};

var cache = std.AutoHashMap(*model.Entry, *Archive).init(main.allocator);

pub fn isCandidate(entry: *const model.Entry) bool {
    return switch (entry.pack.etype) {
        .reg, .link => archive_zip.isCandidate(entry.name()),
        else => false,
    };
}

pub fn loaded(entry: *model.Entry) ?*model.Dir {
    const item = cache.get(entry) orelse return null;
    return item.root;
}

pub fn errorString(err: anyerror) [:0]const u8 {
    return switch (err) {
        error.ArchiveTooManyEntries => "Archive has more than 1,000,000 entries",
        error.ZipNoEndRecord => "Not a valid ZIP archive",
        error.ZipTruncated, error.EndOfStream => "Truncated ZIP archive",
        error.ZipMultiDiskUnsupported => "Multi-volume ZIP archives are not supported",
        error.AccessDenied => "Access denied",
        error.FileNotFound => "Archive no longer exists",
        else => "Invalid or unsupported ZIP archive",
    };
}

fn createNode(allocator: std.mem.Allocator, name: []const u8, is_dir: bool) !*BuildNode {
    const node = try allocator.create(BuildNode);
    node.* = .{ .name = name, .is_dir = is_dir };
    return node;
}

fn validPath(path: []const u8) bool {
    if (path.len == 0 or path[0] == '/') return false;
    var depth: usize = 0;
    var parts = std.mem.tokenizeScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
        depth += 1;
        if (depth > 256) return false;
    }
    return depth > 0;
}

fn addEntry(root: *BuildNode, allocator: std.mem.Allocator, entry: archive_zip.Entry) !void {
    if (!validPath(entry.path)) return;

    var component_count: usize = 0;
    var count_it = std.mem.tokenizeScalar(u8, entry.path, '/');
    while (count_it.next()) |_| component_count += 1;

    var current = root;
    var component_index: usize = 0;
    var parts = std.mem.tokenizeScalar(u8, entry.path, '/');
    while (parts.next()) |part| {
        component_index += 1;
        const is_last = component_index == component_count;
        const needs_dir = !is_last or entry.is_dir;
        const child = current.children.get(part) orelse blk: {
            const node = try createNode(allocator, part, needs_dir);
            try current.children.put(allocator, node.name, node);
            break :blk node;
        };
        if (needs_dir) child.is_dir = true;
        current = child;
    }

    current.own_packed +|= entry.compressed_size;
    current.own_unpacked +|= entry.uncompressed_size;
}

fn aggregate(node: *BuildNode) void {
    node.packed_size = node.own_packed;
    node.unpacked_size = node.own_unpacked;
    node.items = 0;
    var children = node.children.valueIterator();
    while (children.next()) |child_ptr| {
        const child = child_ptr.*;
        aggregate(child);
        node.packed_size +|= child.packed_size;
        node.unpacked_size +|= child.unpacked_size;
        node.items +|= 1 +| child.items;
    }
}

fn toPackedSize(bytes: u64) model.Blocks {
    // Virtual archive trees never flow back into filesystem accounting. In
    // that tree this field stores exact packed bytes rather than 512-byte
    // filesystem blocks, preserving ncdu's compact entry representation.
    return @intCast(@min(bytes, std.math.maxInt(model.Blocks)));
}

fn materialize(allocator: std.mem.Allocator, node: *BuildNode, parent: ?*model.Dir) *model.Entry {
    const entry = model.Entry.create(allocator, if (node.is_dir) .dir else .reg, false, node.name);
    entry.pack.blocks = toPackedSize(node.packed_size);
    entry.size = node.unpacked_size;

    if (entry.dir()) |dir| {
        dir.parent = parent;
        dir.items = node.items;
        var children = node.children.valueIterator();
        while (children.next()) |child_ptr| {
            const child = materialize(allocator, child_ptr.*, dir);
            child.next.ptr = dir.sub.ptr;
            dir.sub.ptr = child;
        }
    }
    return entry;
}

/// Lazily creates an in-memory directory tree for `source`. The archive's
/// children are independent from the filesystem tree, so their sizes never
/// contribute to ncdu's normal disk-usage totals.
pub fn open(source: *model.Entry, parent: *model.Dir, path: [:0]const u8) !*model.Dir {
    const file = try std.fs.cwd().openFileZ(path, .{});
    defer file.close();
    const stat = try file.stat();

    if (cache.get(source)) |item| {
        if (item.file_size == stat.size and item.mtime == stat.mtime) {
            item.root.parent = parent;
            return item.root;
        }
        _ = cache.remove(source);
        item.arena.deinit();
        main.allocator.destroy(item);
    }

    const item = try main.allocator.create(Archive);
    errdefer main.allocator.destroy(item);
    item.* = .{
        .arena = std.heap.ArenaAllocator.init(main.allocator),
        .root = undefined,
        .file_size = stat.size,
        .mtime = stat.mtime,
    };
    errdefer item.arena.deinit();
    const allocator = item.arena.allocator();

    const entries = try archive_zip.scan(allocator, file);
    const build_root = try createNode(allocator, source.name(), true);
    for (entries) |entry| try addEntry(build_root, allocator, entry);
    aggregate(build_root);

    item.root = materialize(allocator, build_root, parent).dir().?;
    try cache.put(source, item);
    return item.root;
}

test "implicit directories aggregate packed and unpacked sizes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const root = try createNode(allocator, "sample.zip", true);
    try addEntry(root, allocator, .{
        .path = "images/raw/cat.bin",
        .compressed_size = 100,
        .uncompressed_size = 900,
        .is_dir = false,
    });
    try addEntry(root, allocator, .{
        .path = "images/raw/dog.bin",
        .compressed_size = 200,
        .uncompressed_size = 800,
        .is_dir = false,
    });
    try addEntry(root, allocator, .{
        .path = "../not-visible",
        .compressed_size = 500,
        .uncompressed_size = 500,
        .is_dir = false,
    });
    aggregate(root);

    try std.testing.expectEqual(@as(u64, 300), root.packed_size);
    try std.testing.expectEqual(@as(u64, 1700), root.unpacked_size);
    try std.testing.expectEqual(@as(u32, 4), root.items);
    const images = root.children.get("images").?;
    try std.testing.expect(images.is_dir);
    try std.testing.expectEqual(@as(u32, 3), images.items);
}
