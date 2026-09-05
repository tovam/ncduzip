// SPDX-FileCopyrightText: 2026 ncdu contributors
// SPDX-License-Identifier: MIT

const std = @import("std");
const main = @import("main.zig");
const model = @import("model.zig");
const archive_zip = @import("archive_zip.zig");

pub const max_depth: u8 = 3;
pub const max_nested_archive_size: u64 = 2 * 1024 * 1024 * 1024;
const max_cached_nested_size: u64 = 4 * 1024 * 1024 * 1024;

const Backing = union(enum) {
    path: [:0]u8,
    temporary: std.fs.File,

    const OpenedBacking = struct {
        file: std.fs.File,
        close_after: bool,

        fn close(self: OpenedBacking) void {
            if (self.close_after) self.file.close();
        }
    };

    fn open(self: *const Backing) !OpenedBacking {
        return switch (self.*) {
            .path => |path| .{ .file = try std.fs.cwd().openFileZ(path, .{}), .close_after = true },
            .temporary => |file| .{ .file = file, .close_after = false },
        };
    }

    fn deinit(self: *Backing) void {
        switch (self.*) {
            .path => |path| main.allocator.free(path),
            .temporary => |file| file.close(),
        }
    }
};

pub const Context = struct {
    arena: std.heap.ArenaAllocator,
    root: *model.Dir,
    backing: Backing,
    file_size: u64,
    mtime: i128,
    depth: u8,
    temporary_bytes: u64 = 0,
    entry_sources: std.AutoHashMapUnmanaged(*model.Entry, archive_zip.Entry) = .empty,
    children: std.AutoHashMap(*model.Entry, *Context),

    fn deinit(self: *Context) void {
        var children = self.children.valueIterator();
        while (children.next()) |child| child.*.deinit();
        self.children.deinit();
        self.backing.deinit();
        self.arena.deinit();
        cached_nested_size -= self.temporary_bytes;
        main.allocator.destroy(self);
    }
};

pub const Opened = struct {
    root: *model.Dir,
    context: *Context,
};

const BuildNode = struct {
    name: []const u8,
    is_dir: bool,
    own_packed: u64 = 0,
    own_unpacked: u64 = 0,
    packed_size: u64 = 0,
    unpacked_size: u64 = 0,
    items: u32 = 0,
    source: ?archive_zip.Entry = null,
    children: std.StringHashMapUnmanaged(*BuildNode) = .empty,
};

var cache = std.AutoHashMap(*model.Entry, *Context).init(main.allocator);
var cached_nested_size: u64 = 0;

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
        error.ArchiveDepthLimit => "Maximum nested ZIP depth (3) reached",
        error.ArchiveNestedTooLarge => "Nested ZIP is larger than 2 GiB",
        error.ArchiveTempLimit => "Nested ZIP cache limit (4 GiB) reached",
        error.ArchiveEntryUnavailable => "ZIP entry metadata is unavailable",
        error.ZipNoEndRecord => "Not a valid ZIP archive",
        error.ZipTruncated, error.EndOfStream => "Truncated ZIP archive",
        error.ZipMultiDiskUnsupported => "Multi-volume ZIP archives are not supported",
        error.ZipEncryptionUnsupported => "Encrypted nested ZIP entries are not supported",
        error.UnsupportedCompressionMethod => "Nested ZIP must use Store or Deflate compression",
        error.ZipCrcMismatch => "Nested ZIP failed its CRC check",
        error.ZipDecompressTruncated, error.ZipUncompressedSizeMismatch => "Nested ZIP data is truncated or has an invalid size",
        error.NoSpaceLeft => "Not enough temporary disk space for nested ZIP",
        error.ReadOnlyFileSystem => "Temporary directory is not writable",
        error.TempNameCollision => "Unable to create a temporary file for nested ZIP",
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
    if (!entry.is_dir) current.source = entry;
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

fn materialize(context: *Context, node: *BuildNode, parent: ?*model.Dir) !*model.Entry {
    const allocator = context.arena.allocator();
    const entry = model.Entry.create(allocator, if (node.is_dir) .dir else .reg, false, node.name);
    entry.pack.blocks = toPackedSize(node.packed_size);
    entry.size = node.unpacked_size;
    if (node.source) |source| try context.entry_sources.put(allocator, entry, source);

    if (entry.dir()) |dir| {
        dir.parent = parent;
        dir.items = node.items;
        var children = node.children.valueIterator();
        while (children.next()) |child_ptr| {
            const child = try materialize(context, child_ptr.*, dir);
            child.next.ptr = dir.sub.ptr;
            dir.sub.ptr = child;
        }
    }
    return entry;
}

fn createContext(
    backing_arg: Backing,
    file: std.fs.File,
    source_name: []const u8,
    parent: *model.Dir,
    depth: u8,
    file_size: u64,
    mtime: i128,
) !*Context {
    var backing = backing_arg;
    var backing_owned = true;
    errdefer if (backing_owned) backing.deinit();
    const item = try main.allocator.create(Context);
    item.* = .{
        .arena = std.heap.ArenaAllocator.init(main.allocator),
        .root = undefined,
        .backing = backing,
        .file_size = file_size,
        .mtime = mtime,
        .depth = depth,
        .children = std.AutoHashMap(*model.Entry, *Context).init(main.allocator),
    };
    backing_owned = false;
    errdefer item.deinit();
    const allocator = item.arena.allocator();

    const entries = try archive_zip.scan(allocator, file);
    const build_root = try createNode(allocator, source_name, true);
    for (entries) |entry| try addEntry(build_root, allocator, entry);
    aggregate(build_root);
    item.root = (try materialize(item, build_root, parent)).dir().?;
    return item;
}

/// Lazily creates an in-memory directory tree for a filesystem ZIP. The
/// archive tree remains separate from normal filesystem accounting.
pub fn openRoot(source: *model.Entry, parent: *model.Dir, path: [:0]const u8) !Opened {
    const file = try std.fs.cwd().openFileZ(path, .{});
    defer file.close();
    const stat = try file.stat();

    if (cache.get(source)) |item| {
        if (item.file_size == stat.size and item.mtime == stat.mtime) {
            item.root.parent = parent;
            return .{ .root = item.root, .context = item };
        }
        _ = cache.remove(source);
        item.deinit();
    }

    const owned_path = try main.allocator.dupeZ(u8, path);
    const item = createContext(
        .{ .path = owned_path },
        file,
        source.name(),
        parent,
        1,
        stat.size,
        stat.mtime,
    ) catch |err| return err;
    errdefer item.deinit();
    try cache.put(source, item);
    return .{ .root = item.root, .context = item };
}

fn openTempDir() !std.fs.Dir {
    const temp_path = std.posix.getenvZ("TMPDIR") orelse "/tmp";
    return std.fs.cwd().openDir(temp_path, .{});
}

fn createAnonymousTemp(temp_dir: std.fs.Dir) !std.fs.File {
    for (0..16) |_| {
        var name_buffer: [48]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buffer, ".ncduzip-{x}", .{std.crypto.random.int(u128)}) catch unreachable;
        const file = temp_dir.createFile(name, .{
            .read = true,
            .exclusive = true,
            .mode = 0o600,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => |cause| return cause,
        };
        temp_dir.deleteFile(name) catch |err| {
            file.close();
            return err;
        };
        return file;
    }
    return error.TempNameCollision;
}

fn cachedNested(parent_context: *Context, source: *model.Entry, parent: *model.Dir) !?Opened {
    if (parent_context.depth >= max_depth) return error.ArchiveDepthLimit;
    if (parent_context.children.get(source)) |item| {
        item.root.parent = parent;
        return .{ .root = item.root, .context = item };
    }
    return null;
}

pub fn openNested(parent_context: *Context, source: *model.Entry, parent: *model.Dir) !Opened {
    if (try cachedNested(parent_context, source, parent)) |opened| return opened;
    var temp_dir = try openTempDir();
    defer temp_dir.close();
    return openNestedUncachedInDir(parent_context, source, parent, temp_dir);
}

fn openNestedInDir(
    parent_context: *Context,
    source: *model.Entry,
    parent: *model.Dir,
    temp_dir: std.fs.Dir,
) !Opened {
    if (try cachedNested(parent_context, source, parent)) |opened| return opened;
    return openNestedUncachedInDir(parent_context, source, parent, temp_dir);
}

fn openNestedUncachedInDir(
    parent_context: *Context,
    source: *model.Entry,
    parent: *model.Dir,
    temp_dir: std.fs.Dir,
) !Opened {
    const source_metadata = parent_context.entry_sources.get(source) orelse return error.ArchiveEntryUnavailable;
    if (source_metadata.uncompressed_size > max_nested_archive_size)
        return error.ArchiveNestedTooLarge;
    if (source_metadata.uncompressed_size > max_cached_nested_size -| cached_nested_size)
        return error.ArchiveTempLimit;

    const parent_backing = try parent_context.backing.open();
    defer parent_backing.close();
    const temporary = try createAnonymousTemp(temp_dir);
    var temporary_owned = true;
    errdefer if (temporary_owned) temporary.close();
    try archive_zip.extractToFile(parent_backing.file, source_metadata, temporary);

    // createContext() owns and closes the temporary file even when it fails.
    temporary_owned = false;
    const item = try createContext(
        .{ .temporary = temporary },
        temporary,
        source.name(),
        parent,
        parent_context.depth + 1,
        source_metadata.uncompressed_size,
        0,
    );
    errdefer item.deinit();
    item.temporary_bytes = source_metadata.uncompressed_size;
    cached_nested_size += source_metadata.uncompressed_size;
    try parent_context.children.put(source, item);
    return .{ .root = item.root, .context = item };
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

test "nested context is opened once and cached" {
    const name = "inner.zip";
    var empty_zip = [_]u8{0} ** @sizeOf(std.zip.EndRecord);
    @memcpy(empty_zip[0..4], &std.zip.end_record_sig);
    const crc32 = std.hash.Crc32.hash(&empty_zip);

    const local_header_size = @sizeOf(std.zip.LocalFileHeader);
    var outer = [_]u8{0} ** (local_header_size + name.len + empty_zip.len);
    @memcpy(outer[0..4], &std.zip.local_file_header_sig);
    std.mem.writeInt(u16, outer[4..6], 20, .little);
    std.mem.writeInt(u32, outer[14..18], crc32, .little);
    std.mem.writeInt(u32, outer[18..22], empty_zip.len, .little);
    std.mem.writeInt(u32, outer[22..26], empty_zip.len, .little);
    std.mem.writeInt(u16, outer[26..28], name.len, .little);
    @memcpy(outer[local_header_size..][0..name.len], name);
    @memcpy(outer[local_header_size + name.len ..], &empty_zip);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const outer_file = try tmp.dir.createFile("outer.bin", .{ .read = true });
    var outer_file_owned = true;
    defer if (outer_file_owned) outer_file.close();
    try outer_file.writeAll(&outer);

    const baseline_cached_size = cached_nested_size;
    {
        const parent_context = try main.allocator.create(Context);
        parent_context.* = .{
            .arena = std.heap.ArenaAllocator.init(main.allocator),
            .root = undefined,
            .backing = .{ .temporary = outer_file },
            .file_size = outer.len,
            .mtime = 0,
            .depth = 1,
            .children = std.AutoHashMap(*model.Entry, *Context).init(main.allocator),
        };
        outer_file_owned = false;
        defer parent_context.deinit();

        const allocator = parent_context.arena.allocator();
        parent_context.root = model.Entry.create(allocator, .dir, false, "outer.zip").dir().?;
        const source = model.Entry.create(allocator, .reg, false, name);
        source.next.ptr = parent_context.root.sub.ptr;
        parent_context.root.sub.ptr = source;
        try parent_context.entry_sources.put(allocator, source, .{
            .path = name,
            .compressed_size = empty_zip.len,
            .uncompressed_size = empty_zip.len,
            .is_dir = false,
            .compression_method = .store,
            .local_header_offset = 0,
            .crc32 = crc32,
        });

        const opened = try openNestedInDir(parent_context, source, parent_context.root, tmp.dir);
        try std.testing.expectEqual(@as(u8, 2), opened.context.depth);
        try std.testing.expectEqualStrings(name, opened.root.entry.name());
        try std.testing.expectEqual(@as(u32, 0), opened.root.items);
        try std.testing.expectEqual(baseline_cached_size + empty_zip.len, cached_nested_size);

        const cached = try openNestedInDir(parent_context, source, parent_context.root, tmp.dir);
        try std.testing.expectEqual(opened.context, cached.context);
        try std.testing.expectEqual(opened.root, cached.root);

        parent_context.depth = max_depth;
        try std.testing.expectError(
            error.ArchiveDepthLimit,
            openNestedInDir(parent_context, source, parent_context.root, tmp.dir),
        );
    }
    try std.testing.expectEqual(baseline_cached_size, cached_nested_size);
}
