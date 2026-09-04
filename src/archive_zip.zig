// SPDX-FileCopyrightText: 2026 ncdu contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const max_entries: u64 = 1_000_000;

pub const Entry = struct {
    path: []const u8,
    compressed_size: u64,
    uncompressed_size: u64,
    is_dir: bool,
};

pub fn isCandidate(name: []const u8) bool {
    return std.ascii.endsWithIgnoreCase(name, ".zip");
}

fn readStruct(comptime T: type, reader: *std.fs.File.Reader) !T {
    return reader.interface.takeStruct(T, .little) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.EndOfStream => return error.ZipTruncated,
    };
}

fn readAll(reader: *std.fs.File.Reader, buf: []u8) !void {
    reader.interface.readSliceAll(buf) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        error.EndOfStream => return error.ZipTruncated,
    };
}

const Sizes = struct {
    compressed: u64,
    uncompressed: u64,
};

fn readZip64Sizes(header: std.zip.CentralDirectoryFileHeader, extra: []const u8) !Sizes {
    var sizes = Sizes{
        .compressed = header.compressed_size,
        .uncompressed = header.uncompressed_size,
    };
    const need_compressed = header.compressed_size == std.math.maxInt(u32);
    const need_uncompressed = header.uncompressed_size == std.math.maxInt(u32);
    if (!need_compressed and !need_uncompressed) return sizes;

    var offset: usize = 0;
    while (offset + 4 <= extra.len) {
        const field_id = std.mem.readInt(u16, extra[offset..][0..2], .little);
        const field_len = std.mem.readInt(u16, extra[offset + 2 ..][0..2], .little);
        const end = offset + 4 + @as(usize, field_len);
        if (end > extra.len) return error.ZipBadExtraFieldSize;

        if (field_id == 1) {
            const data = extra[offset + 4 .. end];
            var data_offset: usize = 0;
            if (need_uncompressed) {
                if (data_offset + 8 > data.len) return error.ZipBadCd64Size;
                sizes.uncompressed = std.mem.readInt(u64, data[data_offset..][0..8], .little);
                data_offset += 8;
            }
            if (need_compressed) {
                if (data_offset + 8 > data.len) return error.ZipBadCd64Size;
                sizes.compressed = std.mem.readInt(u64, data[data_offset..][0..8], .little);
            }
            return sizes;
        }
        offset = end;
    }
    return error.ZipMissingZip64Info;
}

/// Reads only ZIP metadata from the central directory. File contents are never
/// decompressed or extracted. Returned paths are owned by `allocator`.
pub fn scan(allocator: std.mem.Allocator, file: std.fs.File) ![]Entry {
    var read_buffer: [4096]u8 = undefined;
    var reader = file.reader(&read_buffer);
    const iterator = try std.zip.Iterator.init(&reader);
    if (iterator.cd_record_count > max_entries) return error.ArchiveTooManyEntries;

    var entries: std.ArrayListUnmanaged(Entry) = .empty;
    try entries.ensureTotalCapacityPrecise(allocator, @intCast(iterator.cd_record_count));

    var filename_buffer: [std.math.maxInt(u16)]u8 = undefined;
    var extra_buffer: [std.math.maxInt(u16)]u8 = undefined;
    var record_offset: u64 = 0;
    var record_index: u64 = 0;
    while (record_index < iterator.cd_record_count) : (record_index += 1) {
        if (record_offset > iterator.cd_size) return error.ZipCdOversized;

        const header_offset = iterator.cd_zip_offset +| record_offset;
        try reader.seekTo(header_offset);
        const header = try readStruct(std.zip.CentralDirectoryFileHeader, &reader);
        if (!std.mem.eql(u8, &header.signature, &std.zip.central_file_header_sig))
            return error.ZipBadCdOffset;
        if (header.disk_number != 0) return error.ZipMultiDiskUnsupported;

        const record_len = @as(u64, @sizeOf(std.zip.CentralDirectoryFileHeader)) +
            @as(u64, header.filename_len) + @as(u64, header.extra_len) + @as(u64, header.comment_len);
        if (record_len > iterator.cd_size -| record_offset) return error.ZipTruncated;

        const filename = filename_buffer[0..header.filename_len];
        try readAll(&reader, filename);
        const extra = extra_buffer[0..header.extra_len];
        try readAll(&reader, extra);
        const sizes = try readZip64Sizes(header, extra);

        record_offset += record_len;
        if (filename.len == 0 or std.mem.indexOfScalar(u8, filename, 0) != null) continue;

        const path = try allocator.dupe(u8, filename);
        std.mem.replaceScalar(u8, path, '\\', '/');
        const unix_mode = header.external_file_attributes >> 16;
        const is_unix_dir = header.version_made_by >> 8 == 3 and unix_mode & 0xf000 == 0x4000;
        entries.appendAssumeCapacity(.{
            .path = path,
            .compressed_size = sizes.compressed,
            .uncompressed_size = sizes.uncompressed,
            .is_dir = std.mem.endsWith(u8, path, "/") or is_unix_dir,
        });
    }
    if (record_offset != iterator.cd_size) return error.ZipCdOversized;
    return entries.toOwnedSlice(allocator);
}

fn appendInt(bytes: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, comptime T: type, value: T) !void {
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &buf, value, .little);
    try bytes.appendSlice(allocator, &buf);
}

fn appendCentralEntry(
    bytes: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    name: []const u8,
    compressed: u32,
    uncompressed: u32,
) !void {
    try bytes.appendSlice(allocator, &std.zip.central_file_header_sig);
    try appendInt(bytes, allocator, u16, 20);
    try appendInt(bytes, allocator, u16, 20);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, 8);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u32, 0);
    try appendInt(bytes, allocator, u32, compressed);
    try appendInt(bytes, allocator, u32, uncompressed);
    try appendInt(bytes, allocator, u16, @intCast(name.len));
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u32, 0);
    try appendInt(bytes, allocator, u32, 0);
    try bytes.appendSlice(allocator, name);
}

test "ZIP candidate detection is case insensitive" {
    try std.testing.expect(isCandidate("photos.zip"));
    try std.testing.expect(isCandidate("PHOTOS.ZIP"));
    try std.testing.expect(!isCandidate("photos.zip.tmp"));
}

test "ZIP64 entry sizes are read from the extra field" {
    var header = std.mem.zeroes(std.zip.CentralDirectoryFileHeader);
    header.compressed_size = std.math.maxInt(u32);
    header.uncompressed_size = std.math.maxInt(u32);

    var extra: [20]u8 = undefined;
    std.mem.writeInt(u16, extra[0..2], 1, .little);
    std.mem.writeInt(u16, extra[2..4], 16, .little);
    std.mem.writeInt(u64, extra[4..12], 9_000_000_000, .little);
    std.mem.writeInt(u64, extra[12..20], 4_000_000_000, .little);
    const sizes = try readZip64Sizes(header, &extra);

    try std.testing.expectEqual(@as(u64, 9_000_000_000), sizes.uncompressed);
    try std.testing.expectEqual(@as(u64, 4_000_000_000), sizes.compressed);
}

test "scan reads paths and sizes from the central directory" {
    const allocator = std.testing.allocator;
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    try appendCentralEntry(&bytes, allocator, "photos/cat.raw", 12, 42);
    try appendCentralEntry(&bytes, allocator, "empty/", 0, 0);
    const central_size: u32 = @intCast(bytes.items.len);
    try bytes.appendSlice(allocator, &std.zip.end_record_sig);
    try appendInt(&bytes, allocator, u16, 0);
    try appendInt(&bytes, allocator, u16, 0);
    try appendInt(&bytes, allocator, u16, 2);
    try appendInt(&bytes, allocator, u16, 2);
    try appendInt(&bytes, allocator, u32, central_size);
    try appendInt(&bytes, allocator, u32, 0);
    try appendInt(&bytes, allocator, u16, 0);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "sample.zip", .data = bytes.items });
    const file = try tmp.dir.openFile("sample.zip", .{});
    defer file.close();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const entries = try scan(arena.allocator(), file);
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("photos/cat.raw", entries[0].path);
    try std.testing.expectEqual(@as(u64, 12), entries[0].compressed_size);
    try std.testing.expectEqual(@as(u64, 42), entries[0].uncompressed_size);
    try std.testing.expect(!entries[0].is_dir);
    try std.testing.expect(entries[1].is_dir);
}
