// SPDX-FileCopyrightText: 2026 ncdu contributors
// SPDX-License-Identifier: MIT

const std = @import("std");

pub const max_entries: u64 = 1_000_000;

pub const Entry = struct {
    path: []const u8,
    compressed_size: u64,
    uncompressed_size: u64,
    is_dir: bool,
    compression_method: std.zip.CompressionMethod = .store,
    local_header_offset: u64 = 0,
    crc32: u32 = 0,
    encrypted: bool = false,
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

const Extents = struct {
    compressed: u64,
    uncompressed: u64,
    local_header_offset: u64,
};

fn readZip64Extents(header: std.zip.CentralDirectoryFileHeader, extra: []const u8) !Extents {
    var extents = Extents{
        .compressed = header.compressed_size,
        .uncompressed = header.uncompressed_size,
        .local_header_offset = header.local_file_header_offset,
    };
    const need_compressed = header.compressed_size == std.math.maxInt(u32);
    const need_uncompressed = header.uncompressed_size == std.math.maxInt(u32);
    const need_offset = header.local_file_header_offset == std.math.maxInt(u32);
    if (!need_compressed and !need_uncompressed and !need_offset) return extents;

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
                extents.uncompressed = std.mem.readInt(u64, data[data_offset..][0..8], .little);
                data_offset += 8;
            }
            if (need_compressed) {
                if (data_offset + 8 > data.len) return error.ZipBadCd64Size;
                extents.compressed = std.mem.readInt(u64, data[data_offset..][0..8], .little);
                data_offset += 8;
            }
            if (need_offset) {
                if (data_offset + 8 > data.len) return error.ZipBadCd64Size;
                extents.local_header_offset = std.mem.readInt(u64, data[data_offset..][0..8], .little);
            }
            return extents;
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
        const extents = try readZip64Extents(header, extra);

        record_offset += record_len;
        if (filename.len == 0 or std.mem.indexOfScalar(u8, filename, 0) != null) continue;

        const path = try allocator.dupe(u8, filename);
        std.mem.replaceScalar(u8, path, '\\', '/');
        const unix_mode = header.external_file_attributes >> 16;
        const is_unix_dir = header.version_made_by >> 8 == 3 and unix_mode & 0xf000 == 0x4000;
        entries.appendAssumeCapacity(.{
            .path = path,
            .compressed_size = extents.compressed,
            .uncompressed_size = extents.uncompressed,
            .is_dir = std.mem.endsWith(u8, path, "/") or is_unix_dir,
            .compression_method = header.compression_method,
            .local_header_offset = extents.local_header_offset,
            .crc32 = header.crc32,
            .encrypted = @as(u16, @bitCast(header.flags)) & 1 != 0,
        });
    }
    if (record_offset != iterator.cd_size) return error.ZipCdOversized;
    return entries.toOwnedSlice(allocator);
}

fn localDataOffset(file: std.fs.File, entry: Entry) !u64 {
    if (entry.encrypted) return error.ZipEncryptionUnsupported;

    var read_buffer: [4096]u8 = undefined;
    var reader = file.reader(&read_buffer);
    try reader.seekTo(entry.local_header_offset);
    const header = try readStruct(std.zip.LocalFileHeader, &reader);
    if (!std.mem.eql(u8, &header.signature, &std.zip.local_file_header_sig))
        return error.ZipBadFileOffset;
    if (header.compression_method != entry.compression_method)
        return error.ZipMismatchCompressionMethod;
    if (@as(u16, @bitCast(header.flags)) & 1 != 0)
        return error.ZipEncryptionUnsupported;
    if (header.crc32 != 0 and header.crc32 != entry.crc32)
        return error.ZipMismatchCrc32;
    if (header.compressed_size != 0 and header.compressed_size != std.math.maxInt(u32) and
        header.compressed_size != entry.compressed_size)
        return error.ZipMismatchCompLen;
    if (header.uncompressed_size != 0 and header.uncompressed_size != std.math.maxInt(u32) and
        header.uncompressed_size != entry.uncompressed_size)
        return error.ZipMismatchUncompLen;

    var filename_buffer: [std.math.maxInt(u16)]u8 = undefined;
    const filename = filename_buffer[0..header.filename_len];
    try readAll(&reader, filename);
    std.mem.replaceScalar(u8, filename, '\\', '/');
    if (!std.mem.eql(u8, filename, entry.path)) return error.ZipMismatchFilename;

    const data_offset = try std.math.add(
        u64,
        entry.local_header_offset,
        @as(u64, @sizeOf(std.zip.LocalFileHeader)) + header.filename_len + header.extra_len,
    );
    const file_size = (try file.stat()).size;
    if (data_offset > file_size or entry.compressed_size > file_size - data_offset)
        return error.ZipTruncated;
    return data_offset;
}

fn verifyCrc(file: std.fs.File, size: u64, expected: u32) !void {
    var crc = std.hash.Crc32.init();
    var buffer: [16 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        const len: usize = @intCast(@min(size - offset, buffer.len));
        const n = try file.pread(buffer[0..len], offset);
        if (n == 0) return error.ZipDecompressTruncated;
        crc.update(buffer[0..n]);
        offset += n;
    }
    if (crc.final() != expected) return error.ZipCrcMismatch;
}

/// Reconstructs one entry into `destination`. Only stored and Deflate entries
/// are supported because those cover the normal ways a nested ZIP is encoded.
pub fn extractToFile(source: std.fs.File, entry: Entry, destination: std.fs.File) !void {
    if (entry.is_dir) return error.ZipExpectedFile;
    switch (entry.compression_method) {
        .store, .deflate => {},
        else => return error.UnsupportedCompressionMethod,
    }
    if (entry.compression_method == .store and entry.compressed_size != entry.uncompressed_size)
        return error.ZipMismatchCompLen;

    const data_offset = try localDataOffset(source, entry);
    var read_buffer: [16 * 1024]u8 = undefined;
    var source_reader = source.reader(&read_buffer);
    try source_reader.seekTo(data_offset);
    var limit_buffer: [4096]u8 = undefined;
    var limited = source_reader.interface.limited(.limited64(entry.compressed_size), &limit_buffer);

    var write_buffer: [16 * 1024]u8 = undefined;
    var destination_writer = destination.writer(&write_buffer);
    switch (entry.compression_method) {
        .store => limited.interface.streamExact64(&destination_writer.interface, entry.uncompressed_size) catch |err| switch (err) {
            error.ReadFailed => return source_reader.err orelse error.ZipDecompressFailed,
            error.WriteFailed => return destination_writer.err orelse error.ZipDecompressFailed,
            error.EndOfStream => return error.ZipDecompressTruncated,
        },
        .deflate => {
            var flate_buffer: [std.compress.flate.max_window_len]u8 = undefined;
            var decompressor: std.compress.flate.Decompress = .init(&limited.interface, .raw, &flate_buffer);
            decompressor.reader.streamExact64(&destination_writer.interface, entry.uncompressed_size) catch |err| switch (err) {
                error.ReadFailed => {
                    if (decompressor.err) |cause| return cause;
                    return source_reader.err orelse error.ZipDecompressFailed;
                },
                error.WriteFailed => return destination_writer.err orelse error.ZipDecompressFailed,
                error.EndOfStream => return error.ZipDecompressTruncated,
            };
            if (decompressor.reader.takeByte()) |_| {
                return error.ZipUncompressedSizeMismatch;
            } else |err| switch (err) {
                error.EndOfStream => {},
                error.ReadFailed => {
                    if (decompressor.err) |cause| return cause;
                    return source_reader.err orelse error.ZipDecompressFailed;
                },
            }
        },
        else => unreachable,
    }
    try destination_writer.end();
    try verifyCrc(destination, entry.uncompressed_size, entry.crc32);
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
    try appendCentralEntryFull(bytes, allocator, name, .deflate, 0, compressed, uncompressed, 0);
}

fn appendCentralEntryFull(
    bytes: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    name: []const u8,
    method: std.zip.CompressionMethod,
    crc32: u32,
    compressed: u32,
    uncompressed: u32,
    local_header_offset: u32,
) !void {
    try bytes.appendSlice(allocator, &std.zip.central_file_header_sig);
    try appendInt(bytes, allocator, u16, 20);
    try appendInt(bytes, allocator, u16, 20);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, @intFromEnum(method));
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u32, crc32);
    try appendInt(bytes, allocator, u32, compressed);
    try appendInt(bytes, allocator, u32, uncompressed);
    try appendInt(bytes, allocator, u16, @intCast(name.len));
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u32, 0);
    try appendInt(bytes, allocator, u32, local_header_offset);
    try bytes.appendSlice(allocator, name);
}

fn appendLocalEntry(
    bytes: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    name: []const u8,
    method: std.zip.CompressionMethod,
    crc32: u32,
    compressed_data: []const u8,
    uncompressed_size: u32,
) !void {
    try bytes.appendSlice(allocator, &std.zip.local_file_header_sig);
    try appendInt(bytes, allocator, u16, 20);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, @intFromEnum(method));
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u32, crc32);
    try appendInt(bytes, allocator, u32, @intCast(compressed_data.len));
    try appendInt(bytes, allocator, u32, uncompressed_size);
    try appendInt(bytes, allocator, u16, @intCast(name.len));
    try appendInt(bytes, allocator, u16, 0);
    try bytes.appendSlice(allocator, name);
    try bytes.appendSlice(allocator, compressed_data);
}

fn appendEndRecord(
    bytes: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    count: u16,
    central_size: u32,
    central_offset: u32,
) !void {
    try bytes.appendSlice(allocator, &std.zip.end_record_sig);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, 0);
    try appendInt(bytes, allocator, u16, count);
    try appendInt(bytes, allocator, u16, count);
    try appendInt(bytes, allocator, u32, central_size);
    try appendInt(bytes, allocator, u32, central_offset);
    try appendInt(bytes, allocator, u16, 0);
}

test "ZIP candidate detection is case insensitive" {
    try std.testing.expect(isCandidate("photos.zip"));
    try std.testing.expect(isCandidate("PHOTOS.ZIP"));
    try std.testing.expect(!isCandidate("photos.zip.tmp"));
}

test "ZIP64 entry extents are read from the extra field" {
    var header = std.mem.zeroes(std.zip.CentralDirectoryFileHeader);
    header.compressed_size = std.math.maxInt(u32);
    header.uncompressed_size = std.math.maxInt(u32);
    header.local_file_header_offset = std.math.maxInt(u32);

    var extra: [28]u8 = undefined;
    std.mem.writeInt(u16, extra[0..2], 1, .little);
    std.mem.writeInt(u16, extra[2..4], 24, .little);
    std.mem.writeInt(u64, extra[4..12], 9_000_000_000, .little);
    std.mem.writeInt(u64, extra[12..20], 4_000_000_000, .little);
    std.mem.writeInt(u64, extra[20..28], 8_000_000_000, .little);
    const extents = try readZip64Extents(header, &extra);

    try std.testing.expectEqual(@as(u64, 9_000_000_000), extents.uncompressed);
    try std.testing.expectEqual(@as(u64, 4_000_000_000), extents.compressed);
    try std.testing.expectEqual(@as(u64, 8_000_000_000), extents.local_header_offset);
}

test "scan reads paths and sizes from the central directory" {
    const allocator = std.testing.allocator;
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    try appendCentralEntry(&bytes, allocator, "photos/cat.raw", 12, 42);
    try appendCentralEntry(&bytes, allocator, "empty/", 0, 0);
    const central_size: u32 = @intCast(bytes.items.len);
    try appendEndRecord(&bytes, allocator, 2, central_size, 0);

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

fn expectExtracted(
    method: std.zip.CompressionMethod,
    compressed_data: []const u8,
    expected: []const u8,
) !void {
    const allocator = std.testing.allocator;
    const name = "inner.zip";
    const crc32 = std.hash.Crc32.hash(expected);
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(allocator);

    try appendLocalEntry(&bytes, allocator, name, method, crc32, compressed_data, @intCast(expected.len));
    const central_offset: u32 = @intCast(bytes.items.len);
    try appendCentralEntryFull(
        &bytes,
        allocator,
        name,
        method,
        crc32,
        @intCast(compressed_data.len),
        @intCast(expected.len),
        0,
    );
    const central_size: u32 = @intCast(bytes.items.len - central_offset);
    try appendEndRecord(&bytes, allocator, 1, central_size, central_offset);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "outer.zip", .data = bytes.items });
    const source = try tmp.dir.openFile("outer.zip", .{});
    defer source.close();
    const destination = try tmp.dir.createFile("actual.zip", .{ .read = true });
    defer destination.close();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const entries = try scan(arena.allocator(), source);
    try std.testing.expectEqual(@as(usize, 1), entries.len);
    try extractToFile(source, entries[0], destination);

    const actual = try allocator.alloc(u8, expected.len);
    defer allocator.free(actual);
    try std.testing.expectEqual(expected.len, try destination.preadAll(actual, 0));
    try std.testing.expectEqualStrings(expected, actual);
}

test "stored nested ZIP entry is reconstructed" {
    const contents = "PK synthetic inner ZIP contents";
    try expectExtracted(.store, contents, contents);
}

test "Deflate nested ZIP entry is reconstructed" {
    const contents = "PK synthetic inner ZIP contents";
    var compressed: [contents.len + 5]u8 = undefined;
    compressed[0] = 1; // Final, uncompressed Deflate block.
    std.mem.writeInt(u16, compressed[1..3], contents.len, .little);
    std.mem.writeInt(u16, compressed[3..5], ~@as(u16, contents.len), .little);
    @memcpy(compressed[5..], contents);
    try expectExtracted(.deflate, &compressed, contents);
}
