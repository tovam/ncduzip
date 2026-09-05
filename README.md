<!--
SPDX-FileCopyrightText: Yorhel <projects@yorhel.nl>
SPDX-License-Identifier: MIT
-->

# ncdu-zig

## Description

Ncdu is a disk usage analyzer with an ncurses interface. It is designed to find
space hogs on a remote server where you don't have an entire graphical setup
available, but it is a useful tool even on regular desktop systems. Ncdu aims
to be fast, simple and easy to use, and should be able to run in any minimal
POSIX-like environment with ncurses installed.

See the [ncdu 2 release announcement](https://dev.yorhel.nl/doc/ncdu2) for
information about the differences between this Zig implementation (2.x) and the
C version (1.x).

## ZIP browsing (MVP0)

ZIP files found during a normal filesystem scan are shown with a `>` marker.
Press Enter to browse one like a directory. The archive is indexed lazily from
its central directory; regular file contents are never decompressed or
extracted.

ZIP files inside ZIP files can also be opened. Only the selected inner ZIP
container is reconstructed in an anonymous temporary file; its contents are
still indexed lazily. Nested archives are cached while their outer archive is
cached.

Inside an archive, disk usage represents packed size and apparent size
represents unpacked size. Press `a` to switch between them. ZIP contents are a
separate, read-only tree and are never added to the filesystem totals.

This initial implementation intentionally keeps a narrow scope:

- ZIP only, with ZIP64 support
- at most 1,000,000 entries per archive
- nested ZIPs up to 3 levels deep and 2 GiB each (4 GiB cached total)
- Store and Deflate compression for nested ZIP containers
- no delete, refresh or shell commands inside archives
- live filesystem scans only; imported ncdu reports remain unchanged

## Requirements

- Zig 0.14 or 0.15
- Some sort of POSIX-like OS
- ncurses
- libzstd

## Install

You can use the Zig build system if you're familiar with that.

There's also a handy Makefile that supports the typical targets, e.g.:

```
make
sudo make install PREFIX=/usr
```
