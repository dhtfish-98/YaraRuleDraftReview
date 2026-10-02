"""Explicit stable regular-file reads, component-by-component no-follow."""

from contextlib import ExitStack, contextmanager
import os
import stat

from .model import DEFAULT_LIMITS, Issue

KEYS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")


def platform():
    if (
        any(not hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"))
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise Issue("safe_file_platform_not_supported")


def parts(path):
    if type(path) is not str or "\0" in path:
        raise Issue("file_path_input")
    try:
        if len(path.encode("utf-8", "strict")) > 8192:
            raise Issue("file_path_input")
    except UnicodeError:
        raise Issue("file_path_input") from None
    absolute = path.startswith("/")
    components = path.split("/")[1:] if absolute else path.split("/")
    if not components or any(item in ("", ".", "..") for item in components):
        raise Issue("file_path_components")
    return absolute, components


@contextmanager
def directory(path, parent=False):
    absolute, components = parts(path)
    platform()
    try:
        with ExitStack() as closing:
            handle = os.open("/" if absolute else ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            closing.callback(os.close, handle)
            for component in components[:-1] if parent else components:
                handle = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=handle
                )
                closing.callback(os.close, handle)
            yield handle, components[-1]
    except (OSError, UnicodeError):
        raise Issue("file_input_or_output_error") from None


def same(left, right):
    return all(getattr(left, key) == getattr(right, key) for key in KEYS)


def read_local(path):
    try:
        with directory(path, parent=True) as (folder, leaf):
            with ExitStack() as closing:
                handle = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
                closing.callback(os.close, handle)
                before = os.fstat(handle)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or not 0 <= before.st_size <= DEFAULT_LIMITS.file_bytes
                ):
                    raise Issue("file_not_regular_or_byte_budget")
                blocks, size = [], 0
                while True:
                    block = os.read(handle, min(65536, DEFAULT_LIMITS.file_bytes + 1 - size))
                    if not block:
                        break
                    size += len(block)
                    if size > DEFAULT_LIMITS.file_bytes:
                        raise Issue("file_byte_budget")
                    blocks.append(block)
                after = os.fstat(handle)
                if (
                    not stat.S_ISREG(after.st_mode)
                    or size != after.st_size
                    or not same(before, after)
                ):
                    raise Issue("file_changed_or_short_read")
                return b"".join(blocks)
    except (OSError, UnicodeError):
        raise Issue("file_input_error") from None
