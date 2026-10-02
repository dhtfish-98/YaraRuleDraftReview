"""Create one new hash-named draft; never overwrite or unlink on failure."""

from contextlib import ExitStack
from hashlib import sha256
import os
import stat

from .files import directory, parts, same
from .model import DEFAULT_LIMITS, Issue


def write_draft(source, output_dir, input_paths=()):
    result = {
        "status": "OPEN",
        "name": None,
        "may_exist": False,
        "atomicity": "OPEN",
        "path_identity_future": "OPEN",
    }
    try:
        if (
            type(source) is not str
            or type(output_dir) is not str
            or type(input_paths) not in (tuple, list)
        ):
            raise Issue("output_input_type")
        parts(output_dir)
        raw = source.encode("ascii", "strict")
        if not raw or len(raw) > DEFAULT_LIMITS.rule_bytes:
            raise Issue("output_byte_budget")
        # Lexical comparison is an independence restriction, not a symlink resolution.
        for path in input_paths:
            if type(path) is not str:
                raise Issue("output_input_type")
            parts(path)
            if os.path.abspath(output_dir) == os.path.dirname(os.path.abspath(path)):
                raise Issue("output_directory_not_independent")
        name = "draft-" + sha256(raw).hexdigest() + ".yar"
        result["name"] = name
        with directory(output_dir) as (folder, _):
            with ExitStack() as closing:
                result["may_exist"] = True
                handle = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK,
                    0o600,
                    dir_fd=folder,
                )
                closing.callback(os.close, handle)
                before = os.fstat(handle)
                if not stat.S_ISREG(before.st_mode) or before.st_size != 0:
                    raise Issue("output_identity")
                written = 0
                while written < len(raw):
                    count = os.write(handle, raw[written : written + 65536])
                    if count <= 0:
                        raise Issue("output_short_write")
                    written += count
                os.fsync(handle)
                after = os.fstat(handle)
                observed = os.stat(name, dir_fd=folder, follow_symlinks=False)
                if (
                    not stat.S_ISREG(after.st_mode)
                    or not stat.S_ISREG(observed.st_mode)
                    or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                    or after.st_size != written
                    or not same(after, observed)
                ):
                    raise Issue("output_identity")
                result["bytes"] = written
        result["status"] = "PASS"
    except Issue as error:
        result["issue"] = error.code
    except (OSError, UnicodeError, ValueError, TypeError):
        result["issue"] = "output_error"
    return result
