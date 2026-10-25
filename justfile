python := "python3"

set shell := [python, "-c"]
set positional-arguments

# Write the Debian installer to a USB. Options in any order: debian, amd64|arm64, /dev/DISK (no prompts).
@zap *options:
    from tasks import main; main("zap")

# Install missing system tools (safe to repeat).
@setup:
    from tasks import main; main("setup")

# Build an ISO file instead of writing a USB. Same options as zap, plus an optional output path.
@build *options:
    from tasks import main; main("build")

# Set or change a login password (saved as a hash in config/credentials.yaml). Options: root, HASH_FILE.
@password *options:
    from tasks import main; main("password")

[private]
@check:
    from tasks import main; main("check")

[private]
@disks:
    from tasks import main; main("disks")

[private]
@eject device:
    from tasks import main; main("eject")

[private]
@test:
    from tasks import main; main("test")
