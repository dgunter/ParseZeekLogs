"""Allow ``python -m parsezeeklogs``."""

import sys

from parsezeeklogs.cli import main

if __name__ == "__main__":
    sys.exit(main())
