"""Exit codes and the one output helper every command shares.

Extracted so that per-product command modules can render results without
importing :mod:`hexact.cli`, which imports them -- a cycle that Python resolves
by half-initialising one of the modules, producing an `AttributeError` at import
time that reads like a typo rather than a design problem.

Exit codes are part of the interface, not decoration: 0 success, 1 an API or
credential failure, 2 a usage error. An agent branches on these.
"""

from __future__ import annotations

import json
import sys
from typing import Any

EXIT_OK, EXIT_FAILURE, EXIT_USAGE = 0, 1, 2


def emit(payload: Any, as_json: bool, render) -> None:
    """Print ``payload`` as JSON, or hand it to ``render`` for a human.

    ``default=str`` on purpose: a datetime that reaches here should serialise
    rather than abort the command after the work has already been done.
    """
    if as_json:
        json.dump(payload, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        render(payload)
