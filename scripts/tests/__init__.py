"""Test package bootstrap for the repository's script harnesses.

The implementation modules are grouped by role under ``scripts/``.  Keep the
module directories on ``sys.path`` so both pytest and ``unittest discover``
can execute the same tests from the repository root without environment
specific ``PYTHONPATH`` settings.
"""

from pathlib import Path
import sys

_SCRIPTS = Path(__file__).resolve().parent.parent
for _path in (_SCRIPTS, _SCRIPTS / "ci", _SCRIPTS / "gates", _SCRIPTS / "gates" / "qemu", _SCRIPTS / "gates" / "stress", _SCRIPTS / "fuzz", _SCRIPTS / "tools"):
    _value = str(_path)
    if _value not in sys.path:
        sys.path.insert(0, _value)
