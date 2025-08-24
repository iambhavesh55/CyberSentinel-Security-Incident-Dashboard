"""Tests for LogParser timestamp parsing"""

from datetime import datetime
import sys
import types
from pathlib import Path

# Provide a minimal stub for pandas to avoid heavy dependency during tests
sys.modules.setdefault("pandas", types.ModuleType("pandas"))
# Minimal stub for yaml used by configuration loading
yaml_stub = types.ModuleType("yaml")
yaml_stub.safe_load = lambda *args, **kwargs: {}
sys.modules.setdefault("yaml", yaml_stub)

# Ensure src package is importable
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data_collection.log_parser import LogParser


def test_parse_timestamp_with_timezone():
    parser = LogParser()
    ts = "10/Oct/2000:13:55:36 -0700"
    expected = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").isoformat()
    assert parser._parse_timestamp(ts) == expected

