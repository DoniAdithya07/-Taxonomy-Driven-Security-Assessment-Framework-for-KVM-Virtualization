import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import make_fixtures  # noqa: E402


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory):
    out = tmp_path_factory.mktemp("fx")
    make_fixtures.main(out)
    return out
