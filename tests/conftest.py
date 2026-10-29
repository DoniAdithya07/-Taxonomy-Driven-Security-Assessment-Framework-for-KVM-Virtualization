import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import make_fixtures  # noqa: E402


def pytest_configure(config):
    # pytest's basetemp (set via --basetemp in pytest.ini) is created with
    # mkdir(parents=False), so a fresh clone needs the parent directories to
    # exist up front; .local/ is gitignored and otherwise only appears once
    # someone has already run the suite or created .local/venv.
    basetemp = config.option.basetemp
    if basetemp:
        Path(basetemp).parent.mkdir(parents=True, exist_ok=True)


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory):
    out = tmp_path_factory.mktemp("fx")
    make_fixtures.main(out)
    return out
