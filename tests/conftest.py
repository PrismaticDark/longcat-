"""
tests/conftest.py
Pytest fixtures and environment setup for LongCat Sentinel v2.3.
"""

import os

try:
    import pytest

    @pytest.fixture(autouse=True)
    def clean_environment():
        """Ensure sensitive environment variables do not leak between test cases."""
        original_env = os.environ.copy()
        yield
        os.environ.clear()
        os.environ.update(original_env)
except ImportError:
    # Pytest is not installed on this environment; conftest is dormant.
    pass
