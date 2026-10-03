"""
longcat_sentinel.breaker
~~~~~~~~~~~~~~~~~~~~~~~~
Protocol-compliant stream interruption and synthetic event injection.
"""

from longcat_sentinel.breaker.compliant_injector import (
    CompliantInjector,
    closing_suffix,
    render_template,
)

__all__ = ["CompliantInjector", "closing_suffix", "render_template"]
