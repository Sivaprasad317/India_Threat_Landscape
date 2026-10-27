"""
Collector registry.

Importing this package registers every collector. Add a new source by
creating a module here with a @register-decorated BaseCollector subclass and
importing it below.
"""

from .base import (BaseCollector, all_collectors, available_collectors,
                   register)

# Import order does not matter; each module self-registers.
from . import ransomware          # noqa: F401
from . import vulns               # noqa: F401
from . import malware_infra       # noqa: F401
from . import phishing            # noqa: F401
from . import india_specific      # noqa: F401
from . import research_exposure   # noqa: F401

__all__ = ["BaseCollector", "register", "all_collectors",
           "available_collectors"]
