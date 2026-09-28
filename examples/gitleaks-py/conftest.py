"""Import the adapter the way the host starts it.

A plugin is a path, not a package.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
