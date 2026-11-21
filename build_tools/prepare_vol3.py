"""Install RAMBreaker's bundled Vol3 plugins + idempotent framework fixes
into a Volatility 3 source tree (runtime\\volatility3 or the dist copy)."""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
logging.basicConfig(level=logging.INFO, format="%(message)s")
from modules.installer import VolatilityInstaller  # noqa: E402

root = Path(sys.argv[1])
inst = VolatilityInstaller(logging.getLogger("prep"))
print("plugins:", inst.install_bundled_plugins(root))
print("layers:", inst.install_bundled_layers(root))
print("fixes:", inst.apply_framework_fixes(root))
