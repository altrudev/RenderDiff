"""Map only the selected Python runtime into an isolated worker."""
from __future__ import annotations
import sys
from pathlib import Path

def isolated_python():
    base=Path(sys.base_prefix).resolve()
    executable=Path(getattr(sys,'_base_executable',sys.executable)).resolve()
    if executable.is_relative_to(base) and not base.is_relative_to(Path('/usr')):
        target=Path('/opt/renderdiff-python')
        return ['--ro-bind',str(base),str(target)], str(target/executable.relative_to(base)), {'PYTHONHOME':str(target)}
    if executable.is_relative_to(Path('/usr')):
        return [],str(executable),{}
    raise RuntimeError('Python runtime cannot be safely mapped into the sandbox')
