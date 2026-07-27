"""Builds a platform-specific (py3-none-win_amd64) wheel bundling thirdeye.dll.

Pure-ctypes package: version-agnostic across CPython 3, but platform-locked
to Windows x64 because it ships a native DLL.
"""

from setuptools import setup
from setuptools.dist import Distribution
from wheel.bdist_wheel import bdist_wheel


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True


class BdistWheel(bdist_wheel):
    def finalize_options(self):
        super().finalize_options()
        self.root_is_pure = False

    def get_tag(self):
        _, _, plat = super().get_tag()
        return "py3", "none", plat


setup(distclass=BinaryDistribution, cmdclass={"bdist_wheel": BdistWheel})
