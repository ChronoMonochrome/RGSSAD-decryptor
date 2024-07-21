import os
import sys
import pybind11

from setuptools import setup, Extension

import sysconfig

# Get Python include and library paths
python_include = sysconfig.get_path("include")
python_library = sysconfig.get_config_var("LIBDIR")   # Note: Adjust if necessary

# Set the Boost include directory
boost_include = "/usr/include"  # Adjust this path if necessary


# Specify the compiler
if sys.platform == 'linux':
    os.environ['CC'] = 'g++'
    os.environ['CXX'] = 'c++'

ext_modules = [
    Extension(
        'decryptor',
        ['decryptor.cpp'],
    include_dirs=[python_include, pybind11.get_include()],
    library_dirs=[python_library],
        language='c++',
        extra_compile_args=['-std=c++23'],
    ),
]

setup(
    name='decryptor',
    ext_modules=ext_modules,
    zip_safe=False,
)
