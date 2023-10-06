#!/usr/bin/env python3
# type: ignore
"""Modified version of build.py from pendulum (Copyright (c) 2015 Sébastien Eustace)
Original:
    https://github.com/sdispater/pendulum/blob/a2267c0/build.py
Licensed under:
    MIT License (https://github.com/sdispater/pendulum/blob/master/LICENSE)
"""

# Internal
import shutil
from os import path, stat, chmod
from distutils.core import Extension, Distribution
from distutils.command.build_ext import build_ext


def build(setup_kwargs):
    """
    This function is mandatory in order to build the extensions.
    """
    distribution = Distribution(
        {
            "name": "secure_context",
            "ext_modules": [
                Extension(
                    "secure_context._extensions._edhc_curve",
                    ["secure_context/_extensions/_edhc_curve.c"],
                    optional=True,
                    libraries=["ssl", "crypto"],
                    define_macros=[("Py_LIMITED_API", "0x03060000")],
                ),
            ],
        }
    )
    distribution.package_dir = "secure_context"

    cmd = build_ext(distribution)
    cmd.ensure_finalized()
    cmd.run()

    # Copy built extensions back to the project
    for output in cmd.get_outputs():
        relative_extension = path.relpath(output, cmd.build_lib)
        if not path.exists(output):
            continue

        directory = path.dirname(relative_extension)
        file_name_parts = path.basename(relative_extension).split(".")
        if len(file_name_parts) > 2:
            file_name_parts[-2] = "abi3"
        relative_extension = f"{directory}/{'.'.join(file_name_parts)}"

        shutil.copyfile(output, relative_extension)
        mode = stat(relative_extension).st_mode
        mode |= (mode & 0o444) >> 2
        chmod(relative_extension, mode)

    return setup_kwargs


if __name__ == "__main__":
    build({})
