#!/usr/bin/env sh

# Be as POSIX compatible as posible.
# Check here for info on what is available:
# https://pubs.opengroup.org/onlinepubs/9699919799/idx/utilities.html

# Command Interpreter Configuration
set -e # exit immediate if an error occurs
set -u # don't allow not set variables to be utilized
# pipefail is not *yet* POSIX standard, but virtually every shell support it
# shellcheck disable=3040
eval 'set -o pipefail' || true # exit immediate if an error occurs in a pipeline

# Enable debug mode when envvar is present
if [ -n "${DEBUG:-}" ]; then set -x; fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Script must be run as root" 1>&2
  exit 1
fi

# Special variables
__dir=$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)

echo "Configuring QEMU for multi-arch build"

# Register qemu
docker run --privileged --rm tonistiigi/binfmt --install
docker run --rm --privileged aptman/qus -s -- -p i386 \
  arm armeb aarch64 aarch64_be x86_64 1>/dev/null 2>&1

_platforms='quay.io/pypa/manylinux2014_x86_64 quay.io/pypa/manylinux2014_i686 quay.io/pypa/manylinux2014_aarch64 quay.io/pypa/manylinux2014_ppc64le quay.io/pypa/manylinux2014_s390x'
_python_versions='3.6 3.7 3.8 3.9 3.10'

echo "Building secure_context package..."
echo "Supported architectures: ${_platforms}"

# build package wheels
_owner="$(ls -nd "${__dir}/secure_context" | awk 'NR==1 {printf "%s:%s",$3,$4}')"
for _py in $_python_versions; do
  for _platform in $_platforms; do
    echo "Building package wheel for ${_platform}, python ${_py}"
    rm -rf secure_context/**/*.so
    docker run --rm \
      -u "${_owner}" \
      -w /src/secure_context \
      -v "${__dir}:/src/secure_context" \
      --pull always \
      "${_platform}" build -f wheel
  done
done

# build package sdist
echo "Building package sdist"
docker run --rm \
  -u "${_owner}" \
  -w /src/secure_context \
  -v "/src/secure_context:${__dir}" \
  --pull always \
  "vvasconcellos/poetry-build:$(echo "${_platform}" | awk 'NF>1{print $NF}')" build -f sdist
