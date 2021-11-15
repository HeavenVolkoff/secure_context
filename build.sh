#!/usr/bin/env sh

# Be as POSIX compatible as posible.
# Check here for info on what is available:
# https://pubs.opengroup.org/onlinepubs/9699919799/idx/utilities.html

# Command Interpreter Configuration
set -e # exit immediate if an error occurs
set -u # don't allow not set variables to be utilized
# pipefail is not *yet* POSIX standard, but virtually every shell support it
eval 'set -o pipefail' || true # exit immediate if an error occurs in a pipeline

# Enable debug mode when envvar is present
if [ -n "${DEBUG:-}" ]; then set -x; fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Script must be run as root" 1>&2
  exit 1
fi

# Special variables
__dir=$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)

echo "Clearing old build files..."
rm -rf "${__dir}"/*.whl "${__dir}"/secure_context/**/*.so "${__dir}/dist" "${__dir}/build"

echo "Configuring QEMU for multi-arch build..."
docker run --privileged --rm tonistiigi/binfmt --install all 1>/dev/null

# List of docker images
_platforms="$(cat <<EOF
quay.io/pypa/manylinux2010_x86_64
quay.io/pypa/manylinux2010_i686
quay.io/pypa/manylinux2014_x86_64
quay.io/pypa/manylinux2014_i686
quay.io/pypa/manylinux2014_aarch64
quay.io/pypa/manylinux2014_ppc64le
EOF
)"

set -- linux-x86_64 linux-x86 linux-x86_64 linux-x86 linux-aarch64 linux-ppc64le

rm -rf "${__dir}/include"
mkdir -p "${__dir}/include"
curl -LsS 'https://ftp.openssl.org/source/old/1.1.0/openssl-1.1.0h.tar.gz' | tar -xzf- -C include
trap 'rm -rf "${__dir}"/*.whl "${__dir}"/secure_context/**/*.so "${__dir}/build" "${__dir}/include" ' EXIT

echo "Building secure_context package..."

# build package wheels
_owner="$(ls -nd "${__dir}/secure_context" | awk 'NR==1 {printf "%s:%s",$3,$4}')"
mkdir -p "${__dir}/dist"
chown "$_owner" "${__dir}/dist"
for _platform in $_platforms; do
  echo "Building package wheel for ${_platform}"
  i=$((${i:-0}+1))
  _tag="$(echo "$_platform" | awk -F'/' '{ print $3 }')"
  rm -rf "$__dir"/secure_context/**/*.so
  docker run -it --rm \
    -w /src/secure_context \
    -v "${__dir}:/src/secure_context" \
    --pull always \
    --entrypoint sh \
    "${_platform}" -c "$(cat << EOF
set -eux
eval 'set -o pipefail' || true

rm -rf secure_context/**/*.so

cd include/openssl-1.1.0h
make clean 1>/dev/null
./Configure "$(eval echo \${$i})" no-ssl3 no-comp no-idea no-asm no-dtls no-dtls1 no-shared no-hw no-engine no-threads no-dso no-err no-nextprotoneg no-psk no-srp no-ec2m no-weak-ssl-ciphers 1>/dev/null
make -j"\$(nproc)" 1>/dev/null
make install_sw 1>/dev/null

cd ../..
/opt/python/cp36-cp36m/bin/python ./build.py
/opt/python/cp36-cp36m/bin/python -m pip wheel --no-deps --use-pep517 .

for wheel in ./secure_context-*.whl; do
  mv "\$wheel" "dist/\$(basename "\$wheel" .whl | awk -F- -v tag="$_tag" '{ printf "%s-%s-%s-abi3-%s.%s.whl",\$1,\$2,\$3,\$5,tag }')"
done

chown -R '${_owner}' dist
EOF
)"
done
