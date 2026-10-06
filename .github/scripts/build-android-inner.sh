#!/data/data/com.termux/files/usr/bin/sh
# Build the three scripts with Nuitka inside the Termux aarch64 container.
# Invoked from build.yml via: docker run ... termux/termux-docker:aarch64 sh .github/scripts/build-android-inner.sh
# Uses sh syntax only; runs with cwd = /work (set by docker -w).

set -e

# Native toolchain from Termux apt; Python packages (nuitka, zstandard) come
# from pip because Termux does not package them in apt.
pkg update -y
pkg install -y python clang patchelf binutils python-pip
python -m pip install --upgrade pip
python -m pip install nuitka zstandard

for s in resign.py mklogo.py core.py; do
    n="${s%.py}"
    echo "== Building $n =="
    python -m nuitka \
        --standalone \
        --onefile \
        --output-filename="${n}-android-aarch64" \
        --output-dir=/work/dist \
        --assume-yes-for-downloads \
        --verbose \
        --verbose-output="/work/dist/nuitka-build-${n}.log" \
        --onefile-no-compression \
        --static-libpython=no \
        --remove-output \
        "/work/${s}"
done
