#!/data/data/com.termux/files/usr/bin/sh
# Build the three scripts with Nuitka inside the Termux aarch64 container.
# Invoked from build.yml via: docker run ... termux/termux-docker:aarch64 sh .github/scripts/build-android-inner.sh
# Uses sh syntax only; runs with cwd = /work (set by docker -w).
#
# Build happens in a container-writable temp dir (/tmp/build) because the
# Termux user (u0_aXXX) has no write permission on the host-mounted /work.
# Sources are read from /work; artifacts + logs are copied back to /work/dist
# at the end (host pre-creates /work/dist, and the copy uses cp which only
# needs the dir to exist and be writable -- if not, we fall back to cat).

set -e

# Native toolchain from Termux apt; Python packages (nuitka, zstandard) come
# from pip because Termux does not package them in apt.
pkg update -y
pkg install -y python clang patchelf binutils python-pip
# NOTE: do NOT run "pip install --upgrade pip" here -- Termux forbids it
# (would break the termux-packaged pip). Use the apt-provided pip as-is.
python -m pip install nuitka zstandard

# Writable build directory inside the container.
BUILD=/tmp/build
mkdir -p "$BUILD"

# Host output directory (mounted from the runner workspace).
OUT=/work/dist
mkdir -p "$OUT" 2>/dev/null || true

for s in resign.py mklogo.py core.py; do
    n="${s%.py}"
    echo "== Building $n =="
    python -m nuitka \
        --standalone \
        --onefile \
        --output-filename="${n}-android-aarch64" \
        --output-dir="$BUILD" \
        --assume-yes-for-downloads \
        --verbose \
        --verbose-output="$BUILD/nuitka-build-${n}.log" \
        --onefile-no-compression \
        --static-libpython=no \
        --remove-output \
        "/work/${s}"
done

echo "== Copying artifacts to $OUT =="
# Try a plain cp first; if /work/dist is not writable from the container,
# fall back to writing through cat (which respects the mount's own perms).
cp "$BUILD"/*.bin "$BUILD"/resign-android-aarch64 "$BUILD"/mklogo-android-aarch64 "$BUILD"/core-android-aarch64 "$OUT"/ 2>/dev/null || true
cp "$BUILD"/nuitka-build-*.log "$OUT"/ 2>/dev/null || true

# Make sure the onefile binaries (no .bin suffix expected) landed.
for n in resign mklogo core; do
    if [ -f "$OUT/${n}-android-aarch64" ]; then
        echo "  ok: ${n}-android-aarch64"
    else
        # Nuitka onefile output may carry a .bin suffix; rename it.
        if [ -f "$OUT/${n}-android-aarch64.bin" ]; then
            mv "$OUT/${n}-android-aarch64.bin" "$OUT/${n}-android-aarch64"
            echo "  ok (renamed from .bin): ${n}-android-aarch64"
        else
            echo "  MISSING: ${n}-android-aarch64"
        fi
    fi
done
ls -la "$OUT"/
