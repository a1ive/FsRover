#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Package an already configured and built CMake tree as GtkRover AppImage.
#
#   scripts/build-appimage.sh <build dir> [output dir]
#
# The tree must have been configured with -DROVER_GTK_REQUIRED=ON so that
# GtkRover, libmagic and the translations are all present.  linuxdeploy and
# its GTK plugin are taken from $LINUXDEPLOY / $LINUXDEPLOY_PLUGIN_GTK, or
# downloaded into <build dir>/appimage-tools.  The AppImage runs on systems
# whose glibc is at least as new as the build host's.

set -eu

if [ $# -lt 1 ]; then
	echo "usage: $0 <build dir> [output dir]" >&2
	exit 2
fi

build=$(realpath "$1")
out=$(realpath "${2:-$build}")
appdir="$build/AppDir"
tools="$build/appimage-tools"
arch=$(uname -m)
id=io.github.a1ive.FsRover

if [ ! -x "$build/GtkRover" ]; then
	echo "$build/GtkRover is missing; configure with -DROVER_GTK_REQUIRED=ON" >&2
	exit 1
fi

fetch() {
	if [ ! -x "$2" ]; then
		mkdir -p "$(dirname "$2")"
		curl -fsSL -o "$2.part" "$1"
		chmod +x "$2.part"
		mv "$2.part" "$2"
	fi
}

linuxdeploy=${LINUXDEPLOY:-$tools/linuxdeploy-$arch.AppImage}
plugin_gtk=${LINUXDEPLOY_PLUGIN_GTK:-$tools/linuxdeploy-plugin-gtk.sh}
fetch "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-$arch.AppImage" \
	"$linuxdeploy"
fetch "https://raw.githubusercontent.com/linuxdeploy/linuxdeploy-plugin-gtk/master/linuxdeploy-plugin-gtk.sh" \
	"$plugin_gtk"
# linuxdeploy finds plugins next to itself or on PATH.
PATH="$(dirname "$plugin_gtk"):$PATH"
export PATH

rm -rf "$appdir"
cmake --install "$build" --prefix "$appdir/usr"

# libmagic's compiled-in database path points at the host; GtkRover looks
# for this copy relative to itself first (propsdlg.cpp).
magic=
for candidate in /usr/lib/file/magic.mgc /usr/share/misc/magic.mgc /usr/share/file/magic.mgc; do
	if [ -f "$candidate" ]; then
		magic=$candidate
		break
	fi
done
if [ -z "$magic" ]; then
	echo "magic.mgc not found; install libmagic-mgc" >&2
	exit 1
fi
mkdir -p "$appdir/usr/share/fsrover"
cp -L "$magic" "$appdir/usr/share/fsrover/magic.mgc"

# The tools are AppImages themselves; CI runners have no FUSE.
APPIMAGE_EXTRACT_AND_RUN=1
DEPLOY_GTK_VERSION=4
export APPIMAGE_EXTRACT_AND_RUN DEPLOY_GTK_VERSION

# Pass 1: deploy libraries and the GTK runtime files.
"$linuxdeploy" --appdir "$appdir" --plugin gtk \
	--executable "$appdir/usr/bin/GtkRover" \
	--executable "$appdir/usr/bin/LinuxRover" \
	--desktop-file "$appdir/usr/share/applications/$id.desktop" \
	--icon-file "$appdir/usr/share/icons/hicolor/256x256/apps/$id.png"

# The GTK plugin pins GDK_BACKEND=x11, a GTK 3 era workaround; GTK 4 picks
# Wayland or X11 by itself, and the user's own GDK_BACKEND should win.
hook="$appdir/apprun-hooks/linuxdeploy-plugin-gtk.sh"
if [ -f "$hook" ]; then
	sed -i 's/^export GDK_BACKEND=x11.*$/: # GDK_BACKEND left to GTK and the user/' "$hook"
fi

# Pass 2: pack.
mkdir -p "$out"
cd "$out"
ARCH=$arch "$linuxdeploy" --appdir "$appdir" --output appimage
