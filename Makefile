# SPDX-License-Identifier: GPL-2.0
#
# Top-level build for revdi: the Rust EVDI kernel module (module/) and the
# ABI-compatible Rust libevdi (library/).
#
# The kernel module needs a kernel tree that carries the Rust DRM/KMS bindings
# (a stock distro kernel will not build it yet); point KDIR at it:
#
#   make KDIR=/path/to/drm-next
#   sudo make install KDIR=/path/to/drm-next
#
# The library builds against the system Rust toolchain and has no such
# requirement.

KDIR ?= /lib/modules/$(shell uname -r)/build

all: module library

module:
	$(MAKE) -C module KDIR=$(KDIR)

library:
	$(MAKE) -C library

install: install-module install-library

install-module:
	$(MAKE) -C module modules_install KDIR=$(KDIR)

install-library:
	$(MAKE) -C library install

clean:
	$(MAKE) -C module clean KDIR=$(KDIR)
	$(MAKE) -C library clean

.PHONY: all module library install install-module install-library clean
