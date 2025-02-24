#!/bin/bash

DISTRO=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
test -n $DISTRO && echo "distribution detected: ${DISTRO}" || echo "could not determine OS type"
if [[ "${DISTRO}" == 'Fedora' ]]; then
	echo 'Installing Fedora libraries for tls_wrapper'
	sudo dnf install \
						  avahi-devel \
						  elfutils-libelf-devel \
						  glib-devel \
						  gtk3-devel \
						  kernel-devel \
						  libconfig-devel \
						  libevent-devel \
						  libnl3-devel \
						  libssl-dev \
						  libnotify-devel \
						  openssl-devel \
						  qrencode \
						  libyaml-dev \
						  

	echo 'Installed'
fi

if [[ "${DISTRO}" == '"Ubuntu"' ]]; then
	echo 'Installing Ubuntu libraries for tls_wrapper'
	sudo apt install \
						  libavahi-client-dev \
						  libconfig-dev \
						  libelf-dev \
						  libevent-dev \
						  libglib2.0-dev \
						  libnl-3-dev \
						  libnl-genl-3-dev \
						  libssl-dev \
						  libnotify-dev \
						  linux-headers-$(uname -r | sed 's/[0-9\.\-]*//') \
						  openssl \
						  qrencode \
						  libyaml-dev \

	echo 'Installed'
fi
