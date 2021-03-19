#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2

set -exo pipefail

if [[ $DOCKER_IMAGE == fedora* ]]; then
    yum -y install qrencode-devel liboath-devel plymouth-devel
elif [[ $DOCKER_IMAGE == opensuse* ]]; then
    zypper -n in qrencode-devel liboath-devel plymouth-devel
elif [[ $DOCKER_IMAGE == ubuntu* ]]; then
    apt-get update; apt-get -y install libqrencode-dev liboath-dev libplymouth-dev plymouth
fi

pushd "$1"

if [ -z "$TPM2TSS_BRANCH" ]; then
    echo "TPM2TSS_BRANCH is unset, please specify TPM2TSS_BRANCH"
    exit 1
fi

if [ -z "$TPM2TOOLS_BRANCH" ]; then
    echo "TPM2TOOLS_BRANCH is unset, please specify TPM2TOOLS_BRANCH"
    exit 1
fi

# Install tpm2-tss
if [ ! -d tpm2-tss ]; then

  git clone --depth=1 -b "${TPM2TSS_BRANCH}" "https://github.com/tpm2-software/tpm2-tss.git"
  pushd tpm2-tss
  ./bootstrap
  ./configure --enable-debug
  make -j$(nproc)
  make install
  popd
else
  echo "tpm2-tss already installed, skipping..."
fi

# Install tpm2-tools
if [ ! -d tpm2-tools ]; then
  git clone --depth=1 -b "${TPM2TOOLS_BRANCH}" "https://github.com/tpm2-software/tpm2-tools.git"
  pushd tpm2-tools
  ./bootstrap
  ./configure --enable-debug --disable-hardening
  make -j$(nproc)
  make install
  popd
else
  echo "tpm2-tss already installed, skipping..."
fi

popd

exit 0
