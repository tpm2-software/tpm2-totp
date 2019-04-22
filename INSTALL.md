# Dependencies

## GNU/Linux
* GNU Autoconf
* GNU Autoconf Archive
* GNU Automake
* GNU Libtool
* C compiler
* C library development libraries and header files
* pkg-config
* tpm2-tss >= 2.0
* libqrencode
* pandoc

For the integration test suite:
* liboath
* tpm_server
* realpath
* ss

## Ubuntu
```
sudo apt -y install \
  build-essential \
  autoconf \
  autoconf-archive \
  automake \
  m4 \
  libtool \
  gcc \
  pkg-config \
  libqrencode-dev \
  pandoc \
  liboath-dev \
  iproute2
git clone --depth=1 http://www.github.com/tpm2-software/tpm2-tss
cd tpm2-tss
./bootstrap
./configure
make -j$(nproc)
sudo make install
```

# Building from source
```
./bootstrap
./configure
make -j$(nproc)
make -j$(nproc) check
sudo make install
```

# Configuration options
You may pass the following options to `./configure`

## Debug messages
This option will enable a lot of debug printing during the invocation of the
library:
```
./configure --enable-debug
```

## Developer linking
In order to link against a developer version of tpm2-tss (not installed):
```
./configure \
  PKG_CONFIG_PATH=${TPM2TSS}/lib:$PKG_CONFIG_PATH \
  CFLAGS=-I${TPM2TSS}/include \
  LDFLAGS=-L${TPM2TSS}/src/tss2-{tcti,mu,sys,esys}/.libs 
```

# Post installation

## ldconfig
You may need to run ldconfig after `make install` to update runtime bindings:
```
sudo ldconfig
```
