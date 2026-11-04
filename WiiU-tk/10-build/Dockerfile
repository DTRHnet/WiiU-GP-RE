FROM ubuntu:20.04
# Persistent builder for the Wii U DRC stack (pc2drc's supported environment).
# Ubuntu 20.04 / gcc 9 + OpenSSL 1.0.1u baked in, because drc-hostap is 2016-era
# code that dereferences OpenSSL structs made opaque in 1.1+.
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential pkg-config git ca-certificates wget nasm yasm \
      autoconf automake libtool m4 \
      libnl-3-dev libnl-genl-3-dev \
      libswscale-dev libavutil-dev libavcodec-dev \
      libsdl2-dev libglew-dev freeglut3-dev libgl1-mesa-dev \
      libvncserver-dev libjpeg-dev libpng-dev zlib1g-dev libbz2-dev liblzo2-dev \
      libgcrypt20-dev cmake \
 && rm -rf /var/lib/apt/lists/*

# OpenSSL 1.0.1u into /opt/drc/external_pkg_install_dir so that the drc-hostap
# defconfig path rewrite (/_123sedreplaceme -> /opt/drc) resolves correctly.
# ftp.openssl.org is unreachable from the build container, so the tarball is
# fetched on the host (GitHub release mirror) and copied into the build context.
COPY openssl-1.0.1u.tar.gz /tmp/openssl-1.0.1u.tar.gz
RUN cd /tmp \
 && tar xf openssl-1.0.1u.tar.gz && cd openssl-1.0.1u \
 && ./config --prefix=/opt/drc/external_pkg_install_dir/ --openssldir=openssl threads zlib no-shared \
 && make -j"$(nproc)" \
 && make install \
 && cd / && rm -rf /tmp/openssl*

# Sanity: what the image actually provides
RUN echo "== gcc: $(gcc -dumpversion)" \
 && echo "== openssl: $(ls /opt/drc/external_pkg_install_dir/lib/libssl.a /opt/drc/external_pkg_install_dir/lib/libcrypto.a 2>&1)" \
 && echo "== vncclient: $(ls /usr/lib/x86_64-linux-gnu/libvncclient* 2>&1 | head -2)" \
 && echo "== rfbclient.h: $(ls /usr/include/rfb/rfbclient.h 2>&1)"
