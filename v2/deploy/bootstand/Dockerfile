# Public test tooling only. Runtime credentials/state are supplied later, never built into layers.
FROM openbao/openbao:2.7.2@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f AS bao
FROM postgres:17.11-bookworm@sha256:839fbb5a4942a7758dd93e18b42ea5649807491a0545b5eeeb8f0b8bb11857a5
USER root
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d
RUN --mount=type=secret,id=proxy_ca,required=true \
    apt-get -o Acquire::https::CaInfo=/run/secrets/proxy_ca update && \
    DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::CaInfo=/run/secrets/proxy_ca \
      install -y --no-install-recommends systemd-sysv dbus linux-image-cloud-amd64 \
      initramfs-tools qemu-system-x86 e2fsprogs nginx-light python3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=bao /usr/bin/bao /usr/bin/bao
ENTRYPOINT ["/bin/sh"]
