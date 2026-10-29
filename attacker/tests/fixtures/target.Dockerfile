FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server util-linux && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/sh lab && passwd -d lab && mkdir -p /run/sshd
COPY target.py /fixture/target.py
CMD ["python3", "/fixture/target.py"]
