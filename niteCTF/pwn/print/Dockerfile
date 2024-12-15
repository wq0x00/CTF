FROM debian:bookworm-slim AS chroot

RUN useradd --no-create-home -u 1000 user

RUN apt update && \
    apt install -y socat libc6 python3 python3-pip pipx gdb vim bash  && \
    rm -rf /var/lib/apt/lists/*


# Add pipx to the PATH (this ensures you can use pipx in the container)
ENV PATH="/root/.local:$PATH"

# Install a Python package using pipx

RUN pipx install pwntools


COPY chall /home/user/
COPY flag.txt /home/user/
COPY solve.py /home/user/



RUN chmod +x /home/user/chall && \
    chmod 444 /home/user/flag.txt
#WORKDIR /home/user/
WORKDIR /
USER root


CMD socat -T60 TCP-LISTEN:1337,reuseaddr,fork EXEC:"/home/user/chall"
