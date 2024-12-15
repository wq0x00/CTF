FROM debian:bookworm-slim

RUN useradd --no-create-home -u 1000 user

RUN apt update && \
    apt install -y socat python3 python3-pip pipx gdb vim bash && \
    rm -rf /var/lib/apt/lists/*

#WORKDIR /home/user
WORKDIR /
COPY chal flag.txt solve.py ./

RUN chmod +x chal

#USER user
USER root

CMD socat -T60 TCP-LISTEN:1337,reuseaddr,fork EXEC:"./chal"
