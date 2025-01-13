FROM ubuntu@sha256:80dd3c3b9c6cecb9f1667e9290b3bc61b78c2678c02cbdae5f0fea92cc6734ab AS app

RUN apt update && apt install -y socat gdb vim bash

#RUN mkdir -p /challenge
#WORKDIR /challenge
WORKDIR /
COPY chall .
COPY flag.txt .

#FROM pwn.red/jail

#COPY --from=app / /srv
#RUN mkdir -p /srv/app
#COPY --chmod=555 ./run /srv/app/run

#ENV JAIL_PIDS=40 JAIL_MEM=10M JAIL_TIME=120

USER root
CMD socat -T60 TCP-LISTEN:5000,reuseaddr,fork EXEC:"./chall"
