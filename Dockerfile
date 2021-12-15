FROM ubuntu:20.04 as main

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get full-upgrade -y
RUN apt-get install -y libbotan-2-12


FROM main as builder
RUN apt-get install -y build-essential ninja-build cmake git
RUN apt-get install -y libbotan-2-dev
RUN git clone https://github.com/wille-io/fast-ca
WORKDIR /fast-ca
RUN cmake -S . -B build
RUN cmake --build build


FROM main
COPY --from=builder /fast-ca/build/fastca /usr/local/bin/
CMD /usr/local/bin/fastca

