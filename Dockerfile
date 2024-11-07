FROM ubuntu:20.04
LABEL authors="ubuntu"

RUN apt update
RUN apt install -y gcc-multilib g++-multilib cmake openjdk-17-jdk
RUN apt install -y tar wget
RUN cd / && wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz && tar xf libsodium-1.0.20.tar.gz

WORKDIR /compile

COPY . .

ENTRYPOINT ["bash"]
