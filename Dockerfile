FROM ubuntu:20.04
LABEL authors="ubuntu"

RUN apt update
RUN apt install -y gcc-multilib g++-multilib cmake openjdk-17-jdk
RUN apt install -y tar wget
WORKDIR /compile

COPY . .

ENTRYPOINT ["bash"]
