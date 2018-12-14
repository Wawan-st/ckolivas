FROM ubuntu

RUN apt-get update -qq \
  && DEBIAN_FRONTEND=noninteractive apt-get install -yqq \
     build-essential autoconf automake libtool pkg-config \
     libcurl4-openssl-dev libudev-dev libusb-1.0-0-dev \
     libncurses5-dev libz-dev

WORKDIR /cgminer
COPY . src

ARG CONFIGURE_ARGS=--enable-bitfury

RUN cd src \
  && sh autogen.sh \
  && ./configure $CONFIGURE_ARGS \
  && make -j4 install \
  && DEBIAN_FRONTEND=noninteractive apt-get remove -yqq \
     build-essential autoconf automake libtool pkg-config \
     libcurl4-openssl-dev libudev-dev libusb-1.0-0-dev \
     libncurses5-dev libz-dev \
  && cd .. \
  && rm -rf src /var/lib/apt/lists/*

ENTRYPOINT [ "/usr/local/bin/cgminer" ]
