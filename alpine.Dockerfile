FROM debian:trixie-slim AS builder

# Install curl: sudo apt install curl
# Install build tools: sudo apt install build-essential
# Install LevelDB: sudo apt install libleveldb-dev libsnappy-dev cmake
RUN apt-get update && apt-get upgrade -y && apt-get install -y curl build-essential libleveldb-dev libsnappy-dev cmake git rustup musl-tools libstdc++6

RUN rustup default stable
RUN ln -s /bin/g++ /bin/musl-g++
#RUN ln -s /usr/bin/g++ /bin/musl-g++

# Install the rust compiler and accessories: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
#RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Source the rust environment: source "$HOME/.cargo/env"
#RUN . "$HOME/.cargo/env"

#RUN useradd --create-home --shell /bin/false triton
#RUN chown triton:triton -cR /home/triton

#USER triton
#WORKDIR /home/triton/

# Download the repository: git clone https://github.com/Neptune-Crypto/neptune-core.git
RUN git clone https://github.com/Neptune-Crypto/neptune-core.git /app

# Enter the repository: cd neptune-core
WORKDIR /app

# Checkout the release branch git checkout release. (Alternatively, for the unstable development branch, skip this step.)
ARG NEPTUNE_TAG="release"
RUN git checkout $NEPTUNE_TAG

# Build for release and put the binaries in your local path (~/.cargo/bin/): cargo install --locked --path . (needs at least 3 GB of RAM and a few minutes)
#RUN "$HOME/.cargo/bin/cargo" install --locked --path .
#RUN cargo install --locked --path .

#RUN ["/root/.cargo/bin/cargo", "build", "--release"]
#ENTRYPOINT ["/root/.cargo/bin/cargo", "run", "--release", "--", "--peers", "51.15.139.238:9798", "--peers", "139.162.193.206:9798", "--peers", "[2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9]:9798"]
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo build --target x86_64-unknown-linux-musl

#RUN ["cargo", "build", "--locked", "--release"]
RUN cargo build --locked --release

#RUN echo ${PWD} && ls /app/target/ -alR

FROM alpine AS final

RUN adduser -D -h /home/triton -s /bin/false triton
RUN mkdir -p -m 777 /home/triton/.local/share/neptune/main
#RUN chmod 777 -cR /home/triton/.local/share/neptune/main
RUN chown triton:triton -cR /home/triton/.local/share/neptune/main
VOLUME /home/triton/.local/share/neptune/main

WORKDIR /home/triton/
COPY --from=builder --chown=triton:triton \
  /app/target/release/neptune-core \
  /app/target/release/neptune-cli \
  /app/target/release/neptune-dashboard \
  /app/target/release/triton-vm-prover .

WORKDIR /home/triton/
RUN echo ${PWD} && ls /home/triton/ -alR
USER triton

ENTRYPOINT ["/home/triton/neptune-core", "--peers", "51.15.139.238:9798", "--peers", "139.162.193.206:9798", "--peers", "[2001:bc8:17c0:41e:46a8:42ff:fe22:e8e9]:9798"]
