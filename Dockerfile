FROM ubuntu:22.04

# Prevent interactive prompts during apt installations
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /workspace

RUN apt-get update && apt-get install -y \
    git \
    curl \
    ccache \
    ninja-build \
    build-essential \
    python3 \
    python3-pip \
    clang \
    lld \
    patch \
    libpcap-dev \
    wget \
    lsb-release \
    software-properties-common \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install cmake gcovr

# Install clang-18
RUN wget https://apt.llvm.org/llvm.sh \
    && chmod +x llvm.sh \
    && ./llvm.sh 18 \
    && rm llvm.sh

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 \
    --slave /usr/bin/clang++ clang++ /usr/bin/clang++-18 \
    && update-alternatives --install /usr/bin/cc cc /usr/bin/clang-18 100 \
    && update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++-18 100 \
    && update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/ld.lld-18 100

ENV CC="ccache clang"
ENV CXX="ccache clang++"

# Build AFL++
RUN git clone https://github.com/AFLplusplus/AFLplusplus
RUN cd AFLplusplus && git checkout 247e8241b4b56520f50846433ac9d10b338e8961 && make all && make install

# Install cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Stateful fuzzing components used by AFLNet (LibAFL)
COPY third_party /workspace/third_party
RUN cd /workspace/third_party/butterfly && \
    cargo build --release
RUN cd /workspace/third_party/netfuzzbench-common && \
    cargo build --release

# Build AFLNet (LibAFL reimplementation)
COPY fuzzers/aflnet /workspace/fuzzers/aflnet
RUN cd /workspace/fuzzers/aflnet && \
    cargo build --release

# Install nlohmann/json
RUN wget -qO- https://github.com/nlohmann/json/archive/refs/tags/v3.12.0.tar.gz | tar -xz && \
    cd json-3.12.0 && \
    mkdir -p build && cd build && cmake -DJSON_BuildTests=OFF .. && make -j 4 && make install && ldconfig && \
    cd ../.. && rm -rf json-3.12.0

# Build & install the InterceptFuzz library (linked into the target harnesses)
COPY fuzzers/interceptfuzz /workspace/fuzzers/interceptfuzz
RUN cd /workspace/fuzzers/interceptfuzz && \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF && \
    cmake --build build --config Release && \
    cmake --install build --prefix /usr/local

# Concat
COPY fuzzers/concat /workspace/fuzzers/concat

# Coverage collection and run statistics (shared by all fuzzers)
COPY common /workspace/common

CMD ["/bin/bash"]
