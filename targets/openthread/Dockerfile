FROM interceptfuzz-base

WORKDIR /workspace

# OpenThread at the evaluated commit
RUN git clone https://github.com/openthread/openthread.git && \
    cd openthread && \
    git checkout 01bce95ba2f191e9dc378a0d71e8fc0bd7d9c9a9

# One source tree per fuzzer + one for coverage
RUN cp -r /workspace/openthread /workspace/openthread-aflnet \
    && cp -r /workspace/openthread /workspace/openthread-concat \
    && cp -r /workspace/openthread /workspace/openthread-cov \
    && mv /workspace/openthread /workspace/openthread-interceptfuzz

COPY patches/ /tmp/patches/

WORKDIR /workspace/openthread-interceptfuzz
RUN git apply --ignore-space-change --ignore-whitespace /tmp/patches/interceptfuzz.patch

WORKDIR /workspace/openthread-concat
RUN git apply --ignore-space-change --ignore-whitespace /tmp/patches/concat.patch

WORKDIR /workspace/openthread-aflnet
RUN git apply --ignore-space-change --ignore-whitespace /tmp/patches/aflnet.patch

WORKDIR /workspace/openthread-cov
RUN git apply --ignore-space-change --ignore-whitespace /tmp/patches/coverage.patch

WORKDIR /workspace

COPY init_fsm /workspace/init_fsm
COPY build_openthread.sh run_openthread_fuzzing.sh /workspace/
RUN chmod +x /workspace/build_openthread.sh /workspace/run_openthread_fuzzing.sh

# Fuzzing campaigns: run_docker.sh -t openthread ...
# Coverage re-collection: run_docker.sh -t openthread --coverage ... (overrides the entrypoint)
ENTRYPOINT ["/workspace/run_openthread_fuzzing.sh"]
CMD ["-h"]
