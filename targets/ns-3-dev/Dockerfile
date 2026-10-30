FROM interceptfuzz-base

WORKDIR /workspace

# ns-3-dev at the evaluated commit
RUN git clone https://gitlab.com/nsnam/ns-3-dev.git && \
    cd ns-3-dev && \
    git checkout be3db7b65393a43537393448b3d7e456267cf8c5

# One source tree per fuzzer + one for coverage
RUN cp -r /workspace/ns-3-dev /workspace/ns-3-dev-aflnet \
    && cp -r /workspace/ns-3-dev /workspace/ns-3-dev-concat \
    && cp -r /workspace/ns-3-dev /workspace/ns-3-dev-cov \
    && mv /workspace/ns-3-dev /workspace/ns-3-dev-interceptfuzz

COPY patches/ /tmp/patches/

WORKDIR /workspace/ns-3-dev-interceptfuzz
RUN git apply --ignore-space-change --ignore-whitespace /tmp/patches/interceptfuzz.patch

WORKDIR /workspace/ns-3-dev-concat
RUN git apply --ignore-space-change --ignore-whitespace /tmp/patches/concat.patch

WORKDIR /workspace/ns-3-dev-aflnet
RUN git apply --ignore-space-change --ignore-whitespace /tmp/patches/aflnet.patch

WORKDIR /workspace/ns-3-dev-cov
RUN git apply --ignore-space-change --ignore-whitespace /tmp/patches/coverage.patch

WORKDIR /workspace

COPY init_fsm /workspace/init_fsm
COPY build_ns-3-dev.sh run_ns-3-dev_fuzzing.sh /workspace/
RUN chmod +x /workspace/build_ns-3-dev.sh /workspace/run_ns-3-dev_fuzzing.sh

# Fuzzing campaigns: run_docker.sh -t ns-3-dev ...
# Coverage re-collection: run_docker.sh -t ns-3-dev --coverage ... (overrides the entrypoint)
ENTRYPOINT ["/workspace/run_ns-3-dev_fuzzing.sh"]
CMD ["-h"]
