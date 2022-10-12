# Build Stage
FROM --platform=linux/amd64 ubuntu:22.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y clang

## Add source code to the build stage.
ADD . /libnpy
WORKDIR /libnpy/mayhem

## Build
RUN clang++ -fsanitize=fuzzer,address,undefined fuzz_parse_header.cpp -I ../include -o fuzz_parse_header

# Package Stage
FROM --platform=linux/amd64 ubuntu:22.04
COPY --from=builder /libnpy/mayhem/fuzz_parse_header /fuzz_parse_header

## Set up fuzzing!
ENTRYPOINT []
CMD /fuzz_parse_header
