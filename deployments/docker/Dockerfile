FROM debian:bookworm-slim AS build

RUN apt-get update \
  && apt-get install -y --no-install-recommends build-essential cmake ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
COPY tests ./tests

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  && cmake --build build -j"$(nproc)" \
  && ctest --test-dir build --output-on-failure

FROM debian:bookworm-slim AS runtime

RUN useradd --system --uid 10001 --create-home --home-dir /app netmon

WORKDIR /app
COPY --from=build /src/build/openwrt-netmon-lite /usr/local/bin/openwrt-netmon-lite
COPY config.example.yaml /app/config.yaml
COPY web /app/web

USER netmon
EXPOSE 8080/tcp 1514/udp 1514/tcp

ENTRYPOINT ["/usr/local/bin/openwrt-netmon-lite"]
CMD ["--config", "/app/config.yaml"]
