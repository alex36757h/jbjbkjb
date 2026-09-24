FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates unzip && rm -rf /var/lib/apt/lists/*
COPY vless-test.sh /vless-test.sh
RUN chmod +x /vless-test.sh
ENV PORT=8080
CMD ["/vless-test.sh"]
