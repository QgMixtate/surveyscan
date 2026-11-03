FROM scratch
COPY --chmod=755 .dist/surveyscan-server /surveyscan-server
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/surveyscan-server"]
