# FROM alpine:3.22 AS builder
# RUN apk add gcc musl-dev linux-headers
# COPY main.c /main.c
# RUN gcc -g -static -o /main /main.c

# FROM scratch
# EXPOSE 7191
# COPY --from=builder /main /main
# CMD ["/main"]

FROM scratch

EXPOSE 7191

COPY main /main

CMD ["/main"]
