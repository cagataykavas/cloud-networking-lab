FROM redis:8.2.10-alpine

USER root
RUN apk add --no-cache iptables

