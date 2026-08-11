# Cloud Networking Lab

Hands-on networking exercises for backend, ML and cloud systems. The goal is to understand the network concepts underneath AWS/GCP/Azure/Huawei service names.

## Topics

- IPv4, CIDR and subnetting
- routing tables and default routes
- public vs private subnets
- NAT and internet gateways
- DNS resolution
- TCP sockets, ports and connection state
- HTTP, keep-alive and reverse proxies
- TLS and certificate termination
- load balancing and health checks
- stateful firewalls / security groups vs stateless ACLs
- retries, timeouts and circuit breaking
- VPC peering and private endpoints

## Labs

```text
01_cidr.py           CIDR membership and subnet splitting
02_tcp_echo.py       TCP client/server fundamentals
03_http_proxy.py     small reverse proxy
04_load_balancer.py  round-robin backend selection + health checks
05_retries.py        bounded exponential backoff
```

The examples are intentionally small enough to explain at a whiteboard.
