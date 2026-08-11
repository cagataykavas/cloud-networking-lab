from ipaddress import ip_address, ip_network


def contains(cidr: str, ip: str) -> bool:
    return ip_address(ip) in ip_network(cidr, strict=False)


def split(cidr: str, new_prefix: int) -> list[str]:
    return [str(n) for n in ip_network(cidr, strict=False).subnets(new_prefix=new_prefix)]


if __name__ == "__main__":
    network = "10.42.0.0/16"
    print("contains 10.42.3.8:", contains(network, "10.42.3.8"))
    print("first /24 subnets:", split(network, 24)[:4])
