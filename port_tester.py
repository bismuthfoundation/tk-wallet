import concurrent.futures
import json
import socket


def test_port(host_port):
    """Test if a port is open on a given host."""
    host, port = host_port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # 2 second timeout
        result = sock.connect_ex((host, int(port)))
        sock.close()

        if result == 0:  # Port is open
            return (host, port)
        return None
    except:
        return None


def main():
    # Input data
    endpoints = {
        "127.0.0.1": "5658",
        "62.112.10.156": "5658",
        "185.184.192.210": "5658",
        "185.100.232.131": "5658",
        "54.38.202.234": "5658",
        "116.120.60.143": "5658",
        "163.172.222.163": "5658",
        "91.121.87.99": "5658",
        "91.121.77.179": "5658",
        "51.15.47.212": "5658",
        "188.165.199.153": "5658",
        "95.216.177.5": "5658",
        "58.79.155.12": "5658",
        "51.15.118.29": "5658",
        "167.86.84.242": "5658",
        "46.105.43.213": "5658",
        "194.19.235.82": "5658",
        "159.89.123.247": "5658",
        "217.23.4.201": "5658",
        "209.250.238.142": "5658",
        "185.125.46.56": "5658",
        "46.171.63.219": "5658",
        "139.59.25.152": "5658",
        "45.32.115.135": "5658",
        "104.238.173.26": "5658",
        "178.62.68.118": "5658",
        "109.236.83.141": "5658",
        "180.68.191.77": "5658",
        "107.191.39.23": "5658",
        "108.61.90.91": "5658",
        "51.68.190.246": "5658",
        "149.28.53.219": "5658",
        "149.28.46.106": "5658",
        "140.82.11.77": "5658",
        "139.180.199.99": "5658",
        "139.59.91.47": "5658",
        "116.203.146.157": "5658",
        "116.203.209.88": "5658",
        "149.28.120.120": "5658",
        "208.167.245.204": "5658",
        "109.92.6.40": "5658",
        "162.213.123.200": "5658",
        "45.76.15.224": "5658",
        "45.77.6.146": "5658",
        "176.31.245.46": "5658",
        "188.166.118.218": "5658",
        "89.25.168.169": "5658",
        "89.25.168.162": "5658",
        "209.246.143.198": "5658",
        "104.248.73.153": "5658",
        "149.28.162.236": "5658",
        "159.89.10.229": "5658",
        "109.190.174.238": "5658",
        "178.128.222.221": "5658",
        "80.240.18.114": "5658",
        "192.99.34.19": "5658",
        "bismuth.live": "5658",
        "89.25.168.163": "5658",
        "217.23.14.6": "5658",
        "89.25.168.178": "5658",
        "51.68.152.196": "5658"
    }

    # Create a thread pool and test all endpoints
    responding_endpoints = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_endpoint = {executor.submit(test_port, (host, port)): (host, port)
                              for host, port in endpoints.items()}

        for future in concurrent.futures.as_completed(future_to_endpoint):
            result = future.result()
            if result:
                host, port = result
                responding_endpoints[host] = port

    # Output the results in a single line
    print(json.dumps(responding_endpoints, separators=(',', ':')))


if __name__ == "__main__":
    main()
