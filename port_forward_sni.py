import socket
import threading
import select
import logging
import struct
import traceback

# 初始化日志
def init_logging(enable_logging):
    if enable_logging:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    else:
        logging.disable(logging.CRITICAL)

# 解析HTTP请求的URL
def parse_http_request(data):
    try:
        request_line = data.split(b'\r\n')[0]
        method, url, version = request_line.split(b' ')
        return url.decode('utf-8')
    except Exception as e:
        print(f"Error parsing HTTP request: {e}")
        return None

# 解析TLS Client Hello消息中的SNI
def parse_sni(data):
    try:
        print(f"First bytes: {' '.join([hex(b) for b in data[:10]])}")
        print(f"Total data length: {len(data)}")
        
        # 1. 检查基本长度
        if len(data) < 5:
            print("Data too short for TLS header")
            return None
            
        # 2. 验证TLS记录层
        if not (data[0] == 0x16 and data[1] == 0x03):
            print("Not a TLS handshake")
            return None
            
        # 3. 获取TLS记录层长度
        tls_record_length = struct.unpack('>H', data[3:5])[0]
        print(f"TLS record length: {tls_record_length}")
        
        if len(data) < tls_record_length + 5:
            print(f"TLS record incomplete. Expected {tls_record_length + 5} bytes, got {len(data)}")
            return None
            
        # 4. 解析Handshake层
        offset = 5  # TLS record header length
        handshake_type = data[offset]
        handshake_length = struct.unpack('>I', b'\x00' + data[offset+1:offset+4])[0]
        print(f"Handshake type: {hex(handshake_type)}, length: {handshake_length}")
        
        if handshake_type != 0x01:
            print("Not a Client Hello message")
            return None
            
        # 5. 移动到Client Hello内容
        offset += 4  # Skip handshake header
        client_version = struct.unpack('>H', data[offset:offset+2])[0]
        print(f"Client Version: {hex(client_version)}")
        offset += 2
        
        # 6. 跳过Client Random
        offset += 32
        
        # 7. 跳过Session ID
        if len(data) < offset + 1:
            print("Data too short for session ID")
            return None
        session_id_length = data[offset]
        print(f"Session ID length: {session_id_length}")
        offset += 1 + session_id_length
        
        # 8. 跳过Cipher Suites
        if len(data) < offset + 2:
            print("Data too short for cipher suites")
            return None
        cipher_suites_length = struct.unpack('>H', data[offset:offset+2])[0]
        print(f"Cipher suites length: {cipher_suites_length}")
        offset += 2 + cipher_suites_length
        
        # 9. 跳过Compression Methods
        if len(data) < offset + 1:
            print("Data too short for compression methods")
            return None
        compression_methods_length = data[offset]
        print(f"Compression methods length: {compression_methods_length}")
        offset += 1 + compression_methods_length
        
        # 10. 解析扩展
        if len(data) < offset + 2:
            print("Data too short for extensions length")
            return None
        extensions_length = struct.unpack('>H', data[offset:offset+2])[0]
        print(f"Extensions length: {extensions_length}")
        offset += 2
        extensions_end = offset + extensions_length
        
        # 11. 遍历所有扩展
        while offset < extensions_end:
            if len(data) < offset + 4:
                print("Data too short for extension header")
                return None
                
            extension_type = struct.unpack('>H', data[offset:offset+2])[0]
            extension_length = struct.unpack('>H', data[offset+2:offset+4])[0]
            print(f"Extension type: {extension_type}, length: {extension_length}")
            offset += 4
            
            if extension_type == 0:  # SNI extension
                if len(data) < offset + 2:
                    print("Data too short for SNI list length")
                    return None
                    
                sni_list_length = struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
                
                if len(data) < offset + 1:
                    print("Data too short for name type")
                    return None
                    
                name_type = data[offset]
                if name_type == 0:  # host_name
                    if len(data) < offset + 3:
                        print("Data too short for hostname length")
                        return None
                        
                    name_length = struct.unpack('>H', data[offset+1:offset+3])[0]
                    if len(data) < offset + 3 + name_length:
                        print("Data too short for hostname")
                        return None
                        
                    server_name = data[offset+3:offset+3+name_length].decode('utf-8')
                    print(f"Found SNI: {server_name}")
                    return server_name
                    
            offset += extension_length
            
        print("No SNI extension found")
        return None
        
    except Exception as e:
        print(f"Error parsing SNI: {e}")
        traceback.print_exc()
        return None

# 转发函数
def forward(source, destination, enable_logging):
    while True:
        try:
            readable, _, _ = select.select([source], [], [], 1)
            if readable:
                data = source.recv(4096)
                if not data:
                    break
                
                # 检查是否是HTTP请求
                if data.startswith(b'GET') or data.startswith(b'POST') or data.startswith(b'HEAD') or data.startswith(b'PUT') or data.startswith(b'DELETE') or data.startswith(b'OPTIONS'):
                    url = parse_http_request(data)
                    if url:
                        logging.info(f"HTTP request URL: {url}")
                
                # 检查是否是HTTPS请求
                elif data.startswith(b'CONNECT'):
                    # 对于CONNECT方法，不解析URL，直接转发
                    destination.sendall(data)
                    if enable_logging:
                        logging.info(f"Forwarded CONNECT request to {destination.getpeername()}")
                    continue
                
                # 检查是否是TLS Client Hello消息
                elif data.startswith(b'\x16\x03'):
                    sni = parse_sni(data)
                    if sni:
                        logging.info(f"HTTPS request SNI: {sni}")
                    # else:
                    #     logging.info(f"HTTPS request SNI: None")
                
                destination.sendall(data)
                if enable_logging:
                    print(f"Forwarded data to {destination.getpeername()}")
        except socket.error as e:
            if e.errno == 10038:
                print("Socket operation on non-socket")
                break
            else:
                print(f"Connection error: {e}")
                break

# 处理单个客户端连接
def handle_client(client_socket, target_host, target_port, enable_logging):
    try:
        # 连接到目标地址
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((target_host, target_port))
        
        if enable_logging:
            logging.info(f"Connected to target {target_host}:{target_port}")

        # 创建两个线程：分别转发客户端到目标和目标到客户端的数据
        threading.Thread(target=forward, args=(client_socket, target_socket, enable_logging)).start()
        threading.Thread(target=forward, args=(target_socket, client_socket, enable_logging)).start()
    except Exception as e:
        print(f"Error handling client: {e}")
        client_socket.close()

# 主端口转发逻辑
def start_port_forwarding(local_host, local_port, target_host, target_port, enable_logging):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((local_host, local_port))
    server.listen(15)
    print(f"[*] Listening on {local_host}:{local_port} and forwarding to {target_host}:{target_port}")
    
    if enable_logging:
        logging.info(f"Started port forwarding from {local_host}:{local_port} to {target_host}:{target_port}")

    while True:
        client_socket, addr = server.accept()
        print(f"[*] Accepted connection from {addr}")
        if enable_logging:
            logging.info(f"Accepted connection from {addr}")
        threading.Thread(target=handle_client, args=(client_socket, target_host, target_port, enable_logging)).start()

if __name__ == "__main__":
    # 配置端口转发信息
    LOCAL_HOST = "0.0.0.0"  # 本地监听地址
    LOCAL_PORT = 8998       # 本地监听端口
    TARGET_HOST = "127.0.0.1"  # 目标地址（替换为实际地址）
    TARGET_PORT = 10809     # 目标端口
    ENABLE_LOGGING = True   # 是否启用日志记录

    # 初始化日志
    if ENABLE_LOGGING:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            handlers=[
                logging.FileHandler('proxy.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
    else:
        logging.disable(logging.CRITICAL)

    # 启动端口转发
    start_port_forwarding(LOCAL_HOST, LOCAL_PORT, TARGET_HOST, TARGET_PORT, ENABLE_LOGGING)
