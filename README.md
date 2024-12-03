# forward

### 简介

该程序实现了一个端口转发工具，主要功能是将本地监听的端口流量转发到指定的目标地址和端口。程序支持HTTP、HTTPS（TLS）请求的解析，并能够提取HTTP请求的URL和TLS Client Hello消息中的SNI（Server Name Indication）信息。以下是程序的主要功能和流程：

1. **日志初始化**：
   - 根据配置决定是否启用日志记录，日志可以输出到文件和控制台。

2. **HTTP请求解析**：
   - 解析HTTP请求的第一行，提取请求的URL。

3. **TLS Client Hello解析**：
   - 解析TLS Client Hello消息，提取其中的SNI信息。

4. **数据转发**：
   - 使用`select`模块监听客户端和服务器端的套接字，将数据双向转发。
   - 对于HTTP请求，提取并记录请求的URL。
   - 对于HTTPS请求，提取并记录SNI信息。

5. **客户端连接处理**：
   - 接受客户端连接后，创建两个线程分别负责将客户端数据转发到目标服务器，以及将目标服务器数据转发回客户端。

6. **端口转发启动**：
   - 绑定本地地址和端口，开始监听客户端连接，并将连接转发到指定的目标地址和端口。

### Introduction

This program implements a port forwarding tool that forwards traffic from a local listening port to a specified target address and port. It supports parsing of HTTP and HTTPS (TLS) requests, and can extract the URL from HTTP requests and the SNI (Server Name Indication) from TLS Client Hello messages. Here are the main functions and workflow of the program:

1. **Logging Initialization**:
   - Determines whether to enable logging based on configuration. Logs can be output to a file and the console.

2. **HTTP Request Parsing**:
   - Parses the first line of an HTTP request to extract the requested URL.

3. **TLS Client Hello Parsing**:
   - Parses the TLS Client Hello message to extract the SNI information.

4. **Data Forwarding**:
   - Uses the `select` module to monitor sockets for both the client and server, forwarding data bidirectionally.
   - For HTTP requests, extracts and logs the requested URL.
   - For HTTPS requests, extracts and logs the SNI information.

5. **Client Connection Handling**:
   - Accepts client connections and creates two threads to handle forwarding data from the client to the target server and from the target server back to the client.

6. **Port Forwarding Startup**:
   - Binds to the local address and port, starts listening for client connections, and forwards the connections to the specified target address and port.
