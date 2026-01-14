# 实验五 安全相关编程实验（RUST）

## 一、实验目的

通过本实验，学习 Rust 在网络安全编程的应用，熟悉如何实现基础的 ICMP 网络攻击，理解网络攻击的危害。

## 二、实验内容

ICMP 差错攻击作为网络攻击的一种主流方式，它是通过利用 ICMP 协议在 TCP/IP 协议簇中的作用来实现攻击的。ICMP 差错攻击的两种主要方式：

### 1. ICMP Unreachable 攻击

攻击者发送大量的 ICMP Unreachable 消息给受害者计算机，导致其无法访问其他主机或网络服务。如果被利用，TCP 盲连接重置漏洞可能允许攻击者针对现有的 TCP 连接创建拒绝服务条件，从而导致会话过早终止。由此产生的会话终止将影响应用程序层，其影响的性质和严重程度取决于应用程序层协议。主要依赖的是网络服务或应用程序对 TCP 连接丢失的容忍度。

**攻击示例：**

Web 客户端（10.0.0.1，TCP 端口 3270）正在从 Web 服务器（192.168.0.1，TCP 端口 80）下载文件。如果两个端点的 TCP/IP 实现都易受攻击，则可以攻击其中任何一个，从而导致 TCP 连接中止。攻击者可以根据探测到的信息缩小端口攻击范围，加速攻击进程。假设客户端运行 Windows，其传出连接选择的端口号范围为 1024-4999，攻击工具就可以尝试使用这个范围的端口进行攻击。

### 2. ICMP Source Quench 攻击

攻击者发送大量的 ICMP Source Quench 消息给受害者计算机，使其服务中断或性能降低。如果主机按照 RFC 1122 处理 ICMP 消息，则依赖于长期 TCP 连接的任何网络服务或应用程序也会受到影响。对于 ICMP Source Quench 攻击，严重性将取决于 TCP 连接的吞吐量，该应用程序很可能会变得不可用。

**安全策略：**

RFC 规范不建议对接收到的 ICMP 错误消息进行任何类型的验证检查。但是也存在例外不听取 RFC 规范的建议，对 ICMP 错误消息进行验证检查。

对于 ICMP，当接收到未受保护的 ICMP 错误消息时，它是通过 ICMP 错误消息有效负载中包含的 SPI（安全参数索引）与相应的安全关联相匹配。然后，应用本地策略来确定是接受还是拒绝消息，以及如果接受将采取什么操作。例如，如果接收到 ICMP 目标不可达消息，则实现必须决定是对其进行操作、拒绝它，还是对其进行约束。

**本次实验目标：** 模拟 ICMP 差错攻击来完成 ICMP 目的端口不可达信息。

### 2.1 搭建 Linux 环境并配置 Rust 编译环境

相应 Linux 环境下配置 Rust 可以参考 [Rust 官网](https://rust-lang.org)。

以 CentOS 7 配置 Rust 环境为例：

#### 配置国内镜像源

因为服务器在国外，网速比较慢，可能无法安装成功。可以使用以下命令配置国内下载地址：

```bash
vim /etc/profile
```

在文件最后添加以下两行：

```bash
export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup
```

然后使环境配置立即生效：

```bash
source /etc/profile
```

#### 安装 Rust

使用以下命令通过网络安装：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

安装过程中需要输入 1、2、3 中的一个数字：
- 输入 `1` 表示默认安装
- 输入 `2` 表示自定制服务
- 输入 `3` 表示取消安装

安装完成后，使用以下命令使环境生效：

```bash
source $HOME/.cargo/env
```

### 2.2 代码编写

#### 开发环境

如果使用 VSCode 的话，推荐安装 `rust-analyzer` 插件。如果资源包国外下载网速慢，可以自行更换国内镜像源。

#### ICMP 差错报文原理

ICMP 的差错报文将收到的需要进行差错报告 IP 数据报的首部和数据字段的前 8 个字节提取出来，作为 ICMP 报文的数据字段。再加上响应的 ICMP 差错报告报文的前 8 个字节，就构成了 ICMP 差错报告报文。提取收到的数据报的数据字段的前 8 个字节是为了得到传输层的端口号（对于 TCP 和 UDP）以及传输层报文的发送序号（对于 TCP）。

#### 代码结构

代码部分主要分为五部分：

#### （1）校验和计算

校验和计算是依据二进制编码进行计算的，可以参考网络上众多例子，不做详细解释。

#### （2）创建 IP 报文

在 Rust 中推荐使用 `MutableIpv4Packet::new` 来创建，输入参数为一块内存。然后设置相应属性。

#### （3）创建 TCP 报文

推荐使用 `MutableTcpPacket::new` 来创建，输入参数为一块内存。然后设置相应属性。

#### （4）创建 ICMP 报文

推荐使用 `MutableIcmpPacket::new` 来创建，输入参数为一块内存。然后设置相应属性。

ICMP 目标不可达报文是由 `type` 和 `code` 字段共同决定的：
- 当 `type` 为 3 时就是不可达报文
- `code` 取值按攻击类型决定（参考相关文档）

#### （5）发送数据报文

使用套接字发送前面设置报文属性的内存即可。不过需要注意的是，Rust的所有权将导致前面报文设置内存的属性会保存在缓冲区，需要从缓冲区写回。可以参考Rust针对所有权的方法：切片与引用。

 

之后使用wireshark抓包就可以看到设置的对应攻击工具发送了设计好的ICMP差错报文。

 

 

**三、相关实验文件**

代码框架与部分代码：

 

// （1）校验和计算

fn in_chksum(addr: &[u16], len: usize) -> u16 {

​    // 相应校验和计算

​    ...

}

 

 

 

fn main() {

 

​    ...

 

​    // （2）IP报文创建及属性设置

​    let mut ip_buf = vec![0; IPHEADER];

​    let mut ip_header = MutableIpv4Packet::new(&mut ip_buf[..]).unwrap();

​    // fill IP Header 

​    ip_header.set_version();

​    ip_header.set_header_length();

​    let addr_slice: &[u16] = unsafe{

​          let ptr = ip_header.packet_mut().as_ptr() as *const u16;

​          slice::from_raw_parts(ptr, IPHEADER as usize)

​    };

​    let check_sum = in_chksum(addr_slice, IPHEADER as usize);

​    ip_header.set_checksum(check_sum);

​    ..

 

​    // （3）TCP报文创建及属性设置

​    let mut tcp_buf = vec![0; TCPHEADER];

​    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buf[..]).unwrap();

​    // fill Tcp Header 

​    tcp_header.set_source(targetport);

​    tcp_header.set_destination(peerport);

 

​    // 同样像ip一样计算check_sum

​    tcp_header.set_checksum(check_sum);

​    ..

 

​    // （4）ICMP创建及属性设置

​    let mut icmp_buf = vec![0; ICMPHEADER];

​    let mut icmp_header = MutableIcmpPacket::new(&mut icmp_buf[..]).unwrap();

​    // IcmpType和IcmpCode可以查看对应攻击示例的enum

​    icmp_header.set_icmp_type(IcmpType);

​    icmp_header.set_icmp_code(IcmpCode);

​    

​    // 同样像ip一样计算check_sum

​    tcp_header.set_checksum(check_sum);

 

 

​    // （5） 报文发送

​    // 把在缓冲区设置的报文属性写回， 以icmp为例

​    buffer[ipheader.. ipheader + ICMPHEADER as usize].copy_from_slice(&icmp_header.to_immutable().packet());

​    //.. 套接字发送