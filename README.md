# kindling-ebpf-demo

## 编译

### 编译环境安装
 ``` 
yum install -y centos-release-scl
yum -y install yum-utils
yum-config-manager --enable rhel-server-rhscl-7-rpms
yum install -y libstdc++-static patch elfutils-libelf-devel
yum install -y  glibc-static
yum install -y llvm-toolset-7.0 devtoolset-8-gcc devtoolset-8-gcc-c++ devtoolset-8-binutils

....  golang如果无法用yum，则自己安装  ....
yum install -y epel-release
yum install -y golang
 ``` 

### 开始编译
#### 前提条件
 ``` 
安装内核头文件 kernel-devel-******
 ``` 

#### 编译ebpf模块
 ``` 
cd driver
make
 ``` 
#### 编译go
 ``` 
cp libkindling.so /usr/lib64/
cd ..
go build
 ``` 

## 运行
 ``` 
export SYSDIG_BPF_PROBE=./driver/bpf/probe.o
./kindling-ebpf-demo
 ``` 
