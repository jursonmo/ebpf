#!/usr/bin/env bash

# Version of libbpf to fetch headers from
LIBBPF_VERSION=1.4.7

# The headers we want
prefix=libbpf-"$LIBBPF_VERSION"
headers=(
    "$prefix"/LICENSE.BSD-2-Clause
    "$prefix"/src/bpf_endian.h
    "$prefix"/src/bpf_helper_defs.h
    "$prefix"/src/bpf_helpers.h
    "$prefix"/src/bpf_tracing.h
)

#下载（curl）指定版本的 libbpf 源码压缩包，并只解压我们需要的头文件到当前目录（tar 的 --xform 选项用来把路径裁剪掉，只保留文件名），这样我们获得了与 libbpf 版本完全匹配的头文件。
# Fetch libbpf release and extract the desired headers
curl -sL "https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz" | \
    tar -xz --xform='s#.*/##' "${headers[@]}"
