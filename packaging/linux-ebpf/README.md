# Aegis Linux eBPF Assets

本目录保存 Aegis Linux 平台的真实 eBPF 资产与构建脚本。

## 目录布局

- `manifest.json`：运行时资产清单
- `src/`：eBPF C 源码
- `build.sh`：在 Linux 主机上生成 `vmlinux.h` 并编译 `.bpf.o`
- `*.bpf.o`：提交入仓的编译产物

## 依赖

需要在 Linux 主机上安装：

- `bpftool`
- `clang`
- `llvm`
- `libbpf-dev`

另外，若要让 `file.bpf.o` 和 `network.bpf.o` 中的 `LSM` 程序真正生效，内核必须在活动 LSM 顺序中包含 `bpf`。
当前仓库默认验证约定为：

```bash
cat /sys/kernel/security/lsm
# 期望包含 bpf
```

若测试机未启用 `bpf` LSM，需要通过 GRUB 内核参数启用，例如：

```bash
GRUB_CMDLINE_LINUX="lsm=lockdown,capability,bpf,landlock,yama,apparmor,ima,evm"
sudo update-grub
sudo reboot
```

## 构建

```bash
cd packaging/linux-ebpf
./build.sh
```

构建脚本会：

1. 从 `/sys/kernel/btf/vmlinux` 生成 `build/include/vmlinux.h`
2. 编译 `process.bpf.c`、`file.bpf.c`、`network.bpf.c`
3. 将产物写回当前目录

## 装载约定

- 所有 bundle 使用 `bpftool prog loadall ... autoattach`
- 文件与网络 bundle 会额外使用 `pinmaps`
- `bpftool` autoattach 在当前 Ubuntu 24.04 测试机上会把 link 直接 pin 到 bundle pin 目录

## 验证目标

- `process.bpf.o`：`tracepoint` + `kprobe`
- `file.bpf.o`：`LSM` 执行阻断与文件保护
- `network.bpf.o`：`tracepoint` + `kprobe` + `LSM` 网络阻断
