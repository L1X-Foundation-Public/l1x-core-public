### Description

**VM parts**
- `vm/vm/l1x-ebpf-runtime` - eBPF runtime
- `vm/vm/l1x-rbpf` - eBPF machine. Based on https://github.com/qmonnet/rbpf
- `vm/vm/l1x-vm-cli` - a tool to run a contract in VM out of the blockchain. It has limited Blockchain environment emulation.
- `vm/vm/vm-execution-fee` - execution fee config
- `vm/vm/vm-outcome` - VM return types

### How to build VM

```bash
cd vm
cargo build -p l1x-vm-cli
```

### How to run a contract

```bash
./vm/target/debug/l1x-vm-cli run l1x-sdk/target/wasm32-unknown-unknown/release/l1x_test_contract.o new
./vm/target/debug/l1x-vm-cli run l1x-sdk/target/wasm32-unknown-unknown/release/l1x_test_contract.o inc_counter
./vm/target/debug/l1x-vm-cli run l1x-sdk/target/wasm32-unknown-unknown/release/l1x_test_contract.o get_counter
```
