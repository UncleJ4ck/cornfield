rule atomic_arch_monero_drainer_qml {
    // run against DECOMPRESSED main.qml, not the ELF (the ELF compresses these)
    strings:
        $sweep = "createTransactionAllAsync"
        $addr  = "865BH8r1M2Ni6nckpNr357dqDYCC4VkoyeX7EReDmAkYWDnS646BgXeLmH8zcPr7ENbC9ZjzEXyD6ZDkYbfMjefx4aBZF8C"
        $gate  = "unlockedBalanceAll"
        $auto  = "commitTransactionAsync"
    condition:
        $addr and $sweep and $gate and $auto
}

rule atomic_arch_stage1_stealer {
    // matches the deps / js-digest Rust stealer ELF directly
    strings:
        $bpf   = "/cloud/scales/agent/../ebpf/scales.bpf.c"
        $mt    = "/api/mt/"
        $vault = "X-Vault-Token:"
        $gpg   = "--batch --no-tty --list-keys --with-colons --fingerprint"
    condition:
        uint32(0) == 0x464c457f and 2 of ($bpf, $mt, $vault, $gpg)
}
