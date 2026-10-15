# experiment note

## environment 
- Ubuntu 22.04 ARM64 from Parallels
- upgrade kernel version from 5.15.0-194-generic to 6.8.0-138-generic(https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md), since linux 5.18 introduces BPF_FUNC_ima_file_hash(), which allows us to calculate hash value.

## why and current problem
- current Agentsight could monitor which files that agent touched(read, write), and also the way they open it, but can not know if the agent actually changes it.
- Agentsight does not record the content before and after, so through Agentsight, we can not know what the file looks like before and after.
- we need to have a tool to know which file the agent edit and version.(Since we record hash)
- so we need to extent Agentsight's eBPF observer of the kernel to monitor if the file touched by agent by recording SHA-256 Hash before its first modification and after its last write.
- why only hash not full contend: no sensitive data leaking, small storage (32 bytes) , could check with git or sha256sum.

## key point - the moment
- calculate sha256hash before agent changes the file, we should catch the moment when the file is opened and before the agent get it.
- if calculate sha256hash after receiving the 'open' notification, it might already get modificated by agent.
- We can only do it in kernel.

## key point - how to get hash
- it's impossible to calculate it using eBPF (memory size limit and opt number), we can use the helper function bpf_ima_file_hash(introduced in 5.18) in IMA module(submodule of kernel)

## key point - where to hook
- bpf_ima_file_hash() needs to read file and sometimes needs to wait for disk, so it only can be called in sleepable hook.
- file_open is sleepable and just on time: just found the file, not delivered to agent yet, not get cleaned yet.

## feasibility test
- Q1: is it feasible to call bpf_ima_file_hash in file_open?
- Q2: is calculated hash from the file before editing, what about overwrite?
- Q3: can we calculate hash while it's read-only?
- Q4: when closing, can we calculate in the kernel?

## Original experiment design
- two hooks: one for before, one for after. lsm.s/file_open, lsm.s/file_release
- call bpf_ima_file_hash and print figure
- if file_release has loading error, automatically retrace to only open hook and only load file_open.
- monitor cat and tee command. cat -- most simple read-only cmd, tee -- for write (why not using simpler echo hello >> file? since bash would do >> itself, the pid which process opens the file can not be filtered independently. tee is a independent process, it can be filtered)
## Original experiment finding
- finding 0: my ubuntu 22.04 's kernel version is 5.15.0-194-generic.
