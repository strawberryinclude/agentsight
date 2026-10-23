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
- print enough information: mode(r/w), size(file size when running hook, to check if file gets empty), ino(inode), path, error code.
  
## Original experiment finding
- finding 0: my ubuntu 22.04 's kernel version is 5.15.0-194-generic. bpf_ima_file_hash() is introduced in 5.18. the kernel needs to be upgraded.
- finding 1: file_open in read-only situaction is not recorded:
 <img width="1008" height="1194" alt="image" src="https://github.com/user-attachments/assets/923d94c1-52e9-4edb-87ee-8825d4b4a0d6" />
there should be 2 open-file record( one from cat, one from bash(echo)), but only one in the record. we need to check if it catches the read-only file open, maybe it is got dropped when analysing in user layer.
-terminal 1: cd ~/agentsight
sudo ./collector/target/release/agentsight debug process | grep test.txt
-terminal 2: cat /tmp/test.txt
<img width="1290" height="404" alt="image" src="https://github.com/user-attachments/assets/51473cb9-74b9-431e-aa83-6fcb68d40b39" />
The last record shows that it catches the read-only file open.
it provides (dev, ino) in every open, so I only need to add hash in current file open hook.
- finding 2: check the availability of bpf_ima_file_hash
  <img width="1248" height="288" alt="image" src="https://github.com/user-attachments/assets/df4940f2-30d2-40c4-928f-034d1c7c396b" />
  CONFIG_BPF_LSM=y, CONFIG_IMA_DEFAULT_HASH="sha256"
- terminal 1: cd ~/agentsight
sudo ./bpf/imaprobe
-terminal 2: echo hello > /tmp/test.txt   
sha256sum /tmp/test.txt                  # A: original content 
cat /tmp/test.txt                        
echo more | tee -a /tmp/test.txt     
sha256sum /tmp/test.txt                  # B: after append
echo reset | tee /tmp/test.txt       
sha256sum /tmp/test.txt                  # C: after rewrite
expectations:
opt               open hash     release hash
cat(read-only)     A               A
tee -a(append)     A               B
tee(rewrite)       B               C
terminal 1:
<img width="912" height="378" alt="image" src="https://github.com/user-attachments/assets/27e22521-b70a-4b20-9f19-2fd6e61890db" />
terminal 2:
<img width="840" height="1442" alt="image" src="https://github.com/user-attachments/assets/5555500f-6211-430e-81e2-5ee93061edc8" />
<img width="926" height="966" alt="image" src="https://github.com/user-attachments/assets/e1ae6379-ebd3-4947-8fe2-63949ef6d4bd" />
<img width="536" height="915" alt="截屏2026-10-15 17 21 12" src="https://github.com/user-attachments/assets/cd1ad393-771c-4a24-9414-c37787f620c0" />
<img width="904" height="178" alt="image" src="https://github.com/user-attachments/assets/1cd4e7c7-ee77-49ff-ac80-52b4b36f3468" />
<img width="526" height="184" alt="截屏2026-10-15 17 22 39" src="https://github.com/user-attachments/assets/a9043f5b-3f8d-46c0-882d-0d918a2792ff" />

read-only hash error -95
tee hash success: 6052eef1a76d3....
### before a-write:
OPEN  pid=4835  comm=tee  mode=-w  ino=3670022  size=6  path=/tmp/test.txt
      hash: 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03 (algo 4)
OPEN  pid=4835  comm=tee  mode=r-  ino=3670022  size=6  path=/tmp/test.txt
      hash: error -95 (Operation not supported)
### before overwrite:
OPEN  pid=4824  comm=tee  mode=-w  ino=3670022  size=11  path=/tmp/test.txt
      hash: 6052eef1a76d3ff777269e8a1720524953b74c4d96e4689679c8982699a32beb (algo 4)
OPEN  pid=4824  comm=tee  mode=r-  ino=3670022  size=11  path=/tmp/test.txt
      hash: error -95 (Operation not supported)
      
## imaprobe code -- 3 parts
- imaprobe.bpf.c: kernel. two hooks, after filtering, call bpf_ima_file_hash, put the figure to ring buffer
if Not File return;          // 过滤目录、设备等
if (pid != cat or tee) return; // 过滤无关进程
e = bpf_ringbuf_reserve(...);       // 在 ring buffer 里占一个位置
input pid, mode, size, incode
bpf_d_path(...)                     // 取路径
bpf_ima_file_hash(file, e->hash, ...) // key: hash
bpf_ringbuf_submit(e, 0);           // 发给用户态
- imaprobe.c: user.loader: load code to kernel, solve with loading error, get figure from ring buffer and print.
- imaprobe.h: both. define record event form.

### Finding 1: file_open sees the content before modification, even with O_TRUNC
- Append (tee -a, O_WRONLY|O_APPEND): kernel hash = A (5891b5b5...), size=6
  -> content before "more" was appended
- Overwrite (tee, O_WRONLY|O_TRUNC): kernel hash = B (6052eef1...), size=11
  -> content before truncation; if the hook ran after truncation we would see
     size=0 and the empty-file hash e3b0c442...
- Why: in do_open(), vfs_open() (which calls the file_open LSM hook) runs
  before handle_truncate()
- Meaning: the pre-modification hash can be measured race-free in the kernel.
  User space could never do this for O_TRUNC: the old content is gone as soon
  as open() returns.
  





