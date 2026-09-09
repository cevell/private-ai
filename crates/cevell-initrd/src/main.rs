use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

const DM_CONTROL_PATH: &str = "/dev/mapper/control";
const SYS_CONTROL_PATH: &str = "/sys/class/misc/device-mapper/dev";
const SYS_BLOCK_DIR: &str = "/sys/class/block";

const DM_VERSION_MAJOR: u32 = 4;
const DM_VERSION_MINOR: u32 = 0;
const DM_VERSION_PATCH: u32 = 0;

const DM_CMD_CREATE: u32 = 3;
const DM_CMD_SUSPEND: u32 = 6;
const DM_CMD_STATUS: u32 = 7;
const DM_CMD_TABLE: u32 = 9;

const DM_FLAG_READONLY: u32 = 1 << 0;
const DM_FLAG_EXISTS: u32 = 1 << 2;
const DM_IOCTL_MAGIC: u32 = 0xfd;
const DM_IOCTL_RW: u32 = 3;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DmIoctl {
    pub version_major: u32,
    pub version_minor: u32,
    pub version_patch: u32,
    pub data_size: u32,
    pub data_start: u32,
    pub target_count: u32,
    pub open_count: i32,
    pub flags: u32,
    pub event_nr: u32,
    pub padding: u32,
    pub dev: u64,
    pub name: [u8; 128],
    pub uuid: [u8; 129],
    pub data: [u8; 7],
}

const _: () = assert!(std::mem::size_of::<DmIoctl>() == 312);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DmTargetSpec {
    pub sector_start: u64,
    pub length: u64,
    pub status: i32,
    pub next: u32,
    pub target_type: [u8; 16],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct VeritySuperblock {
    pub magic: [u8; 8],
    pub version: u32,
    pub hash_type: u32,
    pub uuid: [u8; 16],
    pub algorithm: [u8; 32],
    pub data_block_size: u32,
    pub hash_block_size: u32,
    pub data_blocks: u64,
    pub salt_size: u16,
    pub pad: [u8; 6],
    pub salt: [u8; 256],
}

fn main() {
    let _ = mount_early_filesystems();
    initrd_log("Cevell OS Stage 1 Rust Initrd Engine initializing...");
    if let Err(e) = run_initrd() {
        initrd_log(&format!("FATAL initrd error: {}", e));
        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }
}

fn run_initrd() -> Result<(), String> {
    load_kernel_modules();

    let roothash = extract_cmdline_param("roothash")
        .ok_or_else(|| "Missing roothash= parameter on kernel command line".to_string())?
        .to_lowercase();

    if roothash.len() != 64 {
        return Err(format!("Invalid roothash length: {}", roothash.len()));
    }
    initrd_log(&format!("Enforcing immutable root hash: {}", roothash));

    let (data_dev, verity_dev) = discover_root_partitions()?;
    initrd_log(&format!("Discovered partitions: root={}, verity={}", data_dev, verity_dev));

    let sb = read_verity_superblock(&verity_dev)?;
    let data_dev_num = get_block_dev_number(&data_dev)?;
    let verity_dev_num = get_block_dev_number(&verity_dev)?;

    let sb_version = sb.version;
    let sb_data_block_size = sb.data_block_size;
    let sb_hash_block_size = sb.hash_block_size;
    let sb_data_blocks = sb.data_blocks;
    let sb_salt_size = sb.salt_size as usize;
    let sb_salt = sb.salt;
    let sb_algo = sb.algorithm;

    let salt_hex = hex_encode(&sb_salt[..sb_salt_size]);
    let salt_param = if salt_hex.is_empty() { "-" } else { &salt_hex };
    let algo = std::str::from_utf8(&sb_algo)
        .unwrap_or("sha256")
        .trim_matches('\0');
    let sectors = sb_data_blocks * (sb_data_block_size as u64 / 512);

    let params = format!(
        "{} {} {} {} {} {} 1 {} {} {}",
        sb_version, data_dev_num, verity_dev_num,
        sb_data_block_size, sb_hash_block_size, sb_data_blocks,
        algo, roothash, salt_param
    );

    initrd_log(&format!("Activating dm-verity device: length={} sectors", sectors));
    activate_dm_verity("root", sectors, &params)?;

    initrd_log("Mounting verified rootfs (/dev/mapper/root -> /sysroot)...");
    fs::create_dir_all("/sysroot").map_err(|e| e.to_string())?;
    unsafe {
        let dev = CString::new("/dev/mapper/root").unwrap();
        let target = CString::new("/sysroot").unwrap();
        let fstype = CString::new("ext4").unwrap();
        let ret = libc::mount(
            dev.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            std::ptr::null(),
        );
        if ret != 0 {
            return Err(format!("mount ext4 failed with errno: {}", std::io::Error::last_os_error()));
        }
    }

    initrd_log("Handing over execution to node supervisor (/usr/bin/cevell-node)...");
    handoff_to_verified_root("/sysroot", "/usr/bin/cevell-node")
}

fn mount_early_filesystems() -> Result<(), String> {
    let mounts = [
        ("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, Some("mode=0755")),
        ("proc", "/proc", "proc", libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None),
        ("sysfs", "/sys", "sysfs", libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, None),
        ("tmpfs", "/run", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV, Some("mode=0755")),
    ];

    for (dev, target, fstype, flags, opts) in mounts {
        let _ = fs::create_dir_all(target);
        let c_dev = CString::new(dev).unwrap();
        let c_target = CString::new(target).unwrap();
        let c_fstype = CString::new(fstype).unwrap();
        let c_opts = opts.map(|o| CString::new(o).unwrap());
        let opts_ptr = match &c_opts {
            Some(o) => o.as_ptr() as *const libc::c_void,
            None => std::ptr::null(),
        };

        unsafe {
            let ret = libc::mount(c_dev.as_ptr(), c_target.as_ptr(), c_fstype.as_ptr(), flags, opts_ptr);
            if ret != 0 {
                return Err(format!("Failed to mount {}: {}", target, std::io::Error::last_os_error()));
            }
        }
    }
    Ok(())
}

fn load_kernel_modules() {
    if let Ok(entries) = fs::read_dir("/lib/modules") {
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map_or(false, |ext| ext == "ko" || ext == "zst"))
            .collect();
        paths.sort();

        for p in paths {
            if let Ok(mut f) = File::open(&p) {
                let mut buf = Vec::new();
                if f.read_to_end(&mut buf).is_ok() {
                    let null_args = CString::new("").unwrap();
                    let ret = unsafe {
                        libc::syscall(libc::SYS_init_module, buf.as_ptr(), buf.len(), null_args.as_ptr())
                    };
                    if ret == 0 {
                        initrd_log(&format!("Loaded driver: {}", p.file_name().unwrap().to_string_lossy()));
                    }
                }
            }
        }
    }
}

fn extract_cmdline_param(name: &str) -> Option<String> {
    let content = fs::read_to_string("/proc/cmdline").ok()?;
    for token in content.split_whitespace() {
        if let Some(val) = token.strip_prefix(&format!("{}=", name)) {
            return Some(val.to_string());
        }
    }
    None
}

fn discover_root_partitions() -> Result<(String, String), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let mut disks = Vec::new();
        if let Ok(entries) = fs::read_dir("/sys/block") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("nvme") || name.starts_with("vd") || name.starts_with("sd") {
                    disks.push(entry.path());
                }
            }
        }
        disks.sort();

        for disk_dir in disks {
            let mut part_map = std::collections::BTreeMap::new();
            if let Ok(entries) = fs::read_dir(&disk_dir) {
                for entry in entries.flatten() {
                    let part_file = entry.path().join("partition");
                    if part_file.exists() {
                        if let Ok(data) = fs::read_to_string(&part_file) {
                            if let Ok(p_num) = data.trim().parse::<i32>() {
                                let dev_name = entry.file_name().to_string_lossy().to_string();
                                part_map.insert(p_num, format!("/dev/{}", dev_name));
                            }
                        }
                    }
                }
            }

            // UEFI 3-partition layout: p1=ESP, p2=root, p3=verity
            if part_map.len() >= 3 {
                if let (Some(r), Some(v)) = (part_map.get(&2), part_map.get(&3)) {
                    return Ok((r.clone(), v.clone()));
                }
            }
            // Fallback 2-partition layout: p1=root, p2=verity
            if let (Some(r), Some(v)) = (part_map.get(&1), part_map.get(&2)) {
                return Ok((r.clone(), v.clone()));
            }
        }
        thread::sleep(Duration::from_millis(150));
    }
    Err("Timed out discovering root partitions".to_string())
}

fn read_verity_superblock(dev_path: &str) -> Result<VeritySuperblock, String> {
    let mut file = File::open(dev_path).map_err(|e| format!("open {}: {}", dev_path, e))?;
    let mut buf = [0u8; 512];
    file.read_exact(&mut buf).map_err(|e| format!("read sb: {}", e))?;

    if &buf[0..8] != b"verity\0\0" {
        return Err("Invalid dm-verity magic header on hash partition".to_string());
    }

    let sb = unsafe { std::ptr::read(buf.as_ptr() as *const VeritySuperblock) };
    let salt_size = sb.salt_size;
    if salt_size > 256 {
        return Err(format!("Unsupported salt size: {}", salt_size));
    }
    Ok(sb)
}

fn get_block_dev_number(path: &str) -> Result<String, String> {
    let name = path.trim_start_matches("/dev/");
    let sys_path = format!("{}/{}/dev", SYS_BLOCK_DIR, name);
    fs::read_to_string(&sys_path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("read {}: {}", sys_path, e))
}

fn activate_dm_verity(name: &str, sectors: u64, params: &str) -> Result<(), String> {
    let _ = fs::create_dir_all("/dev/mapper");
    if let Ok(dev_str) = fs::read_to_string(SYS_CONTROL_PATH) {
        let parts: Vec<&str> = dev_str.trim().split(':').collect();
        if parts.len() == 2 {
            if let (Ok(maj), Ok(min)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                let dev_id = libc::makedev(maj, min);
                let c_path = CString::new(DM_CONTROL_PATH).unwrap();
                unsafe {
                    libc::mknod(c_path.as_ptr(), libc::S_IFCHR | 0o600, dev_id);
                }
            }
        }
    }

    let control = OpenOptions::new()
        .read(true)
        .write(true)
        .open(DM_CONTROL_PATH)
        .map_err(|e| format!("open dm-control: {}", e))?;

    use std::os::unix::io::AsRawFd;
    let fd = control.as_raw_fd();

    // 1. Create mapping
    let mut create_hdr = new_dm_ioctl_header(name, DM_FLAG_READONLY | DM_FLAG_EXISTS);
    send_dm_ioctl(fd, DM_CMD_CREATE, &mut create_hdr, &[])?;

    // 2. Load verity table
    let mut spec = DmTargetSpec {
        sector_start: 0,
        length: sectors,
        status: 0,
        next: 0,
        target_type: [0; 16],
    };
    let target_type = b"verity";
    spec.target_type[..target_type.len()].copy_from_slice(target_type);

    let target_size = ((std::mem::size_of::<DmTargetSpec>() + params.len() + 1 + 7) & !7) as u32;
    spec.next = target_size;

    let mut spec_bytes = vec![0u8; std::mem::size_of::<DmTargetSpec>()];
    unsafe {
        std::ptr::copy_nonoverlapping(
            &spec as *const DmTargetSpec as *const u8,
            spec_bytes.as_mut_ptr(),
            spec_bytes.len(),
        );
    }

    let mut payload = spec_bytes;
    payload.extend_from_slice(params.as_bytes());
    payload.push(0);
    while payload.len() % 8 != 0 {
        payload.push(0);
    }

    let mut table_hdr = new_dm_ioctl_header(name, DM_FLAG_READONLY | DM_FLAG_EXISTS);
    table_hdr.target_count = 1;
    send_dm_ioctl(fd, DM_CMD_TABLE, &mut table_hdr, &payload)?;

    // 3. Resume / activate table
    let mut resume_hdr = new_dm_ioctl_header(name, DM_FLAG_READONLY | DM_FLAG_EXISTS);
    send_dm_ioctl(fd, DM_CMD_SUSPEND, &mut resume_hdr, &[])?;

    // 4. Status query to ensure block node
    let mut status_hdr = new_dm_ioctl_header(name, DM_FLAG_EXISTS);
    send_dm_ioctl(fd, DM_CMD_STATUS, &mut status_hdr, &[])?;

    let node_path = format!("/dev/mapper/{}", name);
    let _ = fs::remove_file(&node_path);
    let c_node = CString::new(node_path).unwrap();
    unsafe {
        let ret = libc::mknod(c_node.as_ptr(), libc::S_IFBLK | 0o600, status_hdr.dev);
        if ret != 0 {
            return Err(format!("mknod failed: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

fn new_dm_ioctl_header(name: &str, flags: u32) -> DmIoctl {
    let mut h = DmIoctl {
        version_major: DM_VERSION_MAJOR,
        version_minor: DM_VERSION_MINOR,
        version_patch: DM_VERSION_PATCH,
        data_size: std::mem::size_of::<DmIoctl>() as u32,
        data_start: std::mem::size_of::<DmIoctl>() as u32,
        target_count: 0,
        open_count: 0,
        flags,
        event_nr: 0,
        padding: 0,
        dev: 0,
        name: [0; 128],
        uuid: [0; 129],
        data: [0; 7],
    };
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(127);
    h.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    h
}

fn send_dm_ioctl(fd: i32, cmd: u32, header: &mut DmIoctl, payload: &[u8]) -> Result<(), String> {
    let hdr_size = std::mem::size_of::<DmIoctl>();
    let total_size = hdr_size + payload.len();
    header.data_size = total_size as u32;

    let mut buf = vec![0u8; total_size];
    unsafe {
        std::ptr::copy_nonoverlapping(
            header as *const DmIoctl as *const u8,
            buf.as_mut_ptr(),
            hdr_size,
        );
    }
    if !payload.is_empty() {
        buf[hdr_size..].copy_from_slice(payload);
    }

    let req = ((DM_IOCTL_RW << 30) | (total_size as u32) << 16 | (DM_IOCTL_MAGIC << 8) | cmd) as _;
    let ret = unsafe { libc::ioctl(fd, req, buf.as_mut_ptr()) };
    if ret < 0 {
        return Err(format!("dm ioctl cmd {} failed: {}", cmd, std::io::Error::last_os_error()));
    }

    unsafe {
        std::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            header as *mut DmIoctl as *mut u8,
            hdr_size,
        );
    }
    Ok(())
}

fn handoff_to_verified_root(target_root: &str, init_bin: &str) -> Result<(), String> {
    // Make / recursively private so MS_MOVE is allowed by Linux VFS
    unsafe {
        let c_empty = CString::new("").unwrap();
        let c_slash = CString::new("/").unwrap();
        let _ = libc::mount(
            c_empty.as_ptr(),
            c_slash.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        );
    }

    for mnt in &["dev", "proc", "sys", "run"] {
        let src = format!("/{}", mnt);
        let dst = format!("{}/{}", target_root, mnt);
        let _ = fs::create_dir_all(&dst);
        let c_src = CString::new(src).unwrap();
        let c_dst = CString::new(dst).unwrap();
        unsafe {
            let _ = libc::mount(c_src.as_ptr(), c_dst.as_ptr(), std::ptr::null(), libc::MS_MOVE, std::ptr::null());
        }
    }

    let c_target = CString::new(target_root).unwrap();
    let c_root = CString::new("/").unwrap();
    let c_dot = CString::new(".").unwrap();
    let c_init = CString::new(init_bin).unwrap();

    unsafe {
        if libc::chdir(c_target.as_ptr()) != 0 {
            return Err("chdir target_root failed".to_string());
        }
        // In Linux VFS, MS_MOVE of a mount directly onto rootfs ("/") is not permitted and returns EINVAL.
        // We attempt MS_MOVE best-effort, but proceed with chroot/chdir which switches root cleanly.
        let _ = libc::mount(c_target.as_ptr(), c_root.as_ptr(), std::ptr::null(), libc::MS_MOVE, std::ptr::null());
        if libc::chroot(c_dot.as_ptr()) != 0 {
            return Err("chroot failed".to_string());
        }
        if libc::chdir(c_root.as_ptr()) != 0 {
            return Err("chdir / failed".to_string());
        }

        let argv = [c_init.as_ptr(), std::ptr::null()];
        let path_env = CString::new("PATH=/usr/bin:/usr/sbin:/bin:/sbin").unwrap();
        let home_env = CString::new("HOME=/root").unwrap();
        let envp = [path_env.as_ptr(), home_env.as_ptr(), std::ptr::null()];
        libc::execve(c_init.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }
    Err("execve failed to execute init".to_string())
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn is_debug_active() -> bool {
    if let Some(debug) = extract_cmdline_param("debug") {
        return debug == "on" || debug == "1" || debug == "true";
    }
    false
}

fn initrd_log(msg: &str) {
    if !is_debug_active() {
        return;
    }
    println!("cevell-initrd: {}", msg);
    for p in &["/dev/kmsg", "/dev/ttyS0", "/dev/console"] {
        if let Ok(mut f) = OpenOptions::new().write(true).open(p) {
            if *p == "/dev/kmsg" {
                let _ = writeln!(f, "<6>cevell-initrd: {}", msg);
            } else {
                let _ = writeln!(f, "cevell-initrd: {}", msg);
            }
        }
    }
}
