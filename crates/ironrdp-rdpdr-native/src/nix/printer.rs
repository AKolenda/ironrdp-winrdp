//! Printer redirection for Linux and macOS: the remote's print jobs land in
//! the local print system.
//!
//! The channel announces one virtual printer to the server (MS-RDPEPC). When
//! the user prints to it, the server-side PostScript driver renders the job and
//! pushes the bytes down as a create / write... / close sequence on that
//! device. The job is spooled to a file while it streams; on close it is
//! handed to `lp`, or written to a file in the user's downloads folder when
//! there is no printer to hand it to.
//!
//! Spool files live in a private (0700) directory created per spooler, under
//! `$XDG_RUNTIME_DIR` when it is set, so a document being printed is never
//! readable by, or redirectable through, another local account.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use ironrdp_pdu::PduResult;
use ironrdp_rdpdr::pdu::RdpdrPdu;
use ironrdp_rdpdr::pdu::efs::{
    DeviceCloseResponse, DeviceCreateResponse, DeviceIoRequest, DeviceIoResponse, DeviceWriteResponse, Information,
    NtStatus, PrinterIoRequest,
};
use ironrdp_svc::SvcMessage;
use nix::unistd::mkdtemp;
use tracing::{debug, info, warn};

/// Where a finished job goes.
#[derive(Debug, Clone)]
pub enum PrintTarget {
    /// The CUPS default destination (`lp` with no `-d`).
    DefaultPrinter,
    /// A named CUPS destination.
    Printer(String),
    /// A directory: each job becomes `Win RDP print <timestamp>.ps` inside it.
    Folder(PathBuf),
}

/// One job in flight: the server opened the printer and is writing.
#[derive(Debug)]
struct Job {
    spool: PathBuf,
    file: File,
    bytes: u64,
}

/// Print-job state for one virtual printer.
#[derive(Debug)]
pub struct PrinterSpooler {
    target: PrintTarget,
    /// Fallback when `lp` is missing or refuses the job.
    fallback_dir: PathBuf,
    /// Private directory holding the spool files, created with the first job
    /// and removed, with anything left in it, when the spooler is dropped.
    spool_dir: Option<PathBuf>,
    next_file_id: u32,
    jobs: HashMap<u32, Job>,
    /// Handles whose job was abandoned after an oversized write; a later close
    /// must not submit whatever was spooled before.
    poisoned: HashMap<u32, PathBuf>,
}

impl PrinterSpooler {
    pub fn new(target: PrintTarget) -> Self {
        Self {
            target,
            fallback_dir: default_fallback_dir(),
            spool_dir: None,
            next_file_id: 1,
            jobs: HashMap::new(),
            poisoned: HashMap::new(),
        }
    }

    #[cfg(test)]
    fn with_fallback_dir(mut self, dir: PathBuf) -> Self {
        self.fallback_dir = dir;
        self
    }

    pub fn handle(&mut self, req: PrinterIoRequest) -> PduResult<Vec<SvcMessage>> {
        match req {
            PrinterIoRequest::Create(create) => {
                let file_id = self.next_file_id;
                self.next_file_id = self.next_file_id.wrapping_add(1).max(1);
                let response = match self.create_spool_file(file_id) {
                    Ok((spool, file)) => {
                        debug!(file_id, ?spool, "Print job opened");
                        self.jobs.insert(file_id, Job { spool, file, bytes: 0 });
                        DeviceCreateResponse {
                            device_io_reply: DeviceIoResponse::new(create.device_io_request, NtStatus::SUCCESS),
                            file_id,
                            information: Information::FILE_OPENED,
                        }
                    }
                    Err(error) => {
                        warn!(%error, "Could not open a spool file for a print job");
                        DeviceCreateResponse {
                            device_io_reply: DeviceIoResponse::new(create.device_io_request, NtStatus::UNSUCCESSFUL),
                            file_id: 0,
                            information: Information::FILE_OPENED,
                        }
                    }
                };
                Ok(vec![SvcMessage::from(RdpdrPdu::DeviceCreateResponse(response))])
            }
            PrinterIoRequest::Write(write) => {
                let file_id = write.device_io_request.file_id;
                let length = u32::try_from(write.write_data.len()).unwrap_or(u32::MAX);
                let status = match self.jobs.get_mut(&file_id) {
                    Some(job) => match job.file.write_all(&write.write_data) {
                        Ok(()) => {
                            job.bytes = job.bytes.saturating_add(u64::from(length));
                            NtStatus::SUCCESS
                        }
                        Err(error) => {
                            warn!(%error, file_id, "Could not spool print data");
                            NtStatus::UNSUCCESSFUL
                        }
                    },
                    None => NtStatus::UNSUCCESSFUL,
                };
                Ok(vec![SvcMessage::from(RdpdrPdu::DeviceWriteResponse(
                    DeviceWriteResponse {
                        device_io_reply: DeviceIoResponse::new(write.device_io_request, status),
                        length,
                    },
                ))])
            }
            PrinterIoRequest::Close(close) => {
                let file_id = close.device_io_request.file_id;
                if let Some(spool) = self.poisoned.remove(&file_id) {
                    let _ = std::fs::remove_file(spool);
                } else if let Some(job) = self.jobs.remove(&file_id) {
                    drop(job.file);
                    self.submit(&job.spool, job.bytes);
                }
                Ok(vec![SvcMessage::from(RdpdrPdu::DeviceCloseResponse(
                    DeviceCloseResponse {
                        device_io_response: DeviceIoResponse::new(close.device_io_request, NtStatus::SUCCESS),
                    },
                ))])
            }
        }
    }

    /// Abandons the job behind an oversized write so a later close discards it.
    pub fn reject_write(&mut self, req: DeviceIoRequest) -> PduResult<Vec<SvcMessage>> {
        if let Some(job) = self.jobs.remove(&req.file_id) {
            warn!(
                file_id = req.file_id,
                "Print job abandoned: the server sent an oversized write"
            );
            self.poisoned.insert(req.file_id, job.spool);
        }
        Ok(vec![SvcMessage::from(RdpdrPdu::DeviceWriteResponse(
            DeviceWriteResponse {
                device_io_reply: DeviceIoResponse::new(req, NtStatus::UNSUCCESSFUL),
                length: 0,
            },
        ))])
    }

    /// Creates the spool file for a new job in this spooler's private directory.
    fn create_spool_file(&mut self, file_id: u32) -> std::io::Result<(PathBuf, File)> {
        let dir = match &mut self.spool_dir {
            Some(dir) => dir,
            slot @ None => {
                let dir = create_spool_dir(
                    std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
                    std::env::temp_dir(),
                )?;
                debug!(?dir, "Print spool directory created");
                slot.insert(dir)
            }
        };
        let spool = dir.join(format!("job-{file_id}.ps"));
        // `create_new` refuses anything already at the path, including a symbolic link.
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&spool)?;
        Ok((spool, file))
    }

    fn submit(&self, spool: &Path, bytes: u64) {
        if bytes == 0 {
            debug!(?spool, "Empty print job discarded");
            let _ = std::fs::remove_file(spool);
            return;
        }
        let mut command = Command::new("lp");
        match &self.target {
            PrintTarget::DefaultPrinter => {}
            PrintTarget::Printer(name) => {
                command.arg("-d").arg(name);
            }
            PrintTarget::Folder(dir) => {
                self.keep(spool, dir);
                return;
            }
        }
        command.arg("-t").arg("Win RDP print job").arg(spool);
        match command.output() {
            Ok(output) if output.status.success() => {
                info!(
                    bytes,
                    "Print job handed to lp: {}",
                    String::from_utf8_lossy(&output.stdout).trim()
                );
                let _ = std::fs::remove_file(spool);
            }
            Ok(output) => {
                warn!(
                    "lp refused the print job ({}); keeping it as a file instead",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
                self.keep(spool, &self.fallback_dir.clone());
            }
            Err(error) => {
                warn!(%error, "lp is not available; keeping the print job as a file instead");
                self.keep(spool, &self.fallback_dir.clone());
            }
        }
    }

    /// Moves the spooled job into `dir` under a readable name.
    fn keep(&self, spool: &Path, dir: &Path) {
        if let Err(error) = std::fs::create_dir_all(dir) {
            warn!(%error, ?dir, "Could not create the print output folder");
            return;
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut destination = dir.join(format!("Win RDP print {stamp}.ps"));
        let mut n = 1;
        while destination.exists() {
            destination = dir.join(format!("Win RDP print {stamp} ({n}).ps"));
            n += 1;
        }
        let moved = std::fs::rename(spool, &destination).or_else(|_| {
            // The spool directory is usually on another file system (tmpfs), so copy
            // into a file this call creates rather than into whatever is at the path.
            let mut saved = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&destination)?;
            std::io::copy(&mut File::open(spool)?, &mut saved)?;
            std::fs::remove_file(spool)
        });
        match moved {
            Ok(()) => info!(?destination, "Print job saved as a PostScript file"),
            Err(error) => warn!(%error, ?destination, "Could not save the print job"),
        }
    }
}

impl Drop for PrinterSpooler {
    fn drop(&mut self) {
        // Takes jobs still streaming, and any that could be neither printed nor saved, with it.
        if let Some(dir) = self.spool_dir.take()
            && let Err(error) = std::fs::remove_dir_all(&dir)
        {
            warn!(%error, ?dir, "Could not remove the print spool directory");
        }
    }
}

/// Creates a private (0700) spool directory with an unpredictable name.
///
/// `runtime_dir` (`$XDG_RUNTIME_DIR`) is preferred: it is private to the user and
/// cleared at logout. A relative value is ignored, as the XDG Base Directory
/// specification requires. `temp_dir` is the fallback; in a shared `/tmp`, the
/// `mkdtemp` name and mode are what keep other local accounts out.
fn create_spool_dir(runtime_dir: Option<PathBuf>, temp_dir: PathBuf) -> std::io::Result<PathBuf> {
    const TEMPLATE: &str = "winrdp-print-XXXXXX";

    if let Some(runtime_dir) = runtime_dir.filter(|dir| dir.is_absolute()) {
        match mkdtemp(&runtime_dir.join(TEMPLATE)) {
            Ok(dir) => return Ok(dir),
            Err(error) => warn!(%error, ?runtime_dir, "Could not create the print spool in the runtime directory"),
        }
    }
    Ok(mkdtemp(&temp_dir.join(TEMPLATE))?)
}

fn default_fallback_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let downloads = home.join("Downloads");
    if downloads.is_dir() { downloads } else { home }
}

impl PrintTarget {
    /// Parses the launcher's setting: `default`, `folder:<dir>`, or a CUPS destination name.
    pub fn parse(value: &str) -> Self {
        let value = value.trim();
        if value.is_empty() || value.eq_ignore_ascii_case("default") {
            Self::DefaultPrinter
        } else if let Some(dir) = value.strip_prefix("folder:") {
            Self::Folder(PathBuf::from(dir))
        } else {
            Self::Printer(value.to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_rdpdr::pdu::efs::{
        CreateDisposition, CreateOptions, DesiredAccess, DeviceCloseRequest, DeviceCreateRequest, DeviceWriteRequest,
        FileAttributes, MajorFunction, MinorFunction, SharedAccess,
    };

    use super::*;

    fn io(file_id: u32, major: MajorFunction) -> DeviceIoRequest {
        DeviceIoRequest {
            device_id: 7,
            file_id,
            completion_id: 1,
            major_function: major,
            minor_function: MinorFunction::IRP_MN_QUERY_DIRECTORY,
        }
    }

    #[test]
    fn a_job_streams_into_the_folder_target() {
        let dir = std::env::temp_dir().join(format!("winrdp-print-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut spooler = PrinterSpooler::new(PrintTarget::Folder(dir.clone())).with_fallback_dir(dir.clone());

        let create = spooler
            .handle(PrinterIoRequest::Create(DeviceCreateRequest {
                device_io_request: io(0, MajorFunction::Create),
                desired_access: DesiredAccess::empty(),
                allocation_size: 0,
                file_attributes: FileAttributes::empty(),
                shared_access: SharedAccess::empty(),
                create_disposition: CreateDisposition::FILE_OPEN,
                create_options: CreateOptions::empty(),
                path: String::new(),
            }))
            .expect("create");
        assert_eq!(create.len(), 1);
        let file_id = spooler.jobs.keys().copied().next().expect("one open job");

        for chunk in [&b"%!PS-Adobe-3.0\n"[..], b"showpage\n"] {
            spooler
                .handle(PrinterIoRequest::Write(DeviceWriteRequest {
                    device_io_request: io(file_id, MajorFunction::Write),
                    offset: 0,
                    write_data: chunk.to_vec(),
                }))
                .expect("write");
        }
        spooler
            .handle(PrinterIoRequest::Close(DeviceCloseRequest::decode(io(
                file_id,
                MajorFunction::Close,
            ))))
            .expect("close");

        let saved: Vec<_> = std::fs::read_dir(&dir).expect("dir").flatten().collect();
        assert_eq!(saved.len(), 1, "one job file");
        let content = std::fs::read_to_string(saved[0].path()).expect("content");
        assert_eq!(content, "%!PS-Adobe-3.0\nshowpage\n");
        assert!(spooler.jobs.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rejected_write_poisons_the_job_so_close_discards_it() {
        let dir = std::env::temp_dir().join(format!("winrdp-print-test-poison-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut spooler = PrinterSpooler::new(PrintTarget::Folder(dir.clone())).with_fallback_dir(dir.clone());
        spooler
            .handle(PrinterIoRequest::Create(DeviceCreateRequest {
                device_io_request: io(0, MajorFunction::Create),
                desired_access: DesiredAccess::empty(),
                allocation_size: 0,
                file_attributes: FileAttributes::empty(),
                shared_access: SharedAccess::empty(),
                create_disposition: CreateDisposition::FILE_OPEN,
                create_options: CreateOptions::empty(),
                path: String::new(),
            }))
            .expect("create");
        let file_id = spooler.jobs.keys().copied().next().expect("one open job");
        spooler.reject_write(io(file_id, MajorFunction::Write)).expect("reject");
        spooler
            .handle(PrinterIoRequest::Close(DeviceCloseRequest::decode(io(
                file_id,
                MajorFunction::Close,
            ))))
            .expect("close");
        assert!(
            !dir.exists() || std::fs::read_dir(&dir).expect("dir").next().is_none(),
            "nothing saved"
        );
    }

    /// Sends a create request; `true` when it opened a job.
    fn open_job(spooler: &mut PrinterSpooler) -> bool {
        let responses = spooler
            .handle(PrinterIoRequest::Create(DeviceCreateRequest {
                device_io_request: io(0, MajorFunction::Create),
                desired_access: DesiredAccess::empty(),
                allocation_size: 0,
                file_attributes: FileAttributes::empty(),
                shared_access: SharedAccess::empty(),
                create_disposition: CreateDisposition::FILE_OPEN,
                create_options: CreateOptions::empty(),
                path: String::new(),
            }))
            .expect("create");
        assert_eq!(responses.len(), 1);
        !spooler.jobs.is_empty()
    }

    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::symlink_metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn a_job_is_spooled_privately_and_the_directory_goes_with_the_spooler() {
        let out = mkdtemp(&std::env::temp_dir().join("winrdp-print-test-XXXXXX")).expect("scratch dir");
        let mut spooler = PrinterSpooler::new(PrintTarget::Folder(out.clone())).with_fallback_dir(out.clone());
        assert!(open_job(&mut spooler));

        let spool = spooler.jobs.values().next().expect("one open job").spool.clone();
        let dir = spooler.spool_dir.clone().expect("spool directory");
        assert_eq!(spool.parent(), Some(dir.as_path()));
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&spool), 0o600);
        let name = dir.file_name().and_then(|name| name.to_str()).expect("name");
        assert!(name.starts_with("winrdp-print-") && !name.ends_with("XXXXXX"), "{name}");

        drop(spooler);
        assert!(!dir.exists(), "the spool directory is removed with the spooler");
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn a_spool_file_is_never_opened_through_something_already_at_its_path() {
        let scratch = mkdtemp(&std::env::temp_dir().join("winrdp-print-test-XXXXXX")).expect("scratch dir");
        let victim = scratch.join("victim");
        std::fs::write(&victim, b"untouched").expect("victim");
        let dir = scratch.join("spool");
        std::fs::create_dir(&dir).expect("spool dir");
        std::os::unix::fs::symlink(&victim, dir.join("job-1.ps")).expect("symlink");

        let mut spooler = PrinterSpooler::new(PrintTarget::Folder(scratch.clone()));
        spooler.spool_dir = Some(dir.clone());
        assert!(!open_job(&mut spooler), "the create is refused");
        assert_eq!(std::fs::read(&victim).expect("victim"), b"untouched");

        drop(spooler);
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn the_spool_directory_prefers_an_absolute_runtime_dir() {
        let scratch = mkdtemp(&std::env::temp_dir().join("winrdp-print-test-XXXXXX")).expect("scratch dir");
        let runtime = scratch.join("runtime");
        let temp = scratch.join("temp");
        std::fs::create_dir(&runtime).expect("runtime");
        std::fs::create_dir(&temp).expect("temp");

        let dir = create_spool_dir(Some(runtime.clone()), temp.clone()).expect("runtime spool dir");
        assert_eq!(dir.parent(), Some(runtime.as_path()));
        assert_eq!(mode(&dir), 0o700);

        let dir = create_spool_dir(None, temp.clone()).expect("unset");
        assert_eq!(dir.parent(), Some(temp.as_path()));
        assert_eq!(mode(&dir), 0o700);

        let dir = create_spool_dir(Some(PathBuf::from("relative")), temp.clone()).expect("relative");
        assert_eq!(dir.parent(), Some(temp.as_path()));

        let dir = create_spool_dir(Some(scratch.join("missing")), temp.clone()).expect("missing");
        assert_eq!(dir.parent(), Some(temp.as_path()));

        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn targets_parse_from_the_launcher_setting() {
        assert!(matches!(PrintTarget::parse("default"), PrintTarget::DefaultPrinter));
        assert!(matches!(PrintTarget::parse(""), PrintTarget::DefaultPrinter));
        assert!(matches!(PrintTarget::parse("HP_LaserJet"), PrintTarget::Printer(n) if n == "HP_LaserJet"));
        assert!(matches!(PrintTarget::parse("folder:/tmp/out"), PrintTarget::Folder(p) if p == Path::new("/tmp/out")));
    }
}
