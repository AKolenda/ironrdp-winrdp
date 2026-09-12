//! Printer redirection for Linux and macOS: the remote's print jobs land in
//! the local print system.
//!
//! The channel announces one virtual printer to the server (MS-RDPEPC). When
//! the user prints to it, the server-side PostScript driver renders the job and
//! pushes the bytes down as a create / write... / close sequence on that
//! device. The job is spooled to a temporary file while it streams; on close
//! it is handed to `lp`, or written to a file in the user's downloads folder
//! when there is no printer to hand it to.

use std::collections::HashMap;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::path::{Path, PathBuf};
use std::process::Command;

use ironrdp_pdu::PduResult;
use ironrdp_rdpdr::pdu::RdpdrPdu;
use ironrdp_rdpdr::pdu::efs::{
    DeviceCloseResponse, DeviceCreateResponse, DeviceIoRequest, DeviceIoResponse, DeviceWriteResponse, Information,
    NtStatus, PrinterIoRequest,
};
use ironrdp_svc::SvcMessage;
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
    file: std::fs::File,
    bytes: u64,
}

/// Print-job state for one virtual printer.
#[derive(Debug)]
pub struct PrinterSpooler {
    target: PrintTarget,
    /// Fallback when `lp` is missing or refuses the job.
    fallback_dir: PathBuf,
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
                // Unique across every spooler in this process, not just this one.
                static SEQUENCE: AtomicU64 = AtomicU64::new(0);
                let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let spool =
                    std::env::temp_dir().join(format!("winrdp-print-{}-{sequence}.ps", std::process::id()));
                let response = match std::fs::File::create(&spool) {
                    Ok(file) => {
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
                Ok(vec![SvcMessage::from(RdpdrPdu::DeviceWriteResponse(DeviceWriteResponse {
                    device_io_reply: DeviceIoResponse::new(write.device_io_request, status),
                    length,
                }))])
            }
            PrinterIoRequest::Close(close) => {
                let file_id = close.device_io_request.file_id;
                if let Some(spool) = self.poisoned.remove(&file_id) {
                    let _ = std::fs::remove_file(spool);
                } else if let Some(job) = self.jobs.remove(&file_id) {
                    drop(job.file);
                    self.submit(&job.spool, job.bytes);
                }
                Ok(vec![SvcMessage::from(RdpdrPdu::DeviceCloseResponse(DeviceCloseResponse {
                    device_io_response: DeviceIoResponse::new(close.device_io_request, NtStatus::SUCCESS),
                }))])
            }
        }
    }

    /// Abandons the job behind an oversized write so a later close discards it.
    pub fn reject_write(&mut self, req: DeviceIoRequest) -> PduResult<Vec<SvcMessage>> {
        if let Some(job) = self.jobs.remove(&req.file_id) {
            warn!(file_id = req.file_id, "Print job abandoned: the server sent an oversized write");
            self.poisoned.insert(req.file_id, job.spool);
        }
        Ok(vec![SvcMessage::from(RdpdrPdu::DeviceWriteResponse(DeviceWriteResponse {
            device_io_reply: DeviceIoResponse::new(req, NtStatus::UNSUCCESSFUL),
            length: 0,
        }))])
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
                info!(bytes, "Print job handed to lp: {}", String::from_utf8_lossy(&output.stdout).trim());
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
            std::fs::copy(spool, &destination)
                .and_then(|_| std::fs::remove_file(spool))
                .map(|()| ())
        });
        match moved {
            Ok(()) => info!(?destination, "Print job saved as a PostScript file"),
            Err(error) => warn!(%error, ?destination, "Could not save the print job"),
        }
    }
}

fn default_fallback_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
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
            .handle(PrinterIoRequest::Close(DeviceCloseRequest::decode(io(file_id, MajorFunction::Close))))
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
            .handle(PrinterIoRequest::Close(DeviceCloseRequest::decode(io(file_id, MajorFunction::Close))))
            .expect("close");
        assert!(!dir.exists() || std::fs::read_dir(&dir).expect("dir").next().is_none(), "nothing saved");
    }

    #[test]
    fn targets_parse_from_the_launcher_setting() {
        assert!(matches!(PrintTarget::parse("default"), PrintTarget::DefaultPrinter));
        assert!(matches!(PrintTarget::parse(""), PrintTarget::DefaultPrinter));
        assert!(matches!(PrintTarget::parse("HP_LaserJet"), PrintTarget::Printer(n) if n == "HP_LaserJet"));
        assert!(matches!(PrintTarget::parse("folder:/tmp/out"), PrintTarget::Folder(p) if p == Path::new("/tmp/out")));
    }
}
