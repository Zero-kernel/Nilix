//! One stable authorization and filesystem snapshot for a pathname operation.
use alloc::sync::Arc;
use kernel_core::fs_context::FsContextState;
use kernel_core::process::{CredentialAuthorization, ProcessArc};
use kernel_core::{current_pid, get_process, MountNamespace, UserNamespace};
use mm::{AdmittedVec, HeapClass};

use crate::types::{FileMode, FsError, Stat};

pub(crate) struct OperationContext {
    pub process: Option<ProcessArc>,
    pub authorization: Option<CredentialAuthorization>,
    pub namespace: Arc<MountNamespace>,
    pub user_namespace: Arc<UserNamespace>,
    pub fs: FsContextState,
    pub umask: u16,
    pub uid: u32,
    pub gid: u32,
    pub groups: AdmittedVec<u32>,
    pub subject: lsm::ProcessCtx,
}

impl OperationContext {
    pub fn current() -> Result<Self, FsError> {
        Self::current_using(None)
    }

    pub fn current_using(existing: Option<&CredentialAuthorization>) -> Result<Self, FsError> {
        let pid = current_pid().ok_or(FsError::PermDenied)?;
        let process = get_process(pid).ok_or(FsError::PermDenied)?;
        Self::from_process(pid, process, existing)
    }

    pub(crate) fn from_process(
        pid: kernel_core::ProcessId,
        process: ProcessArc,
        existing: Option<&CredentialAuthorization>,
    ) -> Result<Self, FsError> {
        let (credentials, namespace, user_namespace, fs, umask, tgid) = {
            let proc = process.lock();
            (
                proc.shared_credentials(),
                proc.mount_ns.clone(),
                proc.user_ns.clone(),
                proc.fs_context.clone(),
                proc.umask,
                proc.tgid,
            )
        };
        let authorization = match existing {
            // An existing reader span remains valid behind a pending writer.
            Some(existing) => existing.derive(),
            None => credentials
                .try_begin_authorization()
                .ok_or(FsError::PermDenied)?,
        };
        {
            let proc = process.lock();
            if !proc.credentials_match_authorization(&authorization)
                || !Arc::ptr_eq(&proc.mount_ns, &namespace)
                || !Arc::ptr_eq(&proc.user_ns, &user_namespace)
                || !proc.fs_context.matches(&fs)
            {
                return Err(FsError::PermDenied);
            }
        }
        let (uid, gid, groups, subject) = {
            let creds = authorization.read();
            let map_uid = |value| {
                user_namespace
                    .map_uid_from_ns(value)
                    .ok_or(FsError::PermDenied)
            };
            let map_gid = |value| {
                user_namespace
                    .map_gid_from_ns(value)
                    .ok_or(FsError::PermDenied)
            };
            let uid = map_uid(creds.euid)?;
            let gid = map_gid(creds.egid)?;
            let mut groups = AdmittedVec::new(HeapClass::Vfs);
            groups
                .try_reserve_exact(creds.supplementary_groups.len())
                .map_err(|_| FsError::NoMem)?;
            for &group in creds.supplementary_groups.iter() {
                groups
                    .push_reserved(map_gid(group)?)
                    .map_err(|_| FsError::NoMem)?;
            }
            let subject = lsm::ProcessCtx::new(
                pid,
                tgid,
                map_uid(creds.uid)?,
                map_gid(creds.gid)?,
                uid,
                gid,
            );
            (uid, gid, groups, subject)
        };
        if fs.root.is_none() || fs.cwd.is_none() {
            return Err(FsError::PermDenied);
        }
        Ok(Self {
            process: Some(process),
            authorization: Some(authorization),
            namespace,
            user_namespace,
            fs,
            umask,
            uid,
            gid,
            groups,
            subject,
        })
    }

    /// Only explicit VFS boot/setup entrypoints use this authority. Process
    /// entrypoints always call current/current_using, including failed snapshots.
    pub(crate) fn trusted(namespace: Arc<MountNamespace>, fs: FsContextState) -> Self {
        Self {
            process: None,
            authorization: None,
            namespace,
            user_namespace: kernel_core::ROOT_USER_NAMESPACE.clone(),
            fs,
            umask: 0,
            uid: 0,
            gid: 0,
            groups: AdmittedVec::new(HeapClass::Vfs),
            subject: lsm::ProcessCtx::new(0, 0, 0, 0, 0, 0),
        }
    }

    pub fn permits(&self, stat: &Stat, read: bool, write: bool, execute: bool) -> bool {
        super::manager::permission_bits_allow(
            self.uid,
            self.gid,
            &self.groups,
            stat,
            read,
            write,
            execute,
        )
    }

    pub fn creation_mode(&self, mode: FileMode) -> FileMode {
        let mut perm = mode.perm & !self.umask;
        if self.uid != 0 {
            perm &= !0o4000;
            if !mode.is_dir() {
                perm &= !0o2000;
            }
        }
        FileMode::new(mode.file_type, perm)
    }

    pub fn revalidate(&self) -> Result<(), FsError> {
        if let Some(process) = &self.process {
            let proc = process.lock();
            if !self
                .authorization
                .as_ref()
                .map(|authorization| proc.credentials_match_authorization(authorization))
                .unwrap_or(false)
                || !Arc::ptr_eq(&proc.mount_ns, &self.namespace)
                || !Arc::ptr_eq(&proc.user_ns, &self.user_namespace)
                || !proc.fs_context.matches(&self.fs)
            {
                return Err(FsError::PermDenied);
            }
        }
        Ok(())
    }
}
