use super::*;
use crate::context::OperationContext;
use crate::path::{
    self, FinalLink, Mount, MountView, NamespaceMountTable, Resolution, ResolvedPath,
};
use crate::topology::{self, Retirement};
use mm::HeapClass;

impl Vfs {
    pub const fn new() -> Self {
        Self {
            mount_tables: RwLock::new(mm::AdmittedMap::new(HeapClass::Vfs)),
            devfs: RwLock::new(None),
            retirement: RwLock::new(None),
        }
    }

    fn retirement(&self) -> Result<Arc<Retirement<Mount>>, FsError> {
        if let Some(existing) = self.retirement.read().as_ref() {
            return Ok(existing.clone());
        }
        let prepared = Retirement::try_new(HeapClass::Vfs)?;
        Ok(self.retirement.write().get_or_insert(prepared).clone())
    }

    fn ensure_namespace_table(
        &self,
        ns: &Arc<MountNamespace>,
    ) -> Result<Arc<NamespaceMountTable>, FsError> {
        if let Some(table) = self.mount_tables.read().get(&ns.id()) {
            return Ok(table.clone());
        }
        let parent = ns
            .parent()
            .map(|parent| self.ensure_namespace_table(&parent))
            .transpose()?;
        let prepared = NamespaceMountTable::try_new(parent.as_deref())?;
        let mut registry = self.mount_tables.write();
        if let Some(table) = registry.get(&ns.id()) {
            return Ok(table.clone());
        }
        registry
            .try_insert(ns.id(), prepared.clone())
            .map_err(|_| FsError::NoMem)?;
        Ok(prepared)
    }

    pub fn materialize_namespace(&self, ns: &Arc<MountNamespace>) -> Result<(), FsError> {
        let _topology = topology::read();
        self.ensure_namespace_table(ns).map(|_| ())
    }

    pub fn remove_namespace_id(&self, id: NamespaceId) {
        let removed = self.mount_tables.write().remove(&id);
        drop(removed);
    }

    pub fn rollback_materialized_namespace(&self, ns: &Arc<MountNamespace>) {
        self.remove_namespace_id(ns.id());
    }

    pub(super) fn trusted_context(
        &self,
        ns: &Arc<MountNamespace>,
    ) -> Result<OperationContext, FsError> {
        let table = self.ensure_namespace_table(ns)?;
        Ok(OperationContext::trusted(
            ns.clone(),
            path::initial_state(&table.root()?)?,
        ))
    }

    pub fn init(&self) {
        let ns = ROOT_MNT_NAMESPACE.clone();
        let ramfs = RamFs::try_new().expect("boot: RAMFS root allocation failed");
        self.mount_in_namespace(&ns, "/", ramfs.clone())
            .expect("boot: root mount failed");
        {
            let topology = topology::write();
            let setup = topology.setup(0, 0);
            for name in ["dev", "proc", "sys", "mnt"] {
                ramfs
                    .create(
                        &ramfs.root_inode(),
                        name,
                        FileMode::directory(0o755),
                        &setup,
                    )
                    .expect("boot: mount directory creation failed");
            }
        }
        let devfs = DevFs::new();
        self.mount_in_namespace(&ns, "/dev", devfs.clone())
            .expect("boot: devfs mount failed");
        *self.devfs.write() = Some(devfs);
        self.mount_in_namespace(
            &ns,
            "/proc",
            ProcFs::try_new().expect("boot: procfs allocation failed"),
        )
        .expect("boot: procfs mount failed");
        let sysfs = RamFs::try_new().expect("boot: sysfs allocation failed");
        self.mount_in_namespace(&ns, "/sys", sysfs.clone())
            .expect("boot: sysfs mount failed");
        {
            let topology = topology::write();
            let setup = topology.setup(0, 0);
            let fs = sysfs
                .create(
                    &sysfs.root_inode(),
                    "fs",
                    FileMode::directory(0o755),
                    &setup,
                )
                .expect("boot: sys/fs creation failed");
            sysfs
                .create(&fs, "cgroup", FileMode::directory(0o755), &setup)
                .expect("boot: cgroup mount directory creation failed");
        }
        self.mount_in_namespace(&ns, "/sys/fs/cgroup", CgroupFs::new())
            .expect("boot: cgroupfs mount failed");
        let root = self
            .ensure_namespace_table(&ns)
            .unwrap()
            .root()
            .unwrap()
            .directory_handle()
            .unwrap();
        kernel_core::fs_context::install_initial_directory(root);
        klog_always!("VFS initialized: ramfs at /, devfs at /dev, procfs at /proc, cgroupfs at /sys/fs/cgroup");
    }

    /// Explicit kernel setup entrypoint. Syscalls use mount(), with a complete
    /// process context; missing credentials never select this authority.
    pub fn mount_in_namespace(
        &self,
        ns: &Arc<MountNamespace>,
        name: &str,
        fs: Arc<dyn FileSystem>,
    ) -> Result<(), FsError> {
        let table = self.ensure_namespace_table(ns)?;
        let retirement = self.retirement()?;
        let topology = topology::write();
        let setup = topology.setup(0, 0);
        setup.defer(&retirement)?;
        let context = if name == "/" && table.view.read().root.is_none() {
            None
        } else {
            Some(self.trusted_context(ns)?)
        };
        let mut view = table.view.write();
        let covered = match context.as_ref() {
            Some(context) => Some(
                path::resolve(
                    context,
                    &view,
                    name,
                    ResolveFlags::empty(),
                    FinalLink::Follow,
                    false,
                )?
                .found()?,
            ),
            None => None,
        };
        self.insert_mount(&mut view, covered.as_ref(), fs, &retirement)
    }

    fn insert_mount(
        &self,
        view: &mut MountView,
        covered: Option<&ResolvedPath>,
        fs: Arc<dyn FileSystem>,
        retirement: &Arc<Retirement<Mount>>,
    ) -> Result<(), FsError> {
        if view.mounts.len() >= crate::mount_namespace::MAX_MOUNTS_PER_NS {
            return Err(FsError::NoMem);
        }
        if let Some(covered) = covered {
            if !covered.inode.is_dir() {
                return Err(FsError::NotDir);
            }
            if covered.inode.ino() == covered.mount.fs.root_inode().ino() {
                return Err(FsError::Busy);
            }
        } else if view.root.is_some() {
            return Err(FsError::Exists);
        }
        if !fs.root_inode().is_dir() {
            return Err(FsError::NotDir);
        }
        let mount = Mount::try_new(fs, covered, retirement)?;
        let id = mount.id;
        view.mounts
            .try_insert(id, mount)
            .map_err(|_| FsError::NoMem)?;
        if covered.is_none() {
            view.root = Some(id);
        }
        Ok(())
    }

    pub fn mount(&self, name: &str, fs: Arc<dyn FileSystem>) -> Result<(), FsError> {
        let context = OperationContext::current()?;
        if context.uid != 0 {
            return Err(FsError::PermDenied);
        }
        let covered =
            self.lookup_using(name, ResolveFlags::empty(), FinalLink::Follow, &context)?;
        lsm::hook_file_permission(&context.subject, covered.inode.ino(), 1)
            .map_err(|_| FsError::PermDenied)?;
        lsm::hook_file_mount(&context.subject, 0, hash_path(name), 0, 0)
            .map_err(|_| FsError::PermDenied)?;
        let table = self.ensure_namespace_table(&context.namespace)?;
        let retirement = self.retirement()?;
        let topology = topology::write();
        let mutation = topology.context(&context);
        mutation.defer(&retirement)?;
        let mut view = table.view.write();
        context.revalidate()?;
        let current = path::resolve(
            &context,
            &view,
            name,
            ResolveFlags::empty(),
            FinalLink::Follow,
            false,
        )?
        .found()?;
        if !current.same(&covered) {
            return Err(FsError::Again);
        }
        self.insert_mount(&mut view, Some(&current), fs, &retirement)
    }

    fn umount_using(&self, name: &str, context: OperationContext) -> Result<(), FsError> {
        if context.uid != 0 {
            return Err(FsError::PermDenied);
        }
        let target = self.lookup_using(name, ResolveFlags::empty(), FinalLink::Follow, &context)?;
        lsm::hook_file_umount(&context.subject, hash_path(name), 0)
            .map_err(|_| FsError::PermDenied)?;
        let table = self.ensure_namespace_table(&context.namespace)?;
        let removed =
            {
                let _topology = topology::write();
                let mut view = table.view.write();
                context.revalidate()?;
                let current = path::resolve(
                    &context,
                    &view,
                    name,
                    ResolveFlags::empty(),
                    FinalLink::Follow,
                    false,
                )?
                .found()?;
                if !current.same(&target) {
                    return Err(FsError::Again);
                }
                if Some(target.mount.id) == view.root
                    || target.inode.ino() != target.mount.fs.root_inode().ino()
                {
                    return Err(FsError::Busy);
                }
                if view.mounts.values().any(|mount| {
                    mount.parent.as_ref().map(|parent| parent.id) == Some(target.mount.id)
                }) {
                    return Err(FsError::Busy);
                }
                view.mounts
                    .remove(&target.mount.id)
                    .ok_or(FsError::NotFound)?
            };
        drop(removed);
        Ok(())
    }

    pub fn umount(&self, name: &str) -> Result<(), FsError> {
        self.umount_using(name, OperationContext::current()?)
    }
    pub fn umount_in_namespace(&self, ns: &Arc<MountNamespace>, name: &str) -> Result<(), FsError> {
        self.umount_using(name, self.trusted_context(ns)?)
    }

    fn lookup_using(
        &self,
        name: &str,
        flags: ResolveFlags,
        final_link: FinalLink,
        context: &OperationContext,
    ) -> Result<ResolvedPath, FsError> {
        let table = self.ensure_namespace_table(&context.namespace)?;
        let _topology = topology::read();
        let view = table.view.read();
        context.revalidate()?;
        path::resolve(context, &view, name, flags, final_link, false)?.found()
    }

    fn observe<R>(
        &self,
        context: &OperationContext,
        observe: impl FnOnce(&MountView) -> Result<R, FsError>,
    ) -> Result<R, FsError> {
        let table = self.ensure_namespace_table(&context.namespace)?;
        let _topology = topology::read();
        let view = table.view.read();
        context.revalidate()?;
        observe(&view)
    }

    pub fn lookup_path(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        self.lookup_path_with_flags(name, ResolveFlags::empty(), true)
    }
    pub fn lookup_path_with_flags(
        &self,
        name: &str,
        flags: ResolveFlags,
        follow: bool,
    ) -> Result<Arc<dyn Inode>, FsError> {
        self.lookup_using(
            name,
            flags,
            if follow {
                FinalLink::Follow
            } else {
                FinalLink::Reject
            },
            &OperationContext::current()?,
        )
        .map(|path| path.inode)
    }
    pub fn lookup_symlink(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        self.lookup_using(
            name,
            ResolveFlags::empty(),
            FinalLink::Return,
            &OperationContext::current()?,
        )
        .map(|path| path.inode)
    }

    pub fn open(&self, name: &str, flags: OpenFlags, mode: u16) -> Result<FileDescriptor, FsError> {
        self.open_with_resolve(name, flags, mode, ResolveFlags::empty())
    }
    pub fn open_trusted(
        &self,
        name: &str,
        flags: OpenFlags,
        mode: u16,
    ) -> Result<FileDescriptor, FsError> {
        let fd = self.open_with_resolve_using(
            name,
            flags,
            mode,
            ResolveFlags::empty(),
            PreparedFileHandle::try_new,
            self.trusted_context(&ROOT_MNT_NAMESPACE)?,
        )?;
        finish_open(fd.as_ref())?;
        Ok(fd)
    }
    pub fn open_with_resolve(
        &self,
        name: &str,
        flags: OpenFlags,
        mode: u16,
        resolve: ResolveFlags,
    ) -> Result<FileDescriptor, FsError> {
        let fd = self.open_with_resolve_using(
            name,
            flags,
            mode,
            resolve,
            PreparedFileHandle::try_new,
            OperationContext::current()?,
        )?;
        finish_open(fd.as_ref())?;
        Ok(fd)
    }

    pub(super) fn open_with_resolve_using<P>(
        &self,
        name: &str,
        flags: OpenFlags,
        mode: u16,
        resolve: ResolveFlags,
        prepare: P,
        context: OperationContext,
    ) -> Result<FileDescriptor, FsError>
    where
        P: FnOnce() -> Result<PreparedFileHandle, FsError>,
    {
        self.open_authorized(
            name,
            flags,
            mode,
            resolve,
            prepare,
            context,
            |context, path, stat| {
                lsm::hook_file_open(
                    &context.subject,
                    stat.ino,
                    LsmOpenFlags(flags.0),
                    &LsmFileCtx::new(stat.ino, stat.mode.to_raw(), hash_path(name)),
                )
                .map_err(|_| FsError::PermDenied)
            },
        )
    }

    fn open_authorized<P, H>(
        &self,
        name: &str,
        flags: OpenFlags,
        mode: u16,
        resolve: ResolveFlags,
        prepare: P,
        context: OperationContext,
        mut authorize: H,
    ) -> Result<FileDescriptor, FsError>
    where
        P: FnOnce() -> Result<PreparedFileHandle, FsError>,
        H: FnMut(&OperationContext, &ResolvedPath, &Stat) -> Result<(), FsError>,
    {
        flags.validate_access_mode()?;
        let prepared = prepare()?;
        let final_link = if flags.is_create() && flags.is_exclusive() {
            FinalLink::Return
        } else if flags.is_nofollow() {
            FinalLink::Reject
        } else {
            FinalLink::Follow
        };
        let check_file = |path: &ResolvedPath| {
            let stat = path.inode.stat()?;
            if flags.is_directory() && !stat.mode.is_dir() {
                return Err(FsError::NotDir);
            }
            if stat.mode.is_dir() && flags.is_writable() {
                return Err(FsError::IsDir);
            }
            if !flags.is_path()
                && !context.permits(&stat, flags.is_readable(), flags.is_writable(), false)
            {
                return Err(FsError::PermDenied);
            }
            Ok(stat)
        };
        let plan = self.observe(&context, |view| {
            path::resolve(&context, view, name, resolve, final_link, flags.is_create())
        })?;
        let mut authorized_mode = None;
        match &plan {
            Resolution::Found(path) => {
                if flags.is_create() && flags.is_exclusive() {
                    return Err(FsError::Exists);
                }
                let stat = check_file(path)?;
                authorize(&context, path, &stat)?;
                authorized_mode = Some(stat.mode.to_raw());
            }
            Resolution::Missing { parent, name } => {
                let stat = parent.inode.stat()?;
                if !context.permits(&stat, false, true, true) {
                    return Err(FsError::PermDenied);
                }
                let mode = context.creation_mode(FileMode::regular(mode & 0o7777));
                lsm::hook_file_create(&context.subject, stat.ino, hash_path(name), mode.to_raw())
                    .map_err(|_| FsError::PermDenied)?;
            }
        }
        let table = self.ensure_namespace_table(&context.namespace)?;
        let (resolved, created) = {
            let topology = topology::write();
            let mutation = topology.context(&context);
            let view = table.view.read();
            context.revalidate()?;
            let current = path::resolve(
                &context,
                &view,
                name,
                resolve,
                final_link,
                flags.is_create(),
            )?;
            match (&plan, current) {
                (Resolution::Found(expected), Resolution::Found(current))
                    if expected.same(&current) =>
                {
                    let stat = check_file(&current)?;
                    if Some(stat.mode.to_raw()) != authorized_mode {
                        return Err(FsError::Again);
                    }
                    (current, false)
                }
                (
                    Resolution::Missing {
                        parent: expected,
                        name: expected_name,
                    },
                    Resolution::Missing { parent, name },
                ) if parent.same(expected) && name == *expected_name => {
                    if !context.permits(&parent.inode.stat()?, false, true, true) {
                        return Err(FsError::PermDenied);
                    }
                    let mode = context.creation_mode(FileMode::regular(mode & 0o7777));
                    let inode = parent
                        .mount
                        .fs
                        .create(&parent.inode, &name, mode, &mutation)?;
                    (
                        ResolvedPath {
                            mount: parent.mount,
                            inode,
                            epoch: view.epoch,
                        },
                        true,
                    )
                }
                _ => return Err(FsError::Again),
            }
        };
        if created {
            let stat = check_file(&resolved)?;
            // Creation selected this real inode. Its open hook executes with no
            // topology/filesystem lock, then identity is checked before opening.
            authorize(&context, &resolved, &stat)?;
            let _topology = topology::read();
            let view = table.view.read();
            context.revalidate()?;
            let current =
                path::resolve(&context, &view, name, resolve, final_link, false)?.found()?;
            if !current.same(&resolved) || check_file(&current)?.mode.to_raw() != stat.mode.to_raw()
            {
                return Err(FsError::Again);
            }
        }
        resolved
            .inode
            .clone()
            .open(flags, prepared.bind_path(&resolved, context))
    }

    fn stat_using(
        &self,
        name: &str,
        follow: bool,
        context: OperationContext,
    ) -> Result<Stat, FsError> {
        let path = self.lookup_using(
            name,
            ResolveFlags::empty(),
            if follow {
                FinalLink::Follow
            } else {
                FinalLink::Return
            },
            &context,
        )?;
        let stat = path.inode.stat()?;
        lsm::hook_file_permission(&context.subject, stat.ino, 0)
            .map_err(|_| FsError::PermDenied)?;
        Ok(stat)
    }
    pub fn stat(&self, name: &str) -> Result<Stat, FsError> {
        self.stat_using(name, true, OperationContext::current()?)
    }
    pub fn stat_nofollow(&self, name: &str) -> Result<Stat, FsError> {
        self.stat_using(name, false, OperationContext::current()?)
    }
    pub fn stat_trusted(&self, name: &str) -> Result<Stat, FsError> {
        self.stat_using(name, true, self.trusted_context(&ROOT_MNT_NAMESPACE)?)
    }

    fn create_using(
        &self,
        input: &str,
        mode: FileMode,
        context: OperationContext,
    ) -> Result<Arc<dyn Inode>, FsError> {
        let (parent, name, trailing) =
            self.observe(&context, |view| path::resolve_parent(&context, view, input))?;
        if trailing && !mode.is_dir() {
            return Err(FsError::NotDir);
        }
        let stat = parent.inode.stat()?;
        if !context.permits(&stat, false, true, true) {
            return Err(FsError::PermDenied);
        }
        let mode = context.creation_mode(mode);
        if mode.is_dir() {
            lsm::hook_file_mkdir(&context.subject, stat.ino, hash_path(&name), mode.to_raw())
                .map_err(|_| FsError::PermDenied)?;
        } else {
            lsm::hook_file_create(&context.subject, stat.ino, hash_path(&name), mode.to_raw())
                .map_err(|_| FsError::PermDenied)?;
        }
        let table = self.ensure_namespace_table(&context.namespace)?;
        let topology = topology::write();
        let mutation = topology.context(&context);
        let view = table.view.read();
        context.revalidate()?;
        let (current, current_name, _) = path::resolve_parent(&context, &view, input)?;
        if !current.same(&parent) || current_name != name {
            return Err(FsError::Again);
        }
        if !context.permits(&current.inode.stat()?, false, true, true) {
            return Err(FsError::PermDenied);
        }
        current
            .mount
            .fs
            .create(&current.inode, &name, mode, &mutation)
    }
    pub fn create(&self, name: &str, mode: FileMode) -> Result<Arc<dyn Inode>, FsError> {
        self.create_using(name, mode, OperationContext::current()?)
    }
    pub fn create_trusted(&self, name: &str, mode: FileMode) -> Result<Arc<dyn Inode>, FsError> {
        self.create_using(name, mode, self.trusted_context(&ROOT_MNT_NAMESPACE)?)
    }

    fn symlink_using(
        &self,
        input: &str,
        target: &str,
        context: OperationContext,
    ) -> Result<(), FsError> {
        if target.is_empty() {
            return Err(FsError::NotFound);
        }
        if target.len() > 4096 || target.contains('\0') {
            return Err(FsError::NameTooLong);
        }
        let (parent, name, trailing) =
            self.observe(&context, |view| path::resolve_parent(&context, view, input))?;
        if trailing {
            return Err(FsError::NotDir);
        }
        let stat = parent.inode.stat()?;
        if !context.permits(&stat, false, true, true) {
            return Err(FsError::PermDenied);
        }
        lsm::hook_file_symlink(
            &context.subject,
            stat.ino,
            hash_path(&name),
            hash_path(target),
        )
        .map_err(|_| FsError::PermDenied)?;
        let table = self.ensure_namespace_table(&context.namespace)?;
        let topology = topology::write();
        let mutation = topology.context(&context);
        let view = table.view.read();
        context.revalidate()?;
        let (current, current_name, _) = path::resolve_parent(&context, &view, input)?;
        if !current.same(&parent) || current_name != name {
            return Err(FsError::Again);
        }
        if !context.permits(&current.inode.stat()?, false, true, true) {
            return Err(FsError::PermDenied);
        }
        current
            .mount
            .fs
            .symlink(&current.inode, &name, target, &mutation)
            .map(|_| ())
    }
    pub fn symlink(&self, name: &str, target: &str) -> Result<(), FsError> {
        self.symlink_using(name, target, OperationContext::current()?)
    }
    pub fn symlink_trusted(&self, name: &str, target: &str) -> Result<(), FsError> {
        self.symlink_using(name, target, self.trusted_context(&ROOT_MNT_NAMESPACE)?)
    }

    pub fn readlink(&self, name: &str) -> Result<String, FsError> {
        let context = OperationContext::current()?;
        let path = self.lookup_using(name, ResolveFlags::empty(), FinalLink::Return, &context)?;
        if !path.inode.is_symlink() {
            return Err(FsError::Invalid);
        }
        lsm::hook_file_permission(&context.subject, path.inode.ino(), 0)
            .map_err(|_| FsError::PermDenied)?;
        let mut bytes = try_zeroed_buf(4097)?;
        let size = path.inode.read_at(0, &mut bytes)?;
        if size > 4096 {
            return Err(FsError::NameTooLong);
        }
        try_string_from_utf8_slice(&bytes[..size])
    }

    fn covered_in_any_namespace(&self, inode: &Arc<dyn Inode>) -> bool {
        self.mount_tables.read().values().any(|table| {
            table.view.read().mounts.values().any(|mount| {
                mount
                    .covered
                    .as_ref()
                    .map(|covered| (covered.fs_id(), covered.ino()))
                    == Some((inode.fs_id(), inode.ino()))
            })
        })
    }

    fn sticky(context: &OperationContext, parent: &Stat, child: &Stat) -> Result<(), FsError> {
        if parent.mode.perm & 0o1000 != 0
            && context.uid != 0
            && context.uid != parent.uid
            && context.uid != child.uid
        {
            return Err(FsError::PermDenied);
        }
        Ok(())
    }

    fn unlink_using(
        &self,
        input: &str,
        must_dir: Option<bool>,
        context: OperationContext,
    ) -> Result<(), FsError> {
        let plan = |view: &MountView| {
            let (parent, name, trailing) = path::resolve_parent(&context, view, input)?;
            let victim = parent.mount.fs.lookup(&parent.inode, &name)?;
            let stat = parent.inode.stat()?;
            let child = victim.stat()?;
            if trailing && !child.mode.is_dir() {
                return Err(FsError::NotDir);
            }
            if !context.permits(&stat, false, true, true) {
                return Err(FsError::PermDenied);
            }
            Self::sticky(&context, &stat, &child)?;
            Ok((parent, name, victim))
        };
        let (parent, name, victim) = self.observe(&context, plan)?;
        if must_dir == Some(true) {
            lsm::hook_file_rmdir(&context.subject, parent.inode.ino(), hash_path(&name))
                .map_err(|_| FsError::PermDenied)?;
        } else {
            lsm::hook_file_unlink(&context.subject, parent.inode.ino(), hash_path(&name))
                .map_err(|_| FsError::PermDenied)?;
        }
        let table = self.ensure_namespace_table(&context.namespace)?;
        let topology = topology::write();
        let mutation = topology.context(&context);
        let view = table.view.read();
        context.revalidate()?;
        let (current, current_name, current_victim) = plan(&view)?;
        if !current.same(&parent) || current_name != name || current_victim.ino() != victim.ino() {
            return Err(FsError::Again);
        }
        if self.covered_in_any_namespace(&current_victim) {
            return Err(FsError::Busy);
        }
        current
            .mount
            .fs
            .unlink(&current.inode, &name, victim.ino(), must_dir, &mutation)
    }
    pub fn unlink(&self, name: &str, must_dir: Option<bool>) -> Result<(), FsError> {
        self.unlink_using(name, must_dir, OperationContext::current()?)
    }
    pub fn unlink_trusted(&self, name: &str, must_dir: Option<bool>) -> Result<(), FsError> {
        self.unlink_using(name, must_dir, self.trusted_context(&ROOT_MNT_NAMESPACE)?)
    }

    fn rename_using(
        &self,
        old: &str,
        new: &str,
        noreplace: bool,
        context: OperationContext,
    ) -> Result<(), FsError> {
        let plan = |view: &MountView| {
            let (old_parent, old_name, old_trailing) = path::resolve_parent(&context, view, old)?;
            let (new_parent, new_name, new_trailing) = path::resolve_parent(&context, view, new)?;
            if old_parent.mount.id != new_parent.mount.id {
                return Err(FsError::CrossDev);
            }
            let fs = &old_parent.mount.fs;
            let source = fs.lookup(&old_parent.inode, &old_name)?;
            let dest = match fs.lookup(&new_parent.inode, &new_name) {
                Ok(inode) => Some(inode),
                Err(FsError::NotFound) => None,
                Err(error) => return Err(error),
            };
            let source_stat = source.stat()?;
            if (old_trailing || new_trailing) && !source_stat.mode.is_dir() {
                return Err(FsError::NotDir);
            }
            let old_stat = old_parent.inode.stat()?;
            let new_stat = new_parent.inode.stat()?;
            if !context.permits(&old_stat, false, true, true)
                || !context.permits(&new_stat, false, true, true)
            {
                return Err(FsError::PermDenied);
            }
            Self::sticky(&context, &old_stat, &source_stat)?;
            if let Some(dest) = &dest {
                Self::sticky(&context, &new_stat, &dest.stat()?)?;
            }
            Ok((old_parent, old_name, new_parent, new_name, source, dest))
        };
        let (old_parent, old_name, new_parent, new_name, source, dest) =
            self.observe(&context, plan)?;
        lsm::hook_file_rename(
            &context.subject,
            old_parent.inode.ino(),
            hash_path(&old_name),
            new_parent.inode.ino(),
            hash_path(&new_name),
        )
        .map_err(|_| FsError::PermDenied)?;
        let table = self.ensure_namespace_table(&context.namespace)?;
        let topology = topology::write();
        let mutation = topology.context(&context);
        let view = table.view.read();
        context.revalidate()?;
        let (
            current_old,
            current_old_name,
            current_new,
            current_new_name,
            current_source,
            current_dest,
        ) = plan(&view)?;
        if !current_old.same(&old_parent)
            || current_old_name != old_name
            || !current_new.same(&new_parent)
            || current_new_name != new_name
            || current_source.ino() != source.ino()
            || current_dest.as_ref().map(|inode| inode.ino())
                != dest.as_ref().map(|inode| inode.ino())
        {
            return Err(FsError::Again);
        }
        if let Some(dest) = &current_dest {
            if self.covered_in_any_namespace(dest) {
                return Err(FsError::Busy);
            }
        }
        current_old.mount.fs.rename(
            &current_old.inode,
            &old_name,
            &current_new.inode,
            &new_name,
            noreplace,
            source.ino(),
            dest.as_ref().map(|dest| dest.ino()),
            &mutation,
        )
    }
    pub fn rename(&self, old: &str, new: &str, noreplace: bool) -> Result<(), FsError> {
        self.rename_using(old, new, noreplace, OperationContext::current()?)
    }
    pub fn rename_trusted(&self, old: &str, new: &str, noreplace: bool) -> Result<(), FsError> {
        self.rename_using(
            old,
            new,
            noreplace,
            self.trusted_context(&ROOT_MNT_NAMESPACE)?,
        )
    }

    pub fn readdir(&self, name: &str) -> Result<Vec<DirEntry>, FsError> {
        let context = OperationContext::current()?;
        let path = self.lookup_using(name, ResolveFlags::empty(), FinalLink::Follow, &context)?;
        let stat = path.inode.stat()?;
        if !stat.mode.is_dir() {
            return Err(FsError::NotDir);
        }
        if !context.permits(&stat, true, false, true) {
            return Err(FsError::PermDenied);
        }
        lsm::hook_file_permission(&context.subject, stat.ino, 5)
            .map_err(|_| FsError::PermDenied)?;
        let mut result = Vec::new();
        let mut offset = 0;
        while let Some((next, entry)) = path.inode.readdir(offset)? {
            if next <= offset || result.len() >= 4096 {
                return Err(FsError::NoMem);
            }
            result.try_reserve(1).map_err(|_| FsError::NoMem)?;
            // lint-fallible: PREALLOCATED(result reserved one element immediately above; push moves the already owned entry)
            result.push(entry);
            offset = next;
        }
        Ok(result)
    }

    pub fn read_file_for_exec(&self, name: &str, max: usize) -> Result<Vec<u8>, SyscallError> {
        self.read_exec_using(
            name,
            max,
            OperationContext::current().map_err(fs_error_to_syscall)?,
        )
    }
    pub fn read_file_for_exec_trusted(
        &self,
        name: &str,
        max: usize,
    ) -> Result<Vec<u8>, SyscallError> {
        self.read_exec_using(
            name,
            max,
            self.trusted_context(&ROOT_MNT_NAMESPACE)
                .map_err(fs_error_to_syscall)?,
        )
    }
    fn read_exec_using(
        &self,
        name: &str,
        max: usize,
        context: OperationContext,
    ) -> Result<Vec<u8>, SyscallError> {
        let path = self
            .lookup_using(name, ResolveFlags::empty(), FinalLink::Follow, &context)
            .map_err(fs_error_to_syscall)?;
        let stat = path.inode.stat().map_err(fs_error_to_syscall)?;
        if stat.mode.is_dir() {
            return Err(SyscallError::EISDIR);
        }
        if !stat.mode.is_file() || !context.permits(&stat, true, false, true) {
            return Err(SyscallError::EACCES);
        }
        lsm::hook_file_open(
            &context.subject,
            stat.ino,
            LsmOpenFlags(0),
            &LsmFileCtx::new(stat.ino, stat.mode.to_raw(), hash_path(name)),
        )
        .map_err(|_| SyscallError::EACCES)?;
        let mut result = Vec::new();
        let mut offset = 0;
        let mut bytes = [0; 4096];
        loop {
            let count = path
                .inode
                .read_at(offset, &mut bytes)
                .map_err(fs_error_to_syscall)?;
            if count > bytes.len() {
                return Err(SyscallError::EIO);
            }
            if count == 0 {
                return Ok(result);
            }
            if result
                .len()
                .checked_add(count)
                .filter(|size| *size <= max)
                .is_none()
            {
                return Err(SyscallError::E2BIG);
            }
            result
                .try_reserve(count)
                .map_err(|_| SyscallError::ENOMEM)?;
            result.extend_from_slice(&bytes[..count]);
            offset += count as u64;
        }
    }

    pub fn getcwd(&self) -> Result<String, FsError> {
        let context = OperationContext::current()?;
        let table = self.ensure_namespace_table(&context.namespace)?;
        let _topology = topology::read();
        context.revalidate()?;
        let result = path::render_cwd(&context, &table.view.read());
        result
    }

    /// Preserve Zero-OS access()'s effective-ID contract. Resolve, test the raw
    /// host inode owner and mediate the requested mask under one credential span.
    pub fn access(&self, name: &str, mode: i32) -> Result<(), FsError> {
        self.access_authorized(
            name,
            mode,
            OperationContext::current()?,
            |context, path, mask| {
                lsm::hook_file_permission(&context.subject, path.inode.ino(), mask)
                    .map_err(|_| FsError::PermDenied)
            },
        )
    }

    fn access_authorized<H>(
        &self,
        name: &str,
        mode: i32,
        context: OperationContext,
        authorize: H,
    ) -> Result<(), FsError>
    where
        H: FnOnce(&OperationContext, &ResolvedPath, u32) -> Result<(), FsError>,
    {
        if mode & !7 != 0 {
            return Err(FsError::Invalid);
        }
        let resolve = |view: &MountView| {
            let resolved = path::resolve(
                &context,
                view,
                name,
                ResolveFlags::empty(),
                FinalLink::Follow,
                false,
            )?
            .found()?;
            let stat = resolved.inode.stat()?;
            if !context.permits(&stat, mode & 4 != 0, mode & 2 != 0, mode & 1 != 0) {
                return Err(FsError::PermDenied);
            }
            Ok(resolved)
        };
        let expected = self.observe(&context, resolve)?;
        // Include F_OK (mask zero); missing context or a denied hook is never
        // interpreted as permission. Reentrant hooks run outside topology locks.
        authorize(&context, &expected, mode as u32)?;
        self.observe(&context, |view| {
            let current = resolve(view)?;
            if current.same(&expected) {
                Ok(())
            } else {
                Err(FsError::Again)
            }
        })
    }

    pub fn change_directory(&self, name: &str, change_root: bool) -> Result<(), FsError> {
        let context = OperationContext::current()?;
        if change_root && context.uid != 0 {
            return Err(FsError::NotPermitted);
        }
        let resolved =
            self.lookup_using(name, ResolveFlags::empty(), FinalLink::Follow, &context)?;
        let stat = resolved.inode.stat()?;
        if !stat.mode.is_dir() {
            return Err(FsError::NotDir);
        }
        if !context.permits(&stat, false, false, true) {
            return Err(FsError::PermDenied);
        }
        lsm::hook_file_permission(&context.subject, stat.ino, 1)
            .map_err(|_| FsError::PermDenied)?;
        let table = self.ensure_namespace_table(&context.namespace)?;
        let old = {
            let _topology = topology::write();
            let view = table.view.read();
            context.revalidate()?;
            let current = path::resolve(
                &context,
                &view,
                name,
                ResolveFlags::empty(),
                FinalLink::Follow,
                false,
            )?
            .found()?;
            if !current.same(&resolved) {
                return Err(FsError::Again);
            }
            if !context.permits(&current.inode.stat()?, false, false, true) {
                return Err(FsError::PermDenied);
            }
            // Select the handle's epoch in the final guarded view. A pivot
            // during the unlocked hook must not misstamp a preflight handle.
            let handle = current.directory_handle()?;
            let mut replacement = context.fs.clone();
            replacement.generation = replacement
                .generation
                .checked_add(1)
                .ok_or(FsError::Again)?;
            if change_root {
                replacement.root = Some(handle.clone());
                if !path::is_beneath(
                    &path::handle_path(&context.fs.cwd, &view)?,
                    &current,
                    &view,
                    false,
                )? {
                    replacement.cwd = Some(handle);
                }
            } else {
                replacement.cwd = Some(handle);
            }
            let process = context.process.as_ref().ok_or(FsError::PermDenied)?;
            let mut proc = process.lock();
            if !proc.fs_context.matches(&context.fs)
                || !Arc::ptr_eq(&proc.mount_ns, &context.namespace)
                || !Arc::ptr_eq(&proc.user_ns, &context.user_namespace)
                || !context
                    .authorization
                    .as_ref()
                    .map(|auth| proc.credentials_match_authorization(auth))
                    .unwrap_or(false)
            {
                return Err(FsError::Again);
            }
            core::mem::replace(&mut proc.fs_context, replacement)
        };
        drop(old);
        Ok(())
    }

    fn pivot_pair(
        context: &OperationContext,
        view: &MountView,
        new_name: &str,
        old_name: &str,
    ) -> Result<(ResolvedPath, ResolvedPath), FsError> {
        if context.uid != 0 {
            return Err(FsError::NotPermitted);
        }
        let root = view.root_path()?;
        if !path::handle_path(&context.fs.root, view)?.same(&root) {
            return Err(FsError::NotPermitted);
        }
        let new_root = path::resolve(
            context,
            view,
            new_name,
            ResolveFlags::empty(),
            FinalLink::Follow,
            false,
        )?
        .found()?;
        let put_old = path::resolve(
            context,
            view,
            old_name,
            ResolveFlags::empty(),
            FinalLink::Follow,
            false,
        )?
        .found()?;
        for path in [&new_root, &put_old] {
            let stat = path.inode.stat()?;
            if !stat.mode.is_dir() {
                return Err(FsError::NotDir);
            }
            if !context.permits(&stat, false, false, true) {
                return Err(FsError::PermDenied);
            }
        }
        if new_root.mount.id == root.mount.id
            || !view.mounts.contains_key(&new_root.mount.id)
            || new_root.inode.ino() != new_root.mount.fs.root_inode().ino()
            || new_root.mount.parent.is_none()
            || put_old.mount.id != new_root.mount.id
            || put_old.same(&new_root)
            || !path::is_beneath(&put_old, &new_root, view, true)?
        {
            return Err(FsError::Invalid);
        }
        if view.mounts.values().any(|mount| {
            mount.parent.as_ref().map(|parent| parent.id) == Some(put_old.mount.id)
                && mount
                    .covered
                    .as_ref()
                    .map(|inode| (inode.fs_id(), inode.ino()))
                    == Some((put_old.inode.fs_id(), put_old.inode.ino()))
        }) {
            return Err(FsError::Busy);
        }
        Ok((new_root, put_old))
    }

    fn pivot_authorized<H>(
        &self,
        new_name: &str,
        old_name: &str,
        context: OperationContext,
        authorize: H,
    ) -> Result<(), FsError>
    where
        H: FnOnce(&OperationContext, &ResolvedPath, &ResolvedPath) -> Result<(), FsError>,
    {
        let (new_root, put_old) = self.observe(&context, |view| {
            Self::pivot_pair(&context, view, new_name, old_name)
        })?;
        authorize(&context, &new_root, &put_old)?;
        let table = self.ensure_namespace_table(&context.namespace)?;
        let retirement = self.retirement()?;
        let old_view = {
            let topology = topology::write();
            topology.context(&context).defer(&retirement)?;
            let mut view = table.view.write();
            context.revalidate()?;
            let (current_new, current_old) = Self::pivot_pair(&context, &view, new_name, old_name)?;
            if !current_new.same(&new_root) || !current_old.same(&put_old) {
                return Err(FsError::Again);
            }
            let prepared = view.prepare_pivot(&current_new, &current_old, &retirement)?;
            core::mem::replace(&mut *view, prepared)
        };
        drop(old_view);
        Ok(())
    }

    pub fn pivot_root(&self, new_name: &str, old_name: &str) -> Result<(), FsError> {
        self.pivot_authorized(
            new_name,
            old_name,
            OperationContext::current()?,
            |context, new_root, put_old| {
                for path in [new_root, put_old] {
                    lsm::hook_file_permission(&context.subject, path.inode.ino(), 1)
                        .map_err(|_| FsError::PermDenied)?;
                }
                lsm::hook_file_mount(&context.subject, 0, hash_path(new_name), 0, 0)
                    .map_err(|_| FsError::PermDenied)
            },
        )
    }

    pub fn namespace_bindings_valid(
        &self,
        source_ns: &Arc<MountNamespace>,
        target_ns: &Arc<MountNamespace>,
        state: &kernel_core::fs_context::FsContextState,
    ) -> Result<kernel_core::fs_context::NamespaceBindings, FsError> {
        struct Permit {
            _topology: spin::RwLockReadGuard<'static, ()>,
            _source: Arc<NamespaceMountTable>,
            _target: Arc<NamespaceMountTable>,
            _charge: mm::HeapCharge,
        }
        let topology = topology::read();
        let source = self.ensure_namespace_table(source_ns)?;
        let target = self.ensure_namespace_table(target_ns)?;
        let (root, cwd) = {
            let view = source.view.read();
            (
                path::handle_path(&state.root, &view)?,
                path::handle_path(&state.cwd, &view)?,
            )
        };
        let replacement = {
            let view = target.view.read();
            let transfer = |path: &ResolvedPath| {
                if !view.mounts.contains_key(&path.mount.id) {
                    return Err(FsError::CrossDev);
                }
                view.canonical(path)?.directory_handle()
            };
            kernel_core::fs_context::FsContextState {
                root: Some(transfer(&root)?),
                cwd: Some(transfer(&cwd)?),
                generation: state.generation.checked_add(1).ok_or(FsError::Again)?,
            }
        };
        let bytes = mm::allocation_charge_bytes(
            core::mem::size_of::<Permit>(),
            core::mem::align_of::<Permit>(),
        )
        .map_err(|_| FsError::NoMem)?;
        let charge = mm::try_reserve_heap(HeapClass::Vfs, bytes)
            .map_err(|_| FsError::NoMem)?
            .commit()
            .map_err(|_| FsError::NoMem)?;
        let permit = alloc::boxed::Box::try_new(Permit {
            _topology: topology,
            _source: source,
            _target: target,
            _charge: charge,
        })
        .map(|permit| permit as alloc::boxed::Box<dyn core::any::Any>)
        .map_err(|_| FsError::NoMem)?;
        Ok(kernel_core::fs_context::NamespaceBindings {
            state: replacement,
            permit,
        })
    }

    pub fn find_mount_in_namespace(
        &self,
        ns: &Arc<MountNamespace>,
        name: &str,
    ) -> Result<(String, Arc<dyn FileSystem>, String), FsError> {
        let context = self.trusted_context(ns)?;
        let path = self.lookup_using(name, ResolveFlags::empty(), FinalLink::Follow, &context)?;
        // This legacy inspection API is used by namespace diagnostics. Runtime
        // resolution never selects a mount by this textual representation.
        Ok((
            crate::types::try_dirent_name("/")?,
            path.mount.fs.clone(),
            crate::types::try_dirent_name(name)?,
        ))
    }

    pub fn register_block_device(
        &self,
        name: &str,
        device: Arc<dyn BlockDevice>,
    ) -> Result<(), FsError> {
        let devfs = self
            .devfs
            .read()
            .as_ref()
            .cloned()
            .ok_or(FsError::NotFound)?;
        devfs.register_block_device(name, device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vfs {
        mm::publish_heap_budgets();
        let vfs = Vfs::new();
        vfs.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/", RamFs::try_new().unwrap())
            .unwrap();
        vfs
    }

    fn context_at(vfs: &Vfs, root: &str, cwd: &str, uid: u32) -> OperationContext {
        let initial = vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap();
        let root = vfs
            .lookup_using(root, ResolveFlags::empty(), FinalLink::Follow, &initial)
            .unwrap();
        let cwd = vfs
            .lookup_using(cwd, ResolveFlags::empty(), FinalLink::Follow, &initial)
            .unwrap();
        let mut context = OperationContext::trusted(
            ROOT_MNT_NAMESPACE.clone(),
            kernel_core::fs_context::FsContextState {
                root: Some(root.directory_handle().unwrap()),
                cwd: Some(cwd.directory_handle().unwrap()),
                generation: 0,
            },
        );
        context.uid = uid;
        context.gid = uid;
        context.subject = LsmProcessCtx::new(100, 100, uid, uid, uid, uid);
        context
    }

    fn lookup(vfs: &Vfs, name: &str, context: &OperationContext) -> Result<ResolvedPath, FsError> {
        vfs.lookup_using(name, ResolveFlags::empty(), FinalLink::Follow, context)
    }

    fn pivot_fixture() -> Vfs {
        let vfs = fixture();
        for name in ["/new", "/new/put-back", "/old-work", "/jail"] {
            vfs.create_trusted(name, FileMode::directory(0o755))
                .unwrap();
        }
        vfs.create_trusted("/old-file", FileMode::regular(0o644))
            .unwrap()
            .write_at(0, b"old object")
            .unwrap();
        let mounted = RamFs::try_new().unwrap();
        {
            let topology = topology::write();
            let setup = topology.setup(0, 0);
            for name in ["old", "nested"] {
                mounted
                    .create(
                        &mounted.root_inode(),
                        name,
                        FileMode::directory(0o755),
                        &setup,
                    )
                    .unwrap();
            }
            mounted
                .create(
                    &mounted.root_inode(),
                    "new-file",
                    FileMode::regular(0o644),
                    &setup,
                )
                .unwrap();
        }
        vfs.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/new", mounted)
            .unwrap();
        vfs.symlink_trusted("/new/absolute", "/new-file").unwrap();
        vfs.mount_in_namespace(
            &ROOT_MNT_NAMESPACE,
            "/new/nested",
            RamFs::try_new().unwrap(),
        )
        .unwrap();
        vfs
    }

    fn pivot(vfs: &Vfs, new_root: &str, put_old: &str) -> Result<(), FsError> {
        vfs.pivot_authorized(
            new_root,
            put_old,
            vfs.trusted_context(&ROOT_MNT_NAMESPACE)?,
            |_, _, _| Ok(()),
        )
    }

    #[test]
    fn pivot_rebinds_saved_and_delayed_fork_state_but_preserves_exact_owners() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = pivot_fixture();
        let initial = context_at(&vfs, "/", "/", 0);
        let delayed_fork = initial.fs.clone();
        let work = context_at(&vfs, "/", "/old-work", 0);
        let jail = context_at(&vfs, "/jail", "/jail", 0);
        let original = lookup(&vfs, "/", &initial).unwrap();
        let mounted = lookup(&vfs, "/new", &initial).unwrap();
        let nested = lookup(&vfs, "/new/nested", &initial).unwrap();
        let descriptor = vfs
            .open_trusted("/old-file", OpenFlags::new(OpenFlags::O_RDONLY), 0)
            .unwrap();
        let sibling = MountNamespace::new_child(ROOT_MNT_NAMESPACE.clone()).unwrap();
        vfs.materialize_namespace(&sibling).unwrap();
        pivot(&vfs, "/new", "/new/old").unwrap();
        let table = vfs.ensure_namespace_table(&ROOT_MNT_NAMESPACE).unwrap();
        assert!(lookup(&vfs, "/", &initial).unwrap().same(&mounted));
        assert!(lookup(&vfs, "/old", &initial).unwrap().same(&original));
        assert!(lookup(&vfs, "/nested", &initial).unwrap().same(&nested));
        assert_eq!(path::render_cwd(&initial, &table.view.read()).unwrap(), "/");
        assert_eq!(
            path::render_cwd(&work, &table.view.read()).unwrap(),
            "/old/old-work"
        );
        assert_eq!(path::render_cwd(&jail, &table.view.read()).unwrap(), "/");
        assert!(matches!(
            lookup(&vfs, "/old-file", &jail),
            Err(FsError::NotFound)
        ));
        assert!(lookup(&vfs, "/absolute", &initial)
            .unwrap()
            .same(&lookup(&vfs, "/new-file", &initial).unwrap()));
        let late_child = OperationContext::trusted(ROOT_MNT_NAMESPACE.clone(), delayed_fork);
        assert!(lookup(&vfs, "/", &late_child).unwrap().same(&mounted));
        let intentional = context_at(&vfs, "/", "/old", 0);
        assert!(lookup(&vfs, ".", &intentional).unwrap().same(&original));
        assert_eq!(
            path::render_cwd(&intentional, &table.view.read()).unwrap(),
            "/old"
        );
        let sibling_context = vfs.trusted_context(&sibling).unwrap();
        assert!(lookup(&vfs, "/", &sibling_context).unwrap().same(&original));
        assert!(lookup(&vfs, "/new", &sibling_context)
            .unwrap()
            .same(&mounted));
        let inherited = MountNamespace::new_child(ROOT_MNT_NAMESPACE.clone()).unwrap();
        vfs.materialize_namespace(&inherited).unwrap();
        let inherited_context = OperationContext::trusted(inherited.clone(), initial.fs.clone());
        assert!(lookup(&vfs, "/", &inherited_context)
            .unwrap()
            .same(&mounted));
        drop(inherited_context);
        vfs.remove_namespace_id(inherited.id());
        vfs.remove_namespace_id(sibling.id());
        drop(table);
        drop(vfs);
        let mut bytes = [0; 10];
        assert_eq!(
            descriptor
                .as_any()
                .downcast_ref::<FileHandle>()
                .unwrap()
                .read(&mut bytes)
                .unwrap(),
            10
        );
        assert_eq!(&bytes, b"old object");
    }

    #[test]
    fn pivot_composes_repeated_transitions_and_enforces_history_bound() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = pivot_fixture();
        let initial = context_at(&vfs, "/", "/", 0);
        let original = lookup(&vfs, "/", &initial).unwrap();
        let mounted = lookup(&vfs, "/new", &initial).unwrap();
        pivot(&vfs, "/new", "/new/old").unwrap();
        let intentional = context_at(&vfs, "/old", "/old", 0);
        assert!(lookup(&vfs, "/", &intentional).unwrap().same(&original));
        for count in 1..path::MAX_ROOT_TRANSITIONS {
            if count % 2 == 1 {
                pivot(&vfs, "/old", "/old/new/put-back").unwrap();
            } else {
                pivot(&vfs, "/new/put-back", "/new/put-back/old").unwrap();
            }
            let expected = if count % 2 == 1 { &original } else { &mounted };
            assert!(lookup(&vfs, "/", &initial).unwrap().same(expected));
            assert!(lookup(&vfs, "/", &intentional).unwrap().same(expected));
        }
        let table = vfs.ensure_namespace_table(&ROOT_MNT_NAMESPACE).unwrap();
        let epoch = table.view.read().epoch;
        assert!(matches!(
            pivot(&vfs, "/new/put-back", "/new/put-back/old"),
            Err(FsError::NoMem)
        ));
        assert_eq!(table.view.read().epoch, epoch);
        assert_eq!(
            table.view.read().transitions.len(),
            path::MAX_ROOT_TRANSITIONS
        );
        assert!(lookup(&vfs, "/", &initial).unwrap().same(&original));
    }

    #[test]
    fn detached_cwd_crossings_rejoin_current_graph_after_pivot() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = pivot_fixture();
        vfs.create_trusted("/detached", FileMode::directory(0o755))
            .unwrap();
        vfs.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/detached", RamFs::try_new().unwrap())
            .unwrap();
        let saved = context_at(&vfs, "/", "/detached", 0);
        let confined = context_at(&vfs, "/detached", "/detached", 0);
        let detached = lookup(&vfs, ".", &saved).unwrap();
        let initial = vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap();
        let old_root = lookup(&vfs, "/", &initial).unwrap();
        let new_root = lookup(&vfs, "/new", &initial).unwrap();
        vfs.umount_in_namespace(&ROOT_MNT_NAMESPACE, "/detached")
            .unwrap();
        pivot(&vfs, "/new", "/new/old").unwrap();
        assert!(lookup(&vfs, ".", &saved).unwrap().same(&detached));
        assert!(lookup(&vfs, "..", &saved).unwrap().same(&old_root));
        assert!(lookup(&vfs, "../..", &saved).unwrap().same(&new_root));
        assert!(lookup(&vfs, "/", &saved).unwrap().same(&new_root));
        assert!(lookup(&vfs, "../..", &confined).unwrap().same(&detached));
        let table = vfs.ensure_namespace_table(&ROOT_MNT_NAMESPACE).unwrap();
        assert!(matches!(
            path::render_cwd(&saved, &table.view.read()),
            Err(FsError::NotFound)
        ));
    }

    #[test]
    fn setns_normalizes_source_history_then_stamps_target_view() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = pivot_fixture();
        let state = context_at(&vfs, "/", "/", 0).fs;
        let sibling = MountNamespace::new_child(ROOT_MNT_NAMESPACE.clone()).unwrap();
        vfs.materialize_namespace(&sibling).unwrap();
        let mounted = lookup(
            &vfs,
            "/new",
            &vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap(),
        )
        .unwrap();
        pivot(&vfs, "/new", "/new/old").unwrap();
        let bindings = vfs
            .namespace_bindings_valid(&ROOT_MNT_NAMESPACE, &sibling, &state)
            .unwrap();
        let normalized = bindings.state;
        drop(bindings.permit);
        assert_eq!(normalized.generation, state.generation + 1);
        let context = OperationContext::trusted(sibling.clone(), normalized);
        assert!(lookup(&vfs, "/", &context).unwrap().same(&mounted));
        assert!(lookup(&vfs, "/new-file", &context).is_ok());
        // The target has a different (empty) history; source normalization must
        // not interpret its root as the old source epoch-zero namespace root.
        assert_eq!(
            vfs.ensure_namespace_table(&sibling)
                .unwrap()
                .view
                .read()
                .epoch,
            0
        );
        vfs.umount_in_namespace(&sibling, "/new/nested").unwrap();
        vfs.umount_in_namespace(&sibling, "/new").unwrap();
        assert!(matches!(
            vfs.namespace_bindings_valid(&ROOT_MNT_NAMESPACE, &sibling, &state),
            Err(FsError::CrossDev)
        ));
        assert!(context.fs.root.is_some());
        vfs.remove_namespace_id(sibling.id());
    }

    #[test]
    fn pivot_invalid_relations_and_reentrant_hook_preserve_namespace() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = pivot_fixture();
        let table = vfs.ensure_namespace_table(&ROOT_MNT_NAMESPACE).unwrap();
        let root = table.root().unwrap();
        for (new_root, put_old) in [
            ("/", "/new/old"),
            ("/old-work", "/old-work"),
            ("/new", "/new"),
            ("/new", "/old-work"),
            ("/new", "/new/nested"),
        ] {
            assert!(matches!(
                pivot(&vfs, new_root, put_old),
                Err(FsError::Invalid)
            ));
            assert!(table.root().unwrap().same(&root));
            assert_eq!(table.view.read().epoch, 0);
        }
        let denied = context_at(&vfs, "/", "/", 1000);
        assert!(matches!(
            vfs.pivot_authorized("/new", "/new/old", denied, |_, _, _| Ok(())),
            Err(FsError::NotPermitted)
        ));
        let jailed = context_at(&vfs, "/jail", "/jail", 0);
        assert!(matches!(
            vfs.pivot_authorized("/", "/", jailed, |_, _, _| Ok(())),
            Err(FsError::NotPermitted)
        ));
        let context = vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap();
        assert!(matches!(
            vfs.pivot_authorized("/new", "/new/old", context, |_, _, _| {
                vfs.rename_trusted("/new/old", "/new/changed", false)?;
                vfs.create_trusted("/new/old", FileMode::directory(0o755))?;
                Ok(())
            }),
            Err(FsError::Again)
        ));
        assert!(table.root().unwrap().same(&root));
        assert_eq!(table.view.read().epoch, 0);
    }

    #[cfg(feature = "host_harness")]
    #[test]
    fn pivot_graph_preparation_reclaims_each_allocator_failure_without_publication() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = pivot_fixture();
        let table = vfs.ensure_namespace_table(&ROOT_MNT_NAMESPACE).unwrap();
        let context = vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap();
        let retirement = vfs.retirement().unwrap();
        let (new_root, put_old) =
            Vfs::pivot_pair(&context, &table.view.read(), "/new", "/new/old").unwrap();
        let baseline = mm::heap_class_snapshot(HeapClass::Vfs);
        crate::allocation_probe::begin_counting();
        let prepared = table
            .view
            .read()
            .prepare_pivot(&new_root, &put_old, &retirement)
            .unwrap();
        let allocations = crate::allocation_probe::end_counting();
        drop(prepared);
        assert!(allocations >= 7);
        assert_eq!(mm::heap_class_snapshot(HeapClass::Vfs), baseline);
        for fail_at in 0..allocations {
            crate::allocation_probe::fail_allocations_from(fail_at);
            let result = table
                .view
                .read()
                .prepare_pivot(&new_root, &put_old, &retirement);
            let failed = crate::allocation_probe::finish_failure();
            assert!(
                matches!(result, Err(FsError::NoMem)),
                "graph allocation {fail_at} did not return ENOMEM"
            );
            assert!(failed, "allocation {fail_at} was not exercised");
            assert_eq!(mm::heap_class_snapshot(HeapClass::Vfs), baseline);
            assert_eq!(table.view.read().epoch, 0);
            assert_eq!(table.view.read().transitions.len(), 0);
        }
    }

    #[cfg(feature = "host_harness")]
    #[test]
    fn actual_pivot_allocation_failures_preserve_graph_and_saved_bindings() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = pivot_fixture();
        let context = vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap();
        crate::allocation_probe::begin_counting();
        vfs.pivot_authorized("/new", "/new/old", context, |_, _, _| Ok(()))
            .unwrap();
        let allocations = crate::allocation_probe::end_counting();
        drop(vfs);
        assert!(allocations >= 7);
        for fail_at in 0..allocations {
            let vfs = pivot_fixture();
            let table = vfs.ensure_namespace_table(&ROOT_MNT_NAMESPACE).unwrap();
            let context = vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap();
            let saved = context.fs.clone();
            let root = table.root().unwrap();
            let baseline = mm::heap_class_snapshot(HeapClass::Vfs);
            crate::allocation_probe::fail_allocations_from(fail_at);
            let result = vfs.pivot_authorized("/new", "/new/old", context, |_, _, _| Ok(()));
            let failed = crate::allocation_probe::finish_failure();
            assert!(failed);
            assert!(
                matches!(result, Err(FsError::NoMem)),
                "pivot allocation {fail_at} did not return ENOMEM"
            );
            assert_eq!(mm::heap_class_snapshot(HeapClass::Vfs), baseline);
            let view = table.view.read();
            assert!(Arc::ptr_eq(&view.root_path().unwrap().mount, &root.mount));
            assert!(path::handle_path(&saved.root, &view).unwrap().same(&root));
            assert!(path::handle_path(&saved.cwd, &view).unwrap().same(&root));
            assert_eq!(view.epoch, 0);
            assert!(view.transitions.is_empty());
        }
    }

    #[test]
    fn pivot_rejects_missing_parent_and_logical_cycle_without_publication() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        for cycle in [false, true] {
            let vfs = pivot_fixture();
            let table = vfs.ensure_namespace_table(&ROOT_MNT_NAMESPACE).unwrap();
            let retirement = vfs.retirement().unwrap();
            let first = Mount::try_new(RamFs::try_new().unwrap(), None, &retirement).unwrap();
            let second =
                Mount::try_new(RamFs::try_new().unwrap(), Some(&first.root(0)), &retirement)
                    .unwrap();
            {
                let mut view = table.view.write();
                view.mounts.try_insert(second.id, second.clone()).unwrap();
                if cycle {
                    // Immutable Arc ownership stays acyclic, while the selected
                    // map's stable-ID graph deliberately contains A -> B -> A.
                    let replacement = Mount::try_represent(
                        first.id,
                        first.fs.clone(),
                        Some(&second.root(0)),
                        &retirement,
                    )
                    .unwrap();
                    view.mounts.try_insert(replacement.id, replacement).unwrap();
                }
            }
            let root = table.root().unwrap();
            let count = table.view.read().mounts.len();
            let baseline = mm::heap_class_snapshot(HeapClass::Vfs);
            assert!(matches!(
                pivot(&vfs, "/new", "/new/old"),
                Err(FsError::Invalid)
            ));
            assert_eq!(mm::heap_class_snapshot(HeapClass::Vfs), baseline);
            let view = table.view.read();
            assert!(Arc::ptr_eq(&view.root_path().unwrap().mount, &root.mount));
            assert_eq!(view.mounts.len(), count);
            assert_eq!(view.epoch, 0);
            assert!(view.transitions.is_empty());
        }
    }

    #[test]
    fn components_apply_search_and_symlinks_before_parent_traversal() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        for (name, mode) in [
            ("/blocked", 0),
            ("/public", 0o755),
            ("/other", 0o755),
            ("/other/sub", 0o755),
        ] {
            vfs.create_trusted(name, FileMode::directory(mode)).unwrap();
        }
        vfs.create_trusted("/regular", FileMode::regular(0o644))
            .unwrap();
        let target = vfs
            .create_trusted("/other/file", FileMode::regular(0o644))
            .unwrap();
        vfs.symlink_trusted("/jump", "/other/sub").unwrap();
        let context = context_at(&vfs, "/", "/", 1000);
        assert!(matches!(
            lookup(&vfs, "/blocked/../public", &context),
            Err(FsError::PermDenied)
        ));
        assert!(matches!(
            lookup(&vfs, "/regular/../public", &context),
            Err(FsError::NotDir)
        ));
        assert_eq!(
            lookup(&vfs, "/jump/../file", &context).unwrap().inode.ino(),
            target.ino()
        );
        assert!(matches!(
            lookup(&vfs, "/regular/", &context),
            Err(FsError::NotDir)
        ));
    }

    #[test]
    fn no_xdev_checks_absolute_link_reset_and_keeps_in_root_anchor() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        for directory in ["/mounted", "/alias"] {
            vfs.create_trusted(directory, FileMode::directory(0o755))
                .unwrap();
        }
        let host = vfs
            .create_trusted("/hostfile", FileMode::regular(0o644))
            .unwrap();
        vfs.symlink_trusted("/hostlink", "/hostfile").unwrap();
        vfs.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/mounted", RamFs::try_new().unwrap())
            .unwrap();
        let inner = vfs
            .create_trusted("/mounted/hostfile", FileMode::regular(0o644))
            .unwrap();
        vfs.symlink_trusted("/mounted/jump", "/hostfile").unwrap();
        let mounted = context_at(&vfs, "/", "/mounted", 0);
        assert!(matches!(
            vfs.lookup_using(
                "jump",
                ResolveFlags::from_bits(1),
                FinalLink::Follow,
                &mounted
            ),
            Err(FsError::CrossDev)
        ));
        assert_eq!(
            lookup(&vfs, "jump", &mounted).unwrap().inode.fs_id(),
            host.fs_id()
        );
        let anchored = vfs
            .lookup_using(
                "jump",
                ResolveFlags::from_bits(1 | 16),
                FinalLink::Follow,
                &mounted,
            )
            .unwrap();
        assert_eq!(
            (anchored.inode.fs_id(), anchored.inode.ino()),
            (inner.fs_id(), inner.ino())
        );
        let root = context_at(&vfs, "/", "/", 0);
        assert!(vfs
            .lookup_using(
                "hostlink",
                ResolveFlags::from_bits(1),
                FinalLink::Follow,
                &root
            )
            .is_ok());
        let filesystem = lookup(&vfs, "/", &root).unwrap().mount.fs.clone();
        vfs.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/alias", filesystem)
            .unwrap();
        let alias = context_at(&vfs, "/", "/alias", 0);
        assert!(matches!(
            vfs.lookup_using(
                "hostlink",
                ResolveFlags::from_bits(1),
                FinalLink::Follow,
                &alias
            ),
            Err(FsError::CrossDev)
        ));
        let confined = context_at(&vfs, "/alias", "/alias", 0);
        assert!(vfs
            .lookup_using(
                "hostlink",
                ResolveFlags::from_bits(1),
                FinalLink::Follow,
                &confined
            )
            .is_ok());
    }

    #[test]
    fn every_component_is_bounded_before_lookup_or_missing_create() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        let long = "x".repeat(256);
        let absolute = alloc::format!("/{long}");
        let intermediate = alloc::format!("/{long}/leaf");
        vfs.symlink_trusted("/expanded", &absolute).unwrap();
        let root = vfs
            .ensure_namespace_table(&ROOT_MNT_NAMESPACE)
            .unwrap()
            .root()
            .unwrap();
        let baseline = mm::heap_class_snapshot(HeapClass::Vfs);
        let ramfs_baseline = mm::heap_class_snapshot(HeapClass::RamFs);
        for name in [&absolute, &intermediate, "/expanded"] {
            assert!(matches!(vfs.stat_trusted(name), Err(FsError::NameTooLong)));
            assert!(matches!(
                vfs.open_trusted(
                    name,
                    OpenFlags::new(OpenFlags::O_CREAT | OpenFlags::O_RDWR),
                    0o600
                ),
                Err(FsError::NameTooLong)
            ));
            assert!(matches!(
                root.mount.fs.lookup(&root.inode, &long),
                Err(FsError::NotFound)
            ));
            assert_eq!(mm::heap_class_snapshot(HeapClass::Vfs), baseline);
            assert_eq!(mm::heap_class_snapshot(HeapClass::RamFs), ramfs_baseline);
        }
        let valid = alloc::format!("/{}", "v".repeat(255));
        assert!(vfs.create_trusted(&valid, FileMode::regular(0o600)).is_ok());
        assert!(vfs.stat_trusted(&valid).is_ok());
    }

    #[test]
    fn dangling_create_final_link_policy_and_shared_expansion_budget() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        vfs.symlink_trusted("/link", "/target").unwrap();
        let descriptor = vfs
            .open_trusted(
                "/link",
                OpenFlags::new(OpenFlags::O_CREAT | OpenFlags::O_RDWR),
                0o600,
            )
            .unwrap();
        descriptor
            .as_any()
            .downcast_ref::<FileHandle>()
            .unwrap()
            .write(b"target bytes")
            .unwrap();
        assert_eq!(vfs.stat_trusted("/target").unwrap().size, 12);
        assert!(matches!(
            vfs.open_trusted("/link", OpenFlags::new(OpenFlags::O_NOFOLLOW), 0),
            Err(FsError::SymlinkLoop)
        ));
        assert!(matches!(
            vfs.open_trusted(
                "/link",
                OpenFlags::new(OpenFlags::O_CREAT | OpenFlags::O_EXCL),
                0o600
            ),
            Err(FsError::Exists)
        ));
        let context = context_at(&vfs, "/", "/", 0);
        assert!(vfs
            .lookup_using("/link", ResolveFlags::empty(), FinalLink::Return, &context)
            .unwrap()
            .inode
            .is_symlink());
        for index in 0..40 {
            let name = alloc::format!("/s{index}");
            let target = if index == 39 {
                String::from("/target")
            } else {
                alloc::format!("/s{}", index + 1)
            };
            vfs.symlink_trusted(&name, &target).unwrap();
        }
        assert!(lookup(&vfs, "/s0", &context).is_ok());
        vfs.symlink_trusted("/too-many", "/s0").unwrap();
        assert!(matches!(
            lookup(&vfs, "/too-many", &context),
            Err(FsError::SymlinkLoop)
        ));
    }

    #[test]
    fn cwd_identity_survives_rename_and_never_follows_replacement() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        vfs.create_trusted("/a", FileMode::directory(0o755))
            .unwrap();
        let old = vfs
            .create_trusted("/a/b", FileMode::directory(0o755))
            .unwrap();
        let context = context_at(&vfs, "/", "/a/b", 0);
        vfs.rename_trusted("/a", "/renamed", false).unwrap();
        let table = vfs.ensure_namespace_table(&ROOT_MNT_NAMESPACE).unwrap();
        assert_eq!(
            path::render_cwd(&context, &table.view.read()).unwrap(),
            "/renamed/b"
        );
        vfs.unlink_trusted("/renamed/b", Some(true)).unwrap();
        let replacement = vfs
            .create_trusted("/renamed/b", FileMode::directory(0o755))
            .unwrap();
        assert_ne!(old.ino(), replacement.ino());
        assert_eq!(lookup(&vfs, ".", &context).unwrap().inode.ino(), old.ino());
        assert!(matches!(
            path::render_cwd(&context, &table.view.read()),
            Err(FsError::NotFound)
        ));
        assert_eq!(
            lookup(&vfs, "..", &context).unwrap().inode.ino(),
            vfs.stat_trusted("/renamed").unwrap().ino
        );
        assert!(matches!(
            vfs.create_using("new", FileMode::regular(0o600), context),
            Err(FsError::NotFound)
        ));
        assert!(matches!(
            vfs.stat_trusted("/renamed/b/new"),
            Err(FsError::NotFound)
        ));
    }

    #[test]
    fn outside_root_cwd_and_resolve_confinement_fail_closed() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        vfs.create_trusted("/jail", FileMode::directory(0o755))
            .unwrap();
        vfs.create_trusted("/jail/work", FileMode::directory(0o755))
            .unwrap();
        let context = context_at(&vfs, "/jail", "/jail/work", 0);
        vfs.rename_trusted("/jail/work", "/outside", false).unwrap();
        assert!(matches!(
            lookup(&vfs, ".", &context),
            Err(FsError::PermDenied)
        ));
        assert_eq!(
            lookup(&vfs, "/", &context).unwrap().inode.ino(),
            vfs.stat_trusted("/jail").unwrap().ino
        );
        let context = context_at(&vfs, "/", "/jail", 0);
        assert!(matches!(
            vfs.lookup_using(
                "../outside",
                ResolveFlags::from_bits(8),
                FinalLink::Follow,
                &context
            ),
            Err(FsError::CrossDev)
        ));
        assert!(matches!(
            vfs.lookup_using(
                "/outside",
                ResolveFlags::from_bits(8),
                FinalLink::Follow,
                &context
            ),
            Err(FsError::CrossDev)
        ));
        assert_eq!(
            vfs.lookup_using(
                "/",
                ResolveFlags::from_bits(16),
                FinalLink::Follow,
                &context
            )
            .unwrap()
            .inode
            .ino(),
            vfs.stat_trusted("/jail").unwrap().ino
        );
        assert!(matches!(
            vfs.lookup_using(
                ".",
                ResolveFlags::from_bits(32),
                FinalLink::Follow,
                &context
            ),
            Err(FsError::Again)
        ));
    }

    #[test]
    fn mount_identity_current_covered_ancestry_and_live_handle_ownership() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        for name in ["/one", "/two"] {
            vfs.create_trusted(name, FileMode::directory(0o755))
                .unwrap();
        }
        let mounted = RamFs::try_new().unwrap();
        let weak = Arc::downgrade(&mounted);
        vfs.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/one", mounted.clone())
            .unwrap();
        vfs.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/two", mounted.clone())
            .unwrap();
        let descriptor = vfs
            .open_trusted(
                "/one/held",
                OpenFlags::new(OpenFlags::O_CREAT | OpenFlags::O_RDWR),
                0o600,
            )
            .unwrap();
        descriptor
            .as_any()
            .downcast_ref::<FileHandle>()
            .unwrap()
            .write(b"held")
            .unwrap();
        let context = context_at(&vfs, "/", "/one", 0);
        assert!(matches!(
            vfs.lookup_using(
                "../two",
                ResolveFlags::from_bits(1),
                FinalLink::Follow,
                &context
            ),
            Err(FsError::CrossDev)
        ));
        vfs.rename_trusted("/one", "/moved", false).unwrap();
        let table = vfs.ensure_namespace_table(&ROOT_MNT_NAMESPACE).unwrap();
        assert_eq!(
            path::render_cwd(&context, &table.view.read()).unwrap(),
            "/moved"
        );
        assert!(matches!(
            vfs.unlink_trusted("/moved", Some(true)),
            Err(FsError::Busy)
        ));
        vfs.umount_in_namespace(&ROOT_MNT_NAMESPACE, "/moved")
            .unwrap();
        vfs.umount_in_namespace(&ROOT_MNT_NAMESPACE, "/two")
            .unwrap();
        vfs.unlink_trusted("/moved", Some(true)).unwrap();
        vfs.create_trusted("/moved", FileMode::directory(0o755))
            .unwrap();
        assert!(matches!(
            path::render_cwd(&context, &table.view.read()),
            Err(FsError::NotFound)
        ));
        drop(context);
        drop(mounted);
        assert!(
            weak.upgrade().is_some(),
            "descriptor retains filesystem after both namespace edges disappear"
        );
        assert_eq!(descriptor.stat().unwrap().size, 4);
        drop(descriptor);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn missing_context_never_authorizes_root_and_creators_store_host_ids() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        assert!(matches!(
            OperationContext::current(),
            Err(FsError::PermDenied)
        ));
        assert!(matches!(vfs.stat("/"), Err(FsError::PermDenied)));
        assert!(matches!(
            vfs.create("/unauthorized", FileMode::regular(0o600)),
            Err(FsError::PermDenied)
        ));
        vfs.create_trusted("/public", FileMode::directory(0o777))
            .unwrap();
        let mut context = context_at(&vfs, "/", "/public", 0x123456);
        context.gid = 0x234567;
        let file = vfs
            .create_using("owned", FileMode::regular(0o600), context)
            .unwrap();
        let stat = file.stat().unwrap();
        assert_eq!((stat.uid, stat.gid), (0x123456, 0x234567));
        let other = context_at(&vfs, "/", "/public", 0x987654);
        assert!(!other.permits(&stat, true, false, false));
    }

    #[test]
    fn access_uses_complete_group_membership_and_mediates_exact_masks() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        vfs.create_trusted("/access", FileMode::directory(0o777))
            .unwrap();
        let mut owner = context_at(&vfs, "/", "/access", 2000);
        owner.gid = 3333;
        let inode = vfs
            .create_using("group-denies", FileMode::regular(0o004), owner)
            .unwrap();
        let make_context = |member| {
            let mut context = context_at(&vfs, "/", "/access", 1000);
            if member {
                context.groups.try_push(3333).unwrap();
            }
            context
        };
        assert!(matches!(
            vfs.access_authorized("group-denies", 4, make_context(true), |_, _, _| Ok(())),
            Err(FsError::PermDenied)
        ));
        assert!(vfs
            .access_authorized(
                "group-denies",
                4,
                make_context(false),
                |context, path, mask| {
                    assert_eq!(context.uid, 1000);
                    assert_eq!(path.inode.ino(), inode.ino());
                    assert_eq!(mask, 4);
                    Ok(())
                }
            )
            .is_ok());
        assert!(matches!(
            vfs.access_authorized("group-denies", 0, make_context(true), |_, _, mask| {
                assert_eq!(mask, 0);
                Err(FsError::PermDenied)
            }),
            Err(FsError::PermDenied)
        ));
        assert!(matches!(
            vfs.access_authorized("group-denies", 8, make_context(false), |_, _, _| panic!(
                "invalid mask reached hook"
            )),
            Err(FsError::Invalid)
        ));
        assert!(matches!(
            vfs.access("/access/group-denies", 0),
            Err(FsError::PermDenied)
        ));
        assert!(matches!(
            vfs.access_authorized("group-denies", 4, make_context(false), |_, _, _| {
                vfs.rename_trusted("/access/group-denies", "/access/moved", false)?;
                vfs.create_trusted("/access/group-denies", FileMode::regular(0o004))?;
                Ok(())
            }),
            Err(FsError::Again)
        ));
    }

    #[cfg(feature = "host_harness")]
    #[test]
    fn access_context_fails_new_admission_but_derives_existing_span_behind_writer() {
        use kernel_core::process::{Process, ProcessNameSnapshot};
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        vfs.create_trusted("/public", FileMode::regular(0o004))
            .unwrap();
        let pid = 0x1014;
        let process = Process::try_new_pcb(
            pid,
            0,
            ProcessNameSnapshot::from_parts("vfs-access", ""),
            120,
        )
        .unwrap();
        process.lock().fs_context = vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap().fs;
        let credentials = process.lock().shared_credentials();
        let authorization = credentials.begin_authorization();
        credentials.with_hosted_pending_writer(|| {
            assert!(credentials.try_read().is_none());
            assert!(matches!(
                OperationContext::from_process(pid, process.clone(), None),
                Err(FsError::PermDenied)
            ));
            let derived =
                OperationContext::from_process(pid, process.clone(), Some(&authorization)).unwrap();
            assert_eq!(derived.uid, 65534);
            vfs.access_authorized("/public", 4, derived, |context, _, mask| {
                assert_eq!((context.subject.euid, mask), (65534, 4));
                assert!(context.authorization.is_some());
                Ok(())
            })
            .unwrap();
        });
        assert!(OperationContext::from_process(pid, process.clone(), None).is_ok());
        process.lock().fs_context = kernel_core::fs_context::FsContextState {
            root: None,
            cwd: None,
            generation: 0,
        };
        assert!(matches!(
            OperationContext::from_process(pid, process, Some(&authorization)),
            Err(FsError::PermDenied)
        ));
    }

    #[test]
    fn access_matches_host_inode_owner_after_namespace_id_mapping() {
        use kernel_core::process::{Process, ProcessNameSnapshot};
        use kernel_core::user_namespace::{UidGidMapping, UserNamespace};
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        vfs.create_trusted("/access", FileMode::directory(0o777))
            .unwrap();
        let mut owner = context_at(&vfs, "/", "/access", 70001);
        owner.gid = 70002;
        let inode = vfs
            .create_using("owned", FileMode::regular(0o600), owner)
            .unwrap();
        let namespace = UserNamespace::new_child(kernel_core::ROOT_USER_NAMESPACE.clone()).unwrap();
        let pid = 0x2014;
        let process = Process::try_new_pcb(
            pid,
            0,
            ProcessNameSnapshot::from_parts("mapped-access", ""),
            120,
        )
        .unwrap();
        {
            let mut proc = process.lock();
            proc.fs_context = vfs.trusted_context(&ROOT_MNT_NAMESPACE).unwrap().fs;
            proc.user_ns = namespace.clone();
        }
        assert!(matches!(
            OperationContext::from_process(pid, process.clone(), None),
            Err(FsError::PermDenied)
        ));
        namespace
            .set_uid_map_from_parent(
                alloc::vec![UidGidMapping {
                    ns_id: 65534,
                    host_id: 70001,
                    count: 1
                }],
                &kernel_core::ROOT_USER_NAMESPACE,
                0,
                true,
                true,
            )
            .unwrap();
        namespace
            .set_gid_map_from_parent(
                alloc::vec![UidGidMapping {
                    ns_id: 65534,
                    host_id: 70002,
                    count: 1
                }],
                &kernel_core::ROOT_USER_NAMESPACE,
                0,
                true,
                true,
            )
            .unwrap();
        let context = OperationContext::from_process(pid, process, None).unwrap();
        assert_eq!((context.uid, context.gid), (70001, 70002));
        assert_eq!(
            namespace.map_uid_to_ns(inode.stat().unwrap().uid),
            Some(65534)
        );
        vfs.access_authorized("/access/owned", 6, context, |context, path, mask| {
            assert_eq!(
                (context.subject.euid, path.inode.stat()?.uid, mask),
                (70001, 70001, 6)
            );
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn stored_cwd_and_root_are_not_retargeted_by_a_later_overmount() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        vfs.create_trusted("/covered", FileMode::directory(0o755))
            .unwrap();
        let underlying = vfs
            .create_trusted("/covered/child", FileMode::regular(0o644))
            .unwrap();
        let cwd = context_at(&vfs, "/", "/covered", 0);
        let root = context_at(&vfs, "/covered", "/covered", 0);
        let mounted = RamFs::try_new().unwrap();
        let replacement = mounted
            .create(
                &mounted.root_inode(),
                "child",
                FileMode::regular(0o644),
                &topology::write().setup(0, 0),
            )
            .unwrap();
        vfs.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/covered", mounted)
            .unwrap();
        assert_eq!(
            lookup(&vfs, "child", &cwd).unwrap().inode.fs_id(),
            underlying.fs_id()
        );
        assert_eq!(
            lookup(&vfs, "/child", &root).unwrap().inode.fs_id(),
            underlying.fs_id()
        );
        let absolute = lookup(&vfs, "/covered/child", &cwd).unwrap();
        assert_eq!(
            (absolute.inode.fs_id(), absolute.inode.ino()),
            (replacement.fs_id(), replacement.ino())
        );
    }

    #[test]
    fn unlocked_open_hook_can_reenter_vfs_and_stale_identity_fails_before_open() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        let vfs = fixture();
        let original = vfs
            .create_trusted("/original", FileMode::regular(0o600))
            .unwrap();
        original.write_at(0, b"must survive").unwrap();
        let context = context_at(&vfs, "/", "/", 0);
        let result = vfs.open_authorized(
            "/original",
            OpenFlags::new(OpenFlags::O_WRONLY | OpenFlags::O_TRUNC),
            0,
            ResolveFlags::empty(),
            PreparedFileHandle::try_new,
            context,
            |_, _, _| {
                // A write reentry would deadlock if authorization still held
                // topology or a mount view lock. It also replaces the name that
                // the outer operation must revalidate before any truncation.
                vfs.rename_trusted("/original", "/moved", false)?;
                vfs.create_trusted("/original", FileMode::regular(0o600))?;
                Ok(())
            },
        );
        assert!(matches!(result, Err(FsError::Again)));
        assert_eq!(original.stat().unwrap().size, 12);
        assert_eq!(vfs.stat_trusted("/original").unwrap().size, 0);
    }

    fn global_namespace_fixture() {
        mm::publish_heap_budgets();
        if !VFS
            .mount_tables
            .read()
            .contains_key(&ROOT_MNT_NAMESPACE.id())
        {
            VFS.mount_in_namespace(&ROOT_MNT_NAMESPACE, "/", RamFs::try_new().unwrap())
                .unwrap();
        }
        kernel_core::mount_namespace::register_destroy_callback(|id| VFS.remove_namespace_id(id));
    }

    #[test]
    fn ext2_description_outlives_last_namespace_and_releases_exact_owners() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        global_namespace_fixture();
        const COVERED: &str = "/ext2-namespace-covered";
        VFS.create_trusted(COVERED, FileMode::directory(0o755))
            .unwrap();
        let count = VFS.mount_tables.read().len();
        let resources = || {
            [
                HeapClass::Vfs,
                HeapClass::RamFs,
                HeapClass::CoreProcess,
                HeapClass::FilesystemIo,
                HeapClass::BlockingIo,
            ]
            .map(mm::heap_class_snapshot)
        };
        let cycle = || {
            let namespace = MountNamespace::new_child(ROOT_MNT_NAMESPACE.clone()).unwrap();
            let id = namespace.id();
            VFS.materialize_namespace(&namespace).unwrap();
            let (fs, device) = crate::devfs::block_geometry_tests::namespace_fixture();
            let weak = Arc::downgrade(&fs);
            VFS.mount_in_namespace(&namespace, COVERED, fs.clone())
                .unwrap();
            let open = |name: &str| {
                let fd = VFS
                    .open_with_resolve_using(
                        name,
                        OpenFlags::new(OpenFlags::O_RDONLY),
                        0,
                        ResolveFlags::empty(),
                        PreparedFileHandle::try_new,
                        VFS.trusted_context(&namespace).unwrap(),
                    )
                    .unwrap();
                finish_open(fd.as_ref()).unwrap();
                fd
            };
            let descriptor = open("/ext2-namespace-covered/held");
            let directory = open(COVERED);
            let original = descriptor.stat().unwrap();
            drop(fs);
            drop(namespace);
            assert_eq!(VFS.mount_tables.read().len(), count);
            assert!(!VFS.mount_tables.read().contains_key(&id));
            assert!(matches!(
                VFS.stat_trusted("/ext2-namespace-covered/held"),
                Err(FsError::NotFound)
            ));
            assert!(weak.upgrade().is_some());
            // Enumerating this real Ext2 directory performs uncached block I/O
            // through the owner retained solely by the open descriptions.
            let before = device.upgrade().unwrap().read_count();
            let handle = directory.as_any().downcast_ref::<FileHandle>().unwrap();
            let mut offset = 0;
            let mut found = false;
            while let Some((next, entry)) = handle.inode.readdir(offset).unwrap() {
                assert!(next > offset);
                found |= entry.name == "held" && entry.ino == original.ino;
                offset = next;
            }
            assert!(found);
            assert!(device.upgrade().unwrap().read_count() > before);
            drop(directory);
            // This is now the only filesystem owner. Nonempty regular reads
            // require kernel physical page-cache backing, unavailable hosted.
            // EOF still upgrades Weak<Ext2Fs> before returning, catching the
            // original inode-only-description lifetime failure directly.
            assert!(weak.upgrade().is_some());
            let stat = descriptor.stat().unwrap();
            assert_eq!(
                (stat.ino, stat.size, stat.mode),
                (original.ino, 0, original.mode)
            );
            let handle = descriptor.as_any().downcast_ref::<FileHandle>().unwrap();
            let bare_inode = handle.inode.clone();
            let mut output = [0xa5; 8];
            assert_eq!(handle.read(&mut output), Ok(0));
            assert_eq!(output, [0xa5; 8]);
            drop(descriptor);
            assert!(weak.upgrade().is_none());
            assert!(device.upgrade().is_none());
            // Negative control: an inode without its description owner cannot
            // upgrade the retired Ext2Fs, even for an empty read.
            assert_eq!(bare_inode.read_at(0, &mut output), Err(FsError::Invalid));
            drop(bare_inode);
            drop(weak);
            drop(device);
        };
        cycle(); // Warm bounded registry backing before exact steady-state checks.
        let baseline = resources();
        for _ in 0..8 {
            cycle();
            assert_eq!(resources(), baseline);
        }
    }

    #[test]
    fn real_namespace_drop_removes_exact_table_and_preserves_open_owner() {
        let _serial = crate::HEAP_TEST_LOCK.lock();
        global_namespace_fixture();
        // Exercise the production callback against its actual global registry.
        // Local Vfs instances deliberately do not pretend that callback owns them.
        // These real boot entrypoints run without a current PCB. Their trusted
        // staging and validation reads must execute every assertion, not skip.
        super::super::run_exec_read_file_self_test();
        super::super::run_rename_self_test();
        VFS.create_trusted("/namespace-covered", FileMode::directory(0o755))
            .unwrap();
        let count = VFS.mount_tables.read().len();
        let cycle = || {
            let namespace = MountNamespace::new_child(ROOT_MNT_NAMESPACE.clone()).unwrap();
            VFS.materialize_namespace(&namespace).unwrap();
            let id = namespace.id();
            let fs = RamFs::try_new().unwrap();
            let weak = Arc::downgrade(&fs);
            fs.create(
                &fs.root_inode(),
                "held",
                FileMode::regular(0o600),
                &topology::write().setup(0, 0),
            )
            .unwrap();
            VFS.mount_in_namespace(&namespace, "/namespace-covered", fs.clone())
                .unwrap();
            let descriptor = VFS
                .open_with_resolve_using(
                    "/namespace-covered/held",
                    OpenFlags::new(OpenFlags::O_RDONLY),
                    0,
                    ResolveFlags::empty(),
                    PreparedFileHandle::try_new,
                    VFS.trusted_context(&namespace).unwrap(),
                )
                .unwrap();
            finish_open(descriptor.as_ref()).unwrap();
            assert!(
                matches!(
                    VFS.unlink_trusted("/namespace-covered", Some(true)),
                    Err(FsError::Busy)
                ),
                "an edge in another live namespace must protect the exact covered object"
            );
            drop(fs);
            drop(namespace);
            assert_eq!(VFS.mount_tables.read().len(), count);
            assert!(!VFS.mount_tables.read().contains_key(&id));
            assert!(weak.upgrade().is_some());
            assert!(descriptor.stat().is_ok());
            VFS.remove_namespace_id(id); // rollback plus destruction is idempotent
            drop(descriptor);
            assert!(weak.upgrade().is_none());
        };
        cycle(); // Admit the bounded registry backing before steady-state measurement.
        let vfs_baseline = mm::heap_class_snapshot(HeapClass::Vfs);
        let ramfs_baseline = mm::heap_class_snapshot(HeapClass::RamFs);
        for _ in 0..32 {
            cycle();
        }
        assert_eq!(mm::heap_class_snapshot(HeapClass::Vfs), vfs_baseline);
        assert_eq!(mm::heap_class_snapshot(HeapClass::RamFs), ramfs_baseline);
    }
}
