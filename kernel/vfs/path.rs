//! Object-based mount traversal and process-root confinement.
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use kernel_core::fs_context::{FsContextState, FsDirectoryHandle};
use mm::{arc_charge_bytes, try_reserve_heap, AdmittedMap, AdmittedVec, HeapCharge, HeapClass};
use spin::RwLock;

use crate::context::OperationContext;
use crate::topology::{Edge, Retirement};
use crate::traits::{FileSystem, Inode};
use crate::types::{FsError, ResolveFlags};

static NEXT_MOUNT: AtomicU64 = AtomicU64::new(1);
static NEXT_ROOT_EPOCH: AtomicU64 = AtomicU64::new(1);
const MAX_ANCESTORS: usize = 4096;
pub(crate) const MAX_ROOT_TRANSITIONS: usize = 256;

pub(crate) fn next_root_epoch() -> Result<u64, FsError> {
    allocate_root_epoch(&NEXT_ROOT_EPOCH)
}

fn allocate_root_epoch(counter: &AtomicU64) -> Result<u64, FsError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |epoch| {
            epoch.checked_add(1)
        })
        .map_err(|_| FsError::NoMem)
}

fn charge_arc<T>() -> Result<HeapCharge, FsError> {
    try_reserve_heap(
        HeapClass::Vfs,
        arc_charge_bytes::<T>().map_err(|_| FsError::NoMem)?,
    )
    .map_err(|_| FsError::NoMem)?
    .commit()
    .map_err(|_| FsError::NoMem)
}

pub(crate) struct Mount {
    pub id: u64,
    pub fs: Arc<dyn FileSystem>,
    pub covered: Option<Arc<dyn Inode>>,
    pub parent: Option<Edge<Mount>>,
    _charge: HeapCharge,
}

impl Mount {
    pub fn try_new(
        fs: Arc<dyn FileSystem>,
        covered: Option<&ResolvedPath>,
        retirement: &Arc<Retirement<Mount>>,
    ) -> Result<Arc<Self>, FsError> {
        let id = NEXT_MOUNT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| FsError::NoSpace)?;
        Self::try_represent(id, fs, covered, retirement)
    }

    /// Preserve the mounted object's ID while replacing its immutable ancestry.
    /// The caller supplies only owners from the replacement graph.
    pub(crate) fn try_represent(
        id: u64,
        fs: Arc<dyn FileSystem>,
        covered: Option<&ResolvedPath>,
        retirement: &Arc<Retirement<Mount>>,
    ) -> Result<Arc<Self>, FsError> {
        let parent = covered
            .map(|path| Edge::try_new(path.mount.clone(), retirement))
            .transpose()?;
        let covered = covered.map(|path| path.inode.clone());
        Arc::try_new(Self {
            id,
            fs,
            covered,
            parent,
            _charge: charge_arc::<Self>()?,
        })
        .map_err(|_| FsError::NoMem)
    }

    pub fn root(self: &Arc<Self>, epoch: u64) -> ResolvedPath {
        ResolvedPath {
            mount: self.clone(),
            inode: self.fs.root_inode(),
            epoch,
        }
    }
}

pub(crate) struct MountView {
    pub mounts: AdmittedMap<u64, Arc<Mount>>,
    pub root: Option<u64>,
    pub epoch: u64,
    pub transitions: AdmittedVec<RootTransition>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathIdentity {
    mount: u64,
    filesystem: u64,
    inode: u64,
}

impl PathIdentity {
    fn of(path: &ResolvedPath) -> Self {
        Self {
            mount: path.mount.id,
            filesystem: path.inode.fs_id(),
            inode: path.inode.ino(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RootTransition {
    pub epoch: u64,
    old: PathIdentity,
    new: PathIdentity,
}

impl RootTransition {
    pub(crate) fn new(epoch: u64, old: &ResolvedPath, new: &ResolvedPath) -> Self {
        Self {
            epoch,
            old: PathIdentity::of(old),
            new: PathIdentity::of(new),
        }
    }
}

impl MountView {
    pub(crate) fn empty() -> Self {
        Self {
            mounts: AdmittedMap::new(HeapClass::Vfs),
            root: None,
            epoch: 0,
            transitions: AdmittedVec::new(HeapClass::Vfs),
        }
    }

    pub(crate) fn root_path(&self) -> Result<ResolvedPath, FsError> {
        Ok(self
            .mounts
            .get(&self.root.ok_or(FsError::NotFound)?)
            .ok_or(FsError::NotFound)?
            .root(self.epoch))
    }

    /// A removed mount still belongs to its saved handle. Only active IDs are
    /// canonicalized; each later upward crossing repeats this check.
    pub(crate) fn canonical(&self, path: &ResolvedPath) -> Result<ResolvedPath, FsError> {
        let mount = self.mounts.get(&path.mount.id).unwrap_or(&path.mount);
        if !Arc::ptr_eq(&mount.fs, &path.mount.fs) || path.inode.fs_id() != mount.fs.fs_id() {
            return Err(FsError::CrossDev);
        }
        Ok(ResolvedPath {
            mount: mount.clone(),
            inode: path.inode.clone(),
            epoch: self.epoch,
        })
    }

    pub(crate) fn prepare_pivot(
        &self,
        new_root: &ResolvedPath,
        put_old: &ResolvedPath,
        retirement: &Arc<Retirement<Mount>>,
    ) -> Result<Self, FsError> {
        if self.transitions.len() >= MAX_ROOT_TRANSITIONS {
            return Err(FsError::NoMem);
        }
        let old_root = self.root_path()?;
        let epoch = next_root_epoch()?;
        let mut next = Self::empty();
        next.mounts
            .try_reserve(self.mounts.len())
            .map_err(|_| FsError::NoMem)?;
        next.transitions
            .try_reserve_exact(self.transitions.len() + 1)
            .map_err(|_| FsError::NoMem)?;
        for transition in &self.transitions {
            next.transitions
                .push_reserved(*transition)
                .map_err(|_| FsError::NoMem)?;
        }
        next.transitions
            .push_reserved(RootTransition::new(epoch, &old_root, new_root))
            .map_err(|_| FsError::NoMem)?;
        next.epoch = epoch;
        next.root = Some(new_root.mount.id);
        let root = Mount::try_represent(
            new_root.mount.id,
            new_root.mount.fs.clone(),
            None,
            retirement,
        )?;
        next.mounts
            .try_insert(root.id, root)
            .map_err(|_| FsError::NoMem)?;
        while next.mounts.len() < self.mounts.len() {
            let before = next.mounts.len();
            for (id, source) in self.mounts.iter() {
                if next.mounts.contains_key(id) {
                    continue;
                }
                let (parent_id, covered) = if *id == old_root.mount.id {
                    (new_root.mount.id, put_old.inode.clone())
                } else {
                    (
                        source.parent.as_ref().ok_or(FsError::Invalid)?.id,
                        source.covered.as_ref().ok_or(FsError::Invalid)?.clone(),
                    )
                };
                let Some(parent) = next.mounts.get(&parent_id) else {
                    continue;
                };
                if covered.fs_id() != parent.fs.fs_id() {
                    return Err(FsError::CrossDev);
                }
                let attachment = ResolvedPath {
                    mount: parent.clone(),
                    inode: covered,
                    epoch,
                };
                let replacement =
                    Mount::try_represent(*id, source.fs.clone(), Some(&attachment), retirement)?;
                next.mounts
                    .try_insert(*id, replacement)
                    .map_err(|_| FsError::NoMem)?;
            }
            // Every pass either installs at least one mount or identifies a
            // cycle/missing parent. No new edge ever targets the old graph.
            if before == next.mounts.len() {
                return Err(FsError::Invalid);
            }
        }
        Ok(next)
    }
}

pub(crate) struct NamespaceMountTable {
    pub view: RwLock<MountView>,
    _charge: HeapCharge,
}

impl NamespaceMountTable {
    pub fn try_new(parent: Option<&Self>) -> Result<Arc<Self>, FsError> {
        let mut view = MountView::empty();
        if let Some(parent) = parent {
            let source = parent.view.read();
            view.mounts
                .try_reserve(source.mounts.len())
                .map_err(|_| FsError::NoMem)?;
            for (id, mount) in source.mounts.iter() {
                view.mounts
                    .try_insert(*id, mount.clone())
                    .map_err(|_| FsError::NoMem)?;
            }
            view.root = source.root;
            view.epoch = source.epoch;
            view.transitions =
                AdmittedVec::try_copy_from_slice(HeapClass::Vfs, &source.transitions)
                    .map_err(|_| FsError::NoMem)?;
        }
        Arc::try_new(Self {
            view: RwLock::new(view),
            _charge: charge_arc::<Self>()?,
        })
        .map_err(|_| FsError::NoMem)
    }

    pub fn root(&self) -> Result<ResolvedPath, FsError> {
        let view = self.view.read();
        view.root_path()
    }
}

#[derive(Clone)]
pub(crate) struct ResolvedPath {
    pub mount: Arc<Mount>,
    pub inode: Arc<dyn Inode>,
    /// Epoch of the guarded namespace view that selected this path.
    pub epoch: u64,
}

impl ResolvedPath {
    pub fn same(&self, other: &Self) -> bool {
        self.mount.id == other.mount.id
            && self.inode.fs_id() == other.inode.fs_id()
            && self.inode.ino() == other.inode.ino()
    }

    pub fn directory_handle(&self) -> Result<Arc<dyn FsDirectoryHandle>, FsError> {
        if !self.inode.is_dir() {
            return Err(FsError::NotDir);
        }
        let handle = DirectoryHandle {
            path: self.clone(),
            _charge: charge_arc::<DirectoryHandle>()?,
        };
        Arc::try_new(handle)
            .map(|handle| handle as Arc<dyn FsDirectoryHandle>)
            .map_err(|_| FsError::NoMem)
    }
}

struct DirectoryHandle {
    path: ResolvedPath,
    _charge: HeapCharge,
}

impl FsDirectoryHandle for DirectoryHandle {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(crate) fn handle_path(
    handle: &Option<Arc<dyn FsDirectoryHandle>>,
    view: &MountView,
) -> Result<ResolvedPath, FsError> {
    let original = handle
        .as_ref()
        .and_then(|handle| handle.as_any().downcast_ref::<DirectoryHandle>())
        .map(|handle| handle.path.clone())
        .ok_or(FsError::PermDenied)?;
    let mut identity = PathIdentity::of(&original);
    for transition in &view.transitions {
        if transition.epoch > original.epoch && transition.old == identity {
            identity = transition.new;
        }
    }
    if identity != PathIdentity::of(&original) {
        // Once a saved root transforms, every later pivot remaps that root
        // again. The final identity is always the active namespace root; the
        // bounded history needs no owners of obsolete mount graphs.
        let root = view.root_path()?;
        if identity != PathIdentity::of(&root) {
            return Err(FsError::CrossDev);
        }
        return Ok(root);
    }
    view.canonical(&original)
}

pub(crate) fn initial_state(path: &ResolvedPath) -> Result<FsContextState, FsError> {
    let root = path.directory_handle()?;
    Ok(FsContextState {
        root: Some(root.clone()),
        cwd: Some(root),
        generation: 0,
    })
}

#[derive(Clone, Copy)]
pub(crate) enum FinalLink {
    Follow,
    Return,
    Reject,
}

pub(crate) enum Resolution {
    Found(ResolvedPath),
    Missing { parent: ResolvedPath, name: String },
}

impl Resolution {
    pub fn found(self) -> Result<ResolvedPath, FsError> {
        match self {
            Self::Found(path) => Ok(path),
            Self::Missing { .. } => Err(FsError::NotFound),
        }
    }
}

fn validate_path(path: &str) -> Result<(), FsError> {
    if path.is_empty() {
        return Err(FsError::NotFound);
    }
    if path.len() > 4096 {
        return Err(FsError::NameTooLong);
    }
    if path.contains('\0') {
        return Err(FsError::Invalid);
    }
    Ok(())
}

fn cross_down(
    mut path: ResolvedPath,
    view: &MountView,
    context: &OperationContext,
    no_xdev: bool,
) -> Result<ResolvedPath, FsError> {
    for _ in 0..crate::mount_namespace::MAX_MOUNTS_PER_NS {
        let crossing = view.mounts.values().find(|mount| {
            mount.parent.as_ref().map(|edge| edge.id) == Some(path.mount.id)
                && mount
                    .covered
                    .as_ref()
                    .map(|inode| (inode.fs_id(), inode.ino()))
                    == Some((path.inode.fs_id(), path.inode.ino()))
        });
        let Some(mount) = crossing else {
            return Ok(path);
        };
        if no_xdev {
            return Err(FsError::CrossDev);
        }
        if !context.permits(&path.inode.stat()?, false, false, true) {
            return Err(FsError::PermDenied);
        }
        path = mount.root(view.epoch);
    }
    Err(FsError::SymlinkLoop)
}

/// Return current parent/name, including the *covered object's current* ancestry
/// at a mount root. Retained detached parents are usable for `..`, but getcwd
/// demands every edge be attached and visible in the pinned namespace view.
fn parent(
    path: &ResolvedPath,
    boundary: &ResolvedPath,
    view: &MountView,
    visible: bool,
    no_xdev: bool,
) -> Result<Option<(ResolvedPath, String, bool)>, FsError> {
    if path.same(boundary) {
        return Ok(None);
    }
    let mut path = view.canonical(path)?;
    if path.inode.ino() == path.mount.fs.root_inode().ino() {
        let Some(edge) = path.mount.parent.as_ref() else {
            return Ok(None);
        };
        if no_xdev {
            return Err(FsError::CrossDev);
        }
        if visible && !view.mounts.contains_key(&path.mount.id) {
            return Err(FsError::NotFound);
        }
        let covered = path.mount.covered.as_ref().ok_or(FsError::Invalid)?.clone();
        path = ResolvedPath {
            mount: edge.target().clone(),
            inode: covered,
            epoch: view.epoch,
        };
        path = view.canonical(&path)?;
        if path.same(boundary) {
            return Ok(Some((path, String::new(), true)));
        }
    }
    let Some(observed) = path.mount.fs.directory_parent(&path.inode)? else {
        return Ok(None);
    };
    if visible && !observed.attached {
        return Err(FsError::NotFound);
    }
    Ok(Some((
        ResolvedPath {
            mount: path.mount,
            inode: observed.inode,
            epoch: view.epoch,
        },
        observed.name,
        observed.attached,
    )))
}

pub(crate) fn is_beneath(
    path: &ResolvedPath,
    root: &ResolvedPath,
    view: &MountView,
    visible: bool,
) -> Result<bool, FsError> {
    let mut path = path.clone();
    for _ in 0..MAX_ANCESTORS {
        if path.same(root) {
            return Ok(true);
        }
        let Some((up, _, _)) = parent(&path, root, view, visible, false)? else {
            return Ok(false);
        };
        if up.same(&path) {
            return Err(FsError::Invalid);
        }
        path = up;
    }
    Err(FsError::NameTooLong)
}

pub(crate) fn render_cwd(context: &OperationContext, view: &MountView) -> Result<String, FsError> {
    let root = handle_path(&context.fs.root, view)?;
    let mut path = handle_path(&context.fs.cwd, view)?;
    let mut rendered = String::new();
    for _ in 0..MAX_ANCESTORS {
        if path.same(&root) {
            if rendered.is_empty() {
                rendered.try_reserve_exact(1).map_err(|_| FsError::NoMem)?;
                rendered.push('/');
            }
            return Ok(rendered);
        }
        let Some((up, name, _)) = parent(&path, &root, view, true, false)? else {
            return Err(FsError::NotFound);
        };
        if !name.is_empty() {
            let length = rendered
                .len()
                .checked_add(name.len() + 1)
                .ok_or(FsError::NameTooLong)?;
            if length > 4096 {
                return Err(FsError::NameTooLong);
            }
            let mut next = String::new();
            next.try_reserve_exact(length).map_err(|_| FsError::NoMem)?;
            next.push('/');
            next.push_str(&name);
            next.push_str(&rendered);
            rendered = next;
        }
        if up.same(&path) {
            return Err(FsError::Invalid);
        }
        path = up;
    }
    Err(FsError::NameTooLong)
}

pub(crate) fn resolve(
    context: &OperationContext,
    view: &MountView,
    input: &str,
    flags: ResolveFlags,
    final_link: FinalLink,
    allow_missing: bool,
) -> Result<Resolution, FsError> {
    validate_path(input)?;
    if flags.bits() & !0x3f != 0 || (flags.beneath() && flags.in_root()) {
        return Err(FsError::Invalid);
    }
    if flags.bits() & ResolveFlags::RESOLVE_CACHED != 0 {
        return Err(FsError::Again);
    }
    if flags.beneath() && input.starts_with('/') {
        return Err(FsError::CrossDev);
    }
    let root = handle_path(&context.fs.root, view)?;
    let cwd = handle_path(&context.fs.cwd, view)?;
    if (!input.starts_with('/') || flags.beneath() || flags.in_root())
        && !is_beneath(&cwd, &root, view, false)?
    {
        return Err(FsError::PermDenied);
    }
    let boundary = if flags.beneath() || flags.in_root() {
        cwd.clone()
    } else {
        root.clone()
    };
    let initial = if input.starts_with('/') {
        boundary.clone()
    } else {
        cwd
    };
    // A stored cwd/root is already an exact mount/inode capability. A later
    // overmount must not retarget it; only a name lookup enters a mount edge.
    let mut current = initial;
    let mut pending = crate::types::try_dirent_name(input)?;
    let mut cursor = 0;
    let mut symlinks = 0;
    loop {
        while pending.as_bytes().get(cursor) == Some(&b'/') {
            cursor += 1;
        }
        if cursor == pending.len() {
            if pending.ends_with('/') && !current.inode.is_dir() {
                return Err(FsError::NotDir);
            }
            return Ok(Resolution::Found(current));
        }
        let end = pending[cursor..]
            .find('/')
            .map(|end| cursor + end)
            .unwrap_or(pending.len());
        let component = &pending[cursor..end];
        let rest = pending[end..].trim_start_matches('/');
        let is_last = rest.is_empty();
        let trailing_slash = is_last && end < pending.len();
        if !current.inode.is_dir() {
            return Err(FsError::NotDir);
        }
        if !context.permits(&current.inode.stat()?, false, false, true) {
            return Err(FsError::PermDenied);
        }
        if component.len() > 255 {
            return Err(FsError::NameTooLong);
        }
        if component == "." {
            cursor = end;
            continue;
        }
        if component == ".." {
            if current.same(&boundary) {
                if flags.beneath() {
                    return Err(FsError::CrossDev);
                }
            } else if let Some((up, _, _)) =
                parent(&current, &boundary, view, false, flags.no_xdev())?
            {
                current = up;
            } else if flags.beneath() {
                return Err(FsError::CrossDev);
            }
            cursor = end;
            continue;
        }
        let inode = match current.mount.fs.lookup(&current.inode, component) {
            Ok(inode) => inode,
            Err(FsError::NotFound) if allow_missing && is_last && !trailing_slash => {
                return Ok(Resolution::Missing {
                    parent: current,
                    name: crate::types::try_dirent_name(component)?,
                });
            }
            Err(error) => return Err(error),
        };
        if inode.fs_id() != current.mount.fs.fs_id() {
            return Err(FsError::CrossDev);
        }
        let next = cross_down(
            ResolvedPath {
                mount: current.mount.clone(),
                inode,
                epoch: view.epoch,
            },
            view,
            context,
            flags.no_xdev(),
        )?;
        if next.inode.is_symlink() {
            if flags.no_symlinks() || (flags.no_magiclinks() && next.mount.fs.fs_type() == "proc") {
                return Err(FsError::SymlinkLoop);
            }
            if is_last && !trailing_slash {
                match final_link {
                    FinalLink::Return => return Ok(Resolution::Found(next)),
                    FinalLink::Reject => return Err(FsError::SymlinkLoop),
                    FinalLink::Follow => {}
                }
            }
            symlinks += 1;
            if symlinks > 40 {
                return Err(FsError::SymlinkLoop);
            }
            let stat = next.inode.stat()?;
            if stat.size > 4096 {
                return Err(FsError::NameTooLong);
            }
            let mut bytes = alloc::vec::Vec::new();
            bytes.try_reserve_exact(4097).map_err(|_| FsError::NoMem)?;
            bytes.resize(4097, 0);
            let length = next.inode.read_at(0, &mut bytes)?;
            if length >= bytes.len() {
                return Err(FsError::NameTooLong);
            }
            let target = core::str::from_utf8(&bytes[..length]).map_err(|_| FsError::Invalid)?;
            validate_path(target)?;
            if target.starts_with('/') {
                if flags.beneath() {
                    return Err(FsError::CrossDev);
                }
                if flags.no_xdev() && next.mount.id != boundary.mount.id {
                    return Err(FsError::CrossDev);
                }
                current = boundary.clone();
            }
            let mut expanded = String::new();
            let length = target
                .len()
                .checked_add(rest.len() + usize::from(end < pending.len()))
                .ok_or(FsError::NameTooLong)?;
            if length > 4096 {
                return Err(FsError::NameTooLong);
            }
            expanded
                .try_reserve_exact(length)
                .map_err(|_| FsError::NoMem)?;
            expanded.push_str(target);
            if end < pending.len() {
                expanded.push('/');
                expanded.push_str(rest);
            }
            pending = expanded;
            cursor = 0;
        } else {
            current = next;
            cursor = end;
        }
    }
}

pub(crate) fn resolve_parent(
    context: &OperationContext,
    view: &MountView,
    path: &str,
) -> Result<(ResolvedPath, String, bool), FsError> {
    validate_path(path)?;
    let trailing = path.ends_with('/');
    let trimmed = path.trim_end_matches('/');
    let (prefix, name) = match trimmed.rsplit_once('/') {
        Some(("", name)) => ("/", name),
        Some(pair) => pair,
        None => (".", trimmed),
    };
    if name.is_empty() {
        return Err(FsError::Busy);
    }
    if name == "." || name == ".." {
        return Err(FsError::Invalid);
    }
    if name.len() > 255 {
        return Err(FsError::NameTooLong);
    }
    let parent = resolve(
        context,
        view,
        prefix,
        ResolveFlags::empty(),
        FinalLink::Follow,
        false,
    )?
    .found()?;
    if !parent.inode.is_dir() {
        return Err(FsError::NotDir);
    }
    if !context.permits(&parent.inode.stat()?, false, false, true) {
        return Err(FsError::PermDenied);
    }
    Ok((parent, crate::types::try_dirent_name(name)?, trailing))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_epoch_exhaustion_never_wraps_or_reuses_a_selection() {
        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(allocate_root_epoch(&counter), Ok(u64::MAX - 1));
        for _ in 0..3 {
            assert_eq!(allocate_root_epoch(&counter), Err(FsError::NoMem));
            assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        }
    }
}
