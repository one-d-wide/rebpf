use iced::{advanced::widget::operation::Operation, widget};
use std::{
    collections::{BTreeMap, HashSet},
    ffi::CStr,
    os::unix::ffi::OsStrExt,
};

#[allow(unused)]
pub fn procs_all() -> BTreeMap<String, u32> {
    procs_all_with(&mut |_| true, usize::MAX)
}

pub fn procs_all_with(
    filter: &mut dyn FnMut(&str) -> bool,
    max_len: usize,
) -> BTreeMap<String, u32> {
    let mut res = BTreeMap::new();
    for ent in std::fs::read_dir("/proc").unwrap() {
        if res.len() >= max_len {
            break;
        }
        let ent = ent.unwrap();
        if !ent.file_name().as_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let path = ent.path().join("exe");
        let exe = path.read_link();
        let exe = match exe {
            Ok(exe) => exe.to_string_lossy().to_string(),
            Err(err) => {
                log::debug!("Can't sweep {path:?}: {err}");
                continue;
            }
        };
        if !filter(&exe) {
            continue;
        }
        *res.entry(exe).or_insert(0) += 1;
    }
    res
}

pub fn ifnames() -> HashSet<String> {
    let mut h = HashSet::new();
    unsafe {
        let mut first: *mut libc::ifaddrs = std::mem::zeroed();
        if libc::getifaddrs(&mut first as *mut *mut libc::ifaddrs) != 0 {
            return h;
        }

        let mut next = first;
        while next != std::mem::zeroed() {
            h.insert(
                CStr::from_ptr((*next).ifa_name)
                    .to_string_lossy()
                    .to_string(),
            );
            next = (*next).ifa_next;
        }
        libc::freeifaddrs(first);
    }
    h
}

pub struct DoUnfocus(pub widget::Id);
impl Operation<message::M> for DoUnfocus {
    fn focusable(
        &mut self,
        id: Option<&widget::Id>,
        _bounds: iced::Rectangle,
        state: &mut dyn iced::advanced::widget::operation::Focusable,
    ) {
        if matches!(id, Some(id) if id == &self.0) {
            state.unfocus();
        }
    }

    fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn Operation<message::M>)) {
        operate(self);
    }
}
