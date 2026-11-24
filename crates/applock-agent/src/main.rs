//! AppLock user-session agent binary (foundation stub).

use applock_core::runtime_summary;
use applock_ipc::PROTOCOL_VERSION;
use applock_sys::current_process_id;

fn main() {
    let (proto, pid) = runtime_summary();
    let _ = (proto, pid, PROTOCOL_VERSION, current_process_id());
}
