//! AppLock background Windows service binary (foundation stub).

use applock_core::runtime_summary;
use applock_ipc::MAX_MESSAGE_BYTES;
use applock_sys::current_process_id;

fn main() {
    let (proto, pid) = runtime_summary();
    let _ = (proto, pid, MAX_MESSAGE_BYTES, current_process_id());
}
