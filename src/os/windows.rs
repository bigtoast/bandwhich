use ::std::collections::HashMap;

use libc::{c_uint, c_void, memcpy};

use ntapi::ntexapi::{
    NtQuerySystemInformation, 
    SystemProcessInformation, SYSTEM_PROCESS_INFORMATION,
    SystemHandleInformation, SYSTEM_HANDLE_INFORMATION,
};
use winapi::shared::minwindef::{DWORD, FALSE, FILETIME, MAX_PATH /*, TRUE, USHORT*/};
use winapi::um::processthreadsapi::{GetProcessTimes, OpenProcess, TerminateProcess};
use winapi::um::winnt::{
    HANDLE, /*, PWSTR*/ PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ,
    ULARGE_INTEGER, /*THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,*/
};
use winapi::um::psapi::{
    EnumProcessModulesEx, GetModuleBaseNameW, GetModuleFileNameExW, GetProcessMemoryInfo,
    LIST_MODULES_ALL, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};

use winapi::shared::ntdef::{PVOID, ULONG};
use winapi::shared::ntstatus::STATUS_INFO_LENGTH_MISMATCH;
use crate::network::{Connection, Protocol};
use crate::OpenSockets;

use sysinfo::{ Pid, System, SystemExt, ProcessExt};

//https://stackoverflow.com/questions/16262114/c-get-handle-of-open-sockets-of-a-program

/*
typedef struct _SYSTEM_HANDLE_INFORMATION {
   ULONG ProcessId;
   UCHAR ObjectTypeNumber;
   UCHAR Flags;
   USHORT Handle;
   PVOID Object;
   ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION;
*/

pub(crate) fn get_open_sockets() -> OpenSockets {
    let mut open_sockets = HashMap::new();
    let mut connections = std::vec::Vec::new();
    
    let mut sys = System::new();

    for (num, prc) in sys.get_process_list().iter() {
        println!("key {} id {} name {}", num, prc.name(), prc.pid());
    }
    OpenSockets {
        sockets_to_procs: open_sockets,
        connections,
    } 
}

unsafe fn get_process_name(process_handler: HANDLE, h_mod: *mut c_void) -> String {
    let mut process_name = [0u16; MAX_PATH + 1];

    GetModuleBaseNameW(
        process_handler,
        h_mod as _,
        process_name.as_mut_ptr(),
        MAX_PATH as DWORD + 1,
    );
    let mut pos = 0;
    for x in process_name.iter() {
        if *x == 0 {
            break;
        }
        pos += 1;
    }
    String::from_utf16_lossy(&process_name[..pos])
}

fn get_process_handle_information(pid: Pid) {
    // Windows 10 notebook requires at least 512KiB of memory to make it in one go
    let mut buffer_size: usize = 512 * 1024;
    let mut handle_information: Vec<u8> = Vec::with_capacity(buffer_size);
    let mut cb_needed = 0;

    let ntstatus = unsafe {
        handle_information.set_len(buffer_size);
        NtQuerySystemInformation(
            SystemHandleInformation,
            handle_information.as_mut_ptr() as PVOID,
            buffer_size as ULONG,
            &mut cb_needed,
        )
    };

    if ntstatus != STATUS_INFO_LENGTH_MISMATCH {
        if ntstatus < 0 {
            eprintln!(
                "Couldn't get handle infos: NtQuerySystemInformation returned {}",
                ntstatus
            );
        }

        // Parse the data block to get process information
        let mut process_ids = Vec::with_capacity(500);
        let mut handle_information_offset = 0;
        loop {
            let p = unsafe {
                handle_information
                    .as_ptr()
                    .offset(handle_information_offset)
                    as *const SYSTEM_HANDLE_INFORMATION
            };
            let pi = unsafe { &*p };

            //process_ids.push(Wrap(p));
            process_ids.push(p);

            if pi.NextEntryOffset == 0 {
                break;
            }

            process_information_offset += pi.NextEntryOffset as isize;
        }
}

//fn refresh_processes(&mut self) {
fn get_process_handler(pid: Pid) -> Option<HANDLE> {
    if pid == 0 {
        return None;
    }
    let options = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE;
    let process_handler = unsafe { OpenProcess(options, FALSE, pid as DWORD) };
    if process_handler.is_null() {
        let options = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        let process_handler = unsafe { OpenProcess(options, FALSE, pid as DWORD) };
        if process_handler.is_null() {
            None
        } else {
            Some(process_handler)
        }
    } else {
        Some(process_handler)
    }
}

fn refresh_processes(){
    // Windows 10 notebook requires at least 512KiB of memory to make it in one go
    let mut buffer_size: usize = 512 * 1024;
    //let mut process_list: HashMap<

    loop {
        let mut process_information: Vec<u8> = Vec::with_capacity(buffer_size);

        let mut cb_needed = 0;
        let ntstatus = unsafe {
            process_information.set_len(buffer_size);
            NtQuerySystemInformation(
                SystemProcessInformation,
                process_information.as_mut_ptr() as PVOID,
                buffer_size as ULONG,
                &mut cb_needed,
            )
        };

        if ntstatus != STATUS_INFO_LENGTH_MISMATCH {
            if ntstatus < 0 {
                eprintln!(
                    "Couldn't get process infos: NtQuerySystemInformation returned {}",
                    ntstatus
                );
            }

            // Parse the data block to get process information
            let mut process_ids = Vec::with_capacity(500);
            let mut process_information_offset = 0;
            loop {
                let p = unsafe {
                    process_information
                        .as_ptr()
                        .offset(process_information_offset)
                        as *const SYSTEM_PROCESS_INFORMATION
                };
                let pi = unsafe { &*p };

                //process_ids.push(Wrap(p));
                process_ids.push(p);

                if pi.NextEntryOffset == 0 {
                    break;
                }

                process_information_offset += pi.NextEntryOffset as isize;
            }
            /*
            let nb_processors = self.processors.len() as u64;
            let process_list = Wrap(UnsafeCell::new(&mut self.process_list));
            let system_time = get_system_computation_time();
            // TODO: instead of using parallel iterator only here, would be better to be able
            //       to run it over `process_information` directly!
            let processes = process_ids
                .into_par_iter()
                .filter_map(|pi| unsafe {
                    let pi = *pi.0;
                    let pid = pi.UniqueProcessId as usize;
                    if let Some(proc_) = (*process_list.0.get()).get_mut(&pid) {
                        proc_.memory = (pi.WorkingSetSize as u64) >> 10u64;
                        proc_.virtual_memory = (pi.VirtualSize as u64) >> 10u64;
                        compute_cpu_usage(proc_, nb_processors, system_time);
                        proc_.updated = true;
                        return None;
                    }
                    let name = get_process_name(&pi, pid);
                    let mut p = Process::new_full(
                        pid,
                        if pi.InheritedFromUniqueProcessId as usize != 0 {
                            Some(pi.InheritedFromUniqueProcessId as usize)
                        } else {
                            None
                        },
                        (pi.WorkingSetSize as u64) >> 10u64,
                        (pi.VirtualSize as u64) >> 10u64,
                        name,
                    );
                    compute_cpu_usage(&mut p, nb_processors, system_time);
                    Some(p)
                })
                .collect::<Vec<_>>();*/
            /*self.process_list.retain(|_, v| {            
                let x = v.updated;
                v.updated = false;
                x
            });*/
            /*for p in processes.into_iter() {
                self.process_list.insert(p.pid(), p);
            }*/

            break;
        }

        // GetNewBufferSize
        if cb_needed == 0 {
            buffer_size *= 2;
            continue;
        }
        // allocating a few more kilo bytes just in case there are some new process
        // kicked in since new call to NtQuerySystemInformation
        buffer_size = (cb_needed + (1024 * 10)) as usize;
    }
}
    