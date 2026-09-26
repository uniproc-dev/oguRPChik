use ::windows::core::GUID;
use serde::Deserialize;
use uuid::Uuid;

pub fn uuid_to_guid(u: Uuid) -> GUID {
    let fields = u.as_fields();
    GUID::from_values(fields.0, fields.1, fields.2, *fields.3)
}
pub fn guid_to_uuid(u: GUID) -> Uuid {
    let v = u.to_u128();
    Uuid::from_u128(v)
}

pub fn get_best_vmid() -> std::io::Result<GUID> {
    let vms = match enumerate_compute_systems("{}") {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return get_wsl_vmid_by_reg()
                .and_then(|opt| {
                    opt.ok_or_else(|| {
                        std::io::Error::new(std::io::ErrorKind::NotFound, "No VM found in registry")
                    })
                })
                .map(uuid_to_guid);
        }
        Err(e) => return Err(e),
    };

    best_vm(&vms).map(uuid_to_guid).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No compute system with a usable VM id found",
        )
    })
}

fn best_vm(vms: &[ComputeSystem]) -> Option<Uuid> {
    vms.iter()
        .filter(|vm| vm.owner == "WSL")
        .chain(vms.iter())
        .find_map(ComputeSystem::vm_id)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ComputeSystem {
    #[serde(default)]
    id: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    runtime_id: String,
}

impl ComputeSystem {
    fn vm_id(&self) -> Option<Uuid> {
        self.runtime_id
            .parse()
            .ok()
            .or_else(|| self.id.parse().ok())
    }
}

fn parse_compute_systems(json: &str) -> std::io::Result<Vec<ComputeSystem>> {
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(json)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

fn enumerate_compute_systems(query: &str) -> std::io::Result<Vec<ComputeSystem>> {
    use std::io::{Error, ErrorKind};
    use widestring::WideCString;
    use winapi::shared::minwindef::LPVOID;
    use winapi::shared::ntdef::{LPCWSTR, LPWSTR};
    use winapi::um::combaseapi::CoTaskMemFree;
    use winapi::um::libloaderapi::{FreeLibrary, GetProcAddress, LoadLibraryA};

    unsafe {
        let module = LoadLibraryA(b"vmcompute.dll\0".as_ptr() as _);
        if module.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        let func = GetProcAddress(module, b"HcsEnumerateComputeSystems\0".as_ptr() as _);
        if func.is_null() {
            FreeLibrary(module);
            return Err(std::io::Error::last_os_error());
        }

        let func: unsafe extern "C" fn(
            query: LPCWSTR,
            compute_systems: &mut LPWSTR,
            result: &mut LPWSTR,
        ) -> i32 = std::mem::transmute(func);

        let query =
            WideCString::from_str(query).map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;
        let mut compute_systems: LPWSTR = std::ptr::null_mut();
        let mut result: LPWSTR = std::ptr::null_mut();

        let hr = func(query.as_ptr(), &mut compute_systems, &mut result);

        let compute_systems = if compute_systems.is_null() {
            String::new()
        } else {
            let str = WideCString::from_ptr_str(compute_systems)
                .to_string()
                .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;
            CoTaskMemFree(compute_systems as LPVOID);
            str
        };

        CoTaskMemFree(result as LPVOID);
        FreeLibrary(module);

        if hr != 0 {
            let err = Error::from_raw_os_error(hr);
            if hr == 0x8037011Bu32 as i32 {
                return Err(Error::new(ErrorKind::PermissionDenied, err));
            }
            return Err(err);
        }

        parse_compute_systems(&compute_systems)
    }
}

fn get_wsl_vmid_by_hcs() -> std::io::Result<Option<Uuid>> {
    let vms = enumerate_compute_systems("{}")?;
    Ok(vms
        .iter()
        .filter(|vm| vm.owner == "WSL")
        .find_map(ComputeSystem::vm_id))
}

pub fn get_wsl_vmid_by_reg() -> std::io::Result<Option<Uuid>> {
    let list = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\HostComputeService\VolatileStore\ComputeSystem")?;
    for k in list.enum_keys() {
        let k = k?;
        let subkey = list.open_subkey(&k)?;
        let ty: u32 = match subkey.get_value("ComputeSystemType") {
            Ok(v) => v,
            Err(_) => continue,
        };
        if ty == 2 {
            if let Ok(v) = k.parse() {
                return Ok(Some(v));
            }
        }
    }
    Ok(None)
}

pub fn get_wsl_vmid() -> std::io::Result<Option<Uuid>> {
    match get_wsl_vmid_by_hcs() {
        Ok(v) => return Ok(v),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => (),
        Err(err) => return Err(err),
    }
    get_wsl_vmid_by_reg()
}

#[cfg(test)]
mod tests {
    use super::*;

    const WSL: &str = "c6de7088-6992-4adf-8038-5984755d5412";
    const COWORK_RUNTIME: &str = "ed4d837e-aa16-57c4-9c8a-d1027b76533a";

    fn listing(entries: &[(&str, &str, &str)]) -> String {
        let entries: Vec<String> = entries
            .iter()
            .map(|(id, owner, runtime_id)| {
                format!(
                    r#"{{"Id":"{id}","SystemType":"VirtualMachine","Name":"{id}","Owner":"{owner}","RuntimeId":"{runtime_id}","State":"Running"}}"#
                )
            })
            .collect();
        format!("[{}]", entries.join(","))
    }

    fn best(json: &str) -> Option<Uuid> {
        best_vm(&parse_compute_systems(json).unwrap())
    }

    #[test]
    fn a_compute_system_with_a_non_uuid_id_does_not_hide_wsl() {
        let json = listing(&[
            ("cowork-vm-45f50555", "cowork-vm-45f50555", COWORK_RUNTIME),
            (WSL, "WSL", WSL),
        ]);
        assert_eq!(best(&json), Some(WSL.parse().unwrap()));
    }

    #[test]
    fn wsl_wins_wherever_it_is_listed() {
        let json = listing(&[
            (WSL, "WSL", WSL),
            ("cowork-vm-45f50555", "cowork-vm-45f50555", COWORK_RUNTIME),
        ]);
        assert_eq!(best(&json), Some(WSL.parse().unwrap()));
    }

    #[test]
    fn without_wsl_the_runtime_id_addresses_the_vm() {
        let json = listing(&[("cowork-vm-45f50555", "cowork-vm-45f50555", COWORK_RUNTIME)]);
        assert_eq!(best(&json), Some(COWORK_RUNTIME.parse().unwrap()));
    }

    #[test]
    fn entries_without_any_uuid_are_skipped() {
        let json = listing(&[("not-a-vm", "someone", ""), (WSL, "WSL", WSL)]);
        assert_eq!(best(&json), Some(WSL.parse().unwrap()));
        assert_eq!(best(&listing(&[("not-a-vm", "someone", "")])), None);
    }

    #[test]
    fn missing_fields_and_an_empty_listing_are_not_errors() {
        assert_eq!(best(r#"[{"Id":"x"},{"Owner":"WSL","RuntimeId":"c6de7088-6992-4adf-8038-5984755d5412"}]"#), Some(WSL.parse().unwrap()));
        assert_eq!(best("[]"), None);
        assert_eq!(best(""), None);
    }
}
