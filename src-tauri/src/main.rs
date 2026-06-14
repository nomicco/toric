#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, RunEvent};

struct AppState {
    conductor: Option<Child>,
    api_server: Option<Child>,
}

impl Drop for AppState {
    fn drop(&mut self) {
        if let Some(mut c) = self.conductor.take() {
            let _ = c.kill();
        }
        if let Some(mut a) = self.api_server.take() {
            let _ = a.kill();
        }
    }
}

fn resource_dir(app: &AppHandle) -> PathBuf {
    app.path().resource_dir().expect("could not find resource dir")
}

fn extract_nix_closure(resource_dir: &PathBuf) -> Result<(), String> {
    let closure_path = resource_dir.join("holochain-nix-closure.tar.gz");
    if !closure_path.exists() {
        return Ok(());
    }
    let nix_store = PathBuf::from("/nix/store");
    if nix_store.exists() {
        return Ok(());
    }
    println!("Extracting nix closure...");
    let status = Command::new("tar")
        .args(["xzf", closure_path.to_str().unwrap(), "-C", "/"])
        .status()
        .map_err(|e| format!("Failed to extract nix closure: {}", e))?;
    if !status.success() {
        return Err("Failed to extract nix closure".to_string());
    }
    Ok(())
}

fn find_nix_linker() -> Option<(PathBuf, String)> {
    let nix_store = PathBuf::from("/nix/store");
    if !nix_store.exists() {
        return None;
    }
    let glibc = std::fs::read_dir(&nix_store).ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("glibc-"))
        .max_by_key(|e| e.file_name().to_string_lossy().to_string())?;

    let ld_path = glibc.path().join("lib/ld-linux-x86-64.so.2");
    if !ld_path.exists() {
        return None;
    }

    let gcc_lib = std::fs::read_dir(&nix_store).ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("gcc-") && name.ends_with("-lib")
        })
        .max_by_key(|e| e.file_name().to_string_lossy().to_string())?;

    let libs = format!(
        "{}:{}",
        gcc_lib.path().join("lib").to_str()?,
        glibc.path().join("lib").to_str()?
    );

    Some((ld_path, libs))
}

fn start_conductor(resource_dir: &PathBuf, data_dir: &PathBuf) -> Result<Child, String> {
    let holochain_bin = resource_dir.join("holochain");
    let config_path = data_dir.join("conductor-config.yaml");

    // Patch the nix interpreter to the system linker if needed
    let system_linker = PathBuf::from("/lib64/ld-linux-x86-64.so.2");
    if system_linker.exists() {
        let _ = Command::new("patchelf")
            .args(["--set-interpreter", "/lib64/ld-linux-x86-64.so.2",
                   holochain_bin.to_str().unwrap()])
            .status();
    }

    let bootstrap_url = std::env::var("BOOTSTRAP_URL")
        .unwrap_or_else(|_| option_env!("TORIC_BOOTSTRAP_URL")
            .unwrap_or("http://192.168.1.169:8888")
            .to_string());
    let signal_url = std::env::var("SIGNAL_URL")
        .unwrap_or_else(|_| option_env!("TORIC_SIGNAL_URL")
            .unwrap_or("wss://dev-test-bootstrap2.holochain.org")
            .to_string());
    let relay_url = std::env::var("RELAY_URL")
        .unwrap_or_else(|_| option_env!("TORIC_RELAY_URL")
            .unwrap_or("wss://dev-test-bootstrap2.holochain.org")
            .to_string());

    let config = format!(
        "---\ndata_root_path: {data_dir}\nkeystore:\n  type: lair_server_in_proc\nadmin_interfaces:\n  - driver:\n      type: websocket\n      port: 44121\n      allowed_origins: \"*\"\nnetwork:\n  bootstrap_url: \"{bootstrap_url}\"\n  signal_url: \"{signal_url}\"\n  relay_url: \"{relay_url}\"\n  signal_allow_plain_text: true\n  danger_allow_non_tls_relay: true\ndb_sync_strategy: Fast\n",
        data_dir = data_dir.to_str().unwrap(),
        bootstrap_url = bootstrap_url,
        signal_url = signal_url,
        relay_url = relay_url,
    );

    std::fs::write(&config_path, config)
        .map_err(|e| format!("Failed to write conductor config: {}", e))?;

    println!("Starting conductor...");

    let mut cmd = if let Some((ld_path, libs)) = find_nix_linker() {
        println!("Using nix linker: {:?}", ld_path);
        let mut c = Command::new(&ld_path);
        c.arg(&holochain_bin);
        c.env("LD_LIBRARY_PATH", &libs);
        c
    } else {
        Command::new(&holochain_bin)
    };

    let child = cmd
        .arg("--piped")
        .arg("-c")
        .arg(&config_path)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start conductor: {}", e))?;

    Ok(child)
}

fn wait_for_conductor(timeout_secs: u64) -> bool {
    use std::net::TcpStream;
    let start = std::time::Instant::now();
    loop {
        if TcpStream::connect("127.0.0.1:44121").is_ok() {
            return true;
        }
        if start.elapsed().as_secs() >= timeout_secs {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}

fn start_api_server(resource_dir: &PathBuf) -> Result<Child, String> {
    let node_bin = which::which("node")
        .map_err(|_| "node not found in PATH".to_string())?;
    let api_path = resource_dir.join("api/index.js");

    println!("Starting API server...");
    Command::new(node_bin)
        .arg(&api_path)
        .env("ADMIN_PORT", "44121")
        .env("APP_PORT", "44122")
        .env("API_PORT", "3000")
        .env("APP_ID", "toric")
        .spawn()
        .map_err(|e| format!("Failed to start API server: {}", e))
}

fn install_happ(resource_dir: PathBuf) {
    let node_bin = match which::which("node") {
        Ok(p) => p,
        Err(_) => { eprintln!("node not found"); return; }
    };
    let install_script = resource_dir.join("scripts/install-happ.js");
    let status = Command::new(node_bin)
        .arg(&install_script)
        .env("ADMIN_PORT", "44121")
        .env("APP_PORT", "44122")
        .env("APP_ID", "toric")
        .status();
    match status {
        Ok(s) if s.success() => println!("Happ installed"),
        _ => println!("Happ install: already installed or non-fatal error"),
    }
}

#[tauri::command]
fn get_api_url() -> String {
    "http://localhost:3000".to_string()
}

fn main() {
    let state = Arc::new(Mutex::new(AppState {
        conductor: None,
        api_server: None,
    }));

    let state_setup = state.clone();
    let state_exit = state.clone();

    tauri::Builder::default()
        .manage(state.clone())
        .invoke_handler(tauri::generate_handler![get_api_url])
        .setup(move |app| {
            let resource_dir = resource_dir(app.handle());
            let data_dir = app.path().app_data_dir()
                .expect("could not find app data dir");

            std::fs::create_dir_all(&data_dir)
                .expect("could not create data dir");

            println!("Resource dir: {:?}", resource_dir);
            println!("Data dir: {:?}", data_dir);

            if let Err(e) = extract_nix_closure(&resource_dir) {
                eprintln!("Warning: {}", e);
            }

            // Start conductor directly.
            // Lair keystore is launched in-process by the conductor itself
            // (type: lair_server_in_proc) — there is no lair socket to wait
            // for before starting. Waiting for it is a dead sleep.
            match start_conductor(&resource_dir, &data_dir) {
                Ok(child) => {
                    state_setup.lock().unwrap().conductor = Some(child);
                }
                Err(e) => {
                    eprintln!("Failed to start conductor: {}", e);
                    std::process::exit(1);
                }
            }

            // Wait for admin websocket to accept connections.
            // This is the correct readiness signal — if port 44121 is
            // accepting connections, the conductor is ready to receive
            // install commands. No additional file or sleep needed.
            println!("Waiting for conductor...");
            if !wait_for_conductor(300) {
                eprintln!("Conductor timed out after 300s");
                std::process::exit(1);
            }
            println!("Conductor ready");

            install_happ(resource_dir.clone());

            match start_api_server(&resource_dir) {
                Ok(child) => {
                    state_setup.lock().unwrap().api_server = Some(child);
                }
                Err(e) => {
                    eprintln!("Warning: API server failed to start: {}", e);
                }
            }

            println!("Toric node running");
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error building tauri app")
        .run(move |_app, event| {
            if let RunEvent::Exit = event {
                let mut s = state_exit.lock().unwrap();
                if let Some(mut c) = s.conductor.take() { let _ = c.kill(); }
                if let Some(mut a) = s.api_server.take() { let _ = a.kill(); }
            }
        });
}