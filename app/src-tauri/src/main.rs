// OPH-S (OPH Sentinel) — personal SIEM / IDPS. DONE by OPH.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ai;
mod cleaner;
mod commands;
mod core;
mod db;
mod deco;
mod dns;
mod etw;
mod fim;
mod firewall;
mod ingest;
mod intel;
mod leak;
mod native;
mod netmon;
mod query;
mod router;
mod services;
mod settings;
mod share;
mod storage;
mod suricata;

use crate::core::Core;
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};

static NET_TASKS: Mutex<Vec<tauri::async_runtime::JoinHandle<()>>> = Mutex::new(Vec::new());

/// (Re)start the listeners whose ports/addresses come from settings.
pub fn restart_network_services(core: Arc<Core>) {
    let mut tasks = NET_TASKS.lock().unwrap();
    for t in tasks.drain(..) {
        t.abort();
    }
    {
        let mut st = core.status.lock().unwrap();
        *st = crate::core::ServiceStatus { intel_updating: st.intel_updating, ..Default::default() };
    }
    tasks.push(tauri::async_runtime::spawn(dns::run(core.clone())));
    tasks.push(tauri::async_runtime::spawn(ingest::run_agent_server(core.clone())));
    tasks.push(tauri::async_runtime::spawn(ingest::run_syslog(core)));
}

/// Tray + window icon for one of the bundled styles (64 px PNGs compiled in).
fn style_png(id: &str) -> &'static [u8] {
    match id {
        "op-radar" => include_bytes!("../icons/styles/op-radar.png"),
        "op-hex" => include_bytes!("../icons/styles/op-hex.png"),
        "op-eye" => include_bytes!("../icons/styles/op-eye.png"),
        "op-bracket" => include_bytes!("../icons/styles/op-bracket.png"),
        "op-orbit" => include_bytes!("../icons/styles/op-orbit.png"),
        _ => include_bytes!("../icons/styles/op-shield.png"),
    }
}

pub fn set_app_icon(core: &Core, id: &str) {
    let Some(app) = core.app.get() else { return };
    let Ok(img) = tauri::image::Image::from_bytes(style_png(id)) else { return };
    if let Some(t) = app.tray_by_id("oph") {
        let _ = t.set_icon(Some(img.clone()));
    }
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_icon(img);
    }
}

/// `oph-sentinel.exe --cleanup`: run by the uninstaller. Removes everything OPH-S
/// changed outside its own folders: hosts entries, firewall rules, autostart, ETW session.
fn cleanup_and_exit() -> ! {
    let r = |cmd: &str, args: &[&str]| {
        let _ = native::run_hidden(cmd, args);
    };
    let hosts = std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32\\drivers\\etc\\hosts");
    firewall::remove_hosts_section(&hosts);
    r("netsh", &["advfirewall", "firewall", "delete", "rule", "name=OPH Sentinel - blocked IPs"]);
    r("netsh", &["advfirewall", "firewall", "delete", "rule", "name=OPH Sentinel - inbound"]);
    r("schtasks", &["/delete", "/tn", "OPH Sentinel", "/f"]);
    r("schtasks", &["/delete", "/tn", "OPH-S", "/f"]);
    r("reg", &["delete", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "OPH Sentinel", "/f"]);
    r("logman", &["stop", "OPH-Sentinel-DNS", "-ets"]);
    r("ipconfig", &["/flushdns"]);
    std::process::exit(0)
}

fn start_services(core: Arc<Core>) {
    core.sys("system.start", "info", format!("OPH-S {} started (mode: {}, administrator: {})", env!("CARGO_PKG_VERSION"), core.settings().mode, core.admin));
    {
        let c = core.clone();
        std::thread::spawn(move || {
            services::rebuild_index(&c); // from cached feeds: protection is active before any download
            services::refresh(c.clone(), false);
            firewall::sync(&c);
            firewall::ensure_inbound(&c); // DNS 53, agents, syslog, download share — private networks only
        });
    }
    restart_network_services(core.clone());
    tauri::async_runtime::spawn(netmon::run_lan(core.clone()));
    tauri::async_runtime::spawn(services::maintenance(core.clone()));
    netmon::run_local_connections(core.clone());
    netmon::run_local_dns_watch(core.clone());
    suricata::run(core.clone());
    fim::start(core.clone());
    leak::start(core.clone());
    // watch the log drive: follow letter changes, fall back when unplugged, merge back when it returns
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            let c = core.clone();
            let _ = tokio::task::spawn_blocking(move || storage::check(&c)).await;
        }
    });
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let style = app.try_state::<Arc<Core>>().map(|c| c.settings().icon_style).unwrap_or_default();
    let mut builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()));
    if let Ok(img) = tauri::image::Image::from_bytes(style_png(&style)) {
        builder = builder.icon(img).unwrap_or_else(|e| panic!("window icon: {e}"));
    }
    let _ = builder
        .title("OPH-S")
        .inner_size(1440.0, 900.0)
        .min_inner_size(1100.0, 680.0)
        .theme(Some(tauri::Theme::Dark))
        .center()
        .build();
}

fn main() {
    // A small runtime: 2 workers + bounded blocking pool keeps idle RAM low.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(8)
        .thread_stack_size(1024 * 1024)
        .enable_all()
        .build()
        .expect("tokio runtime");
    tauri::async_runtime::set(rt.handle().clone());
    let _rt = Box::leak(Box::new(rt));

    if std::env::args().any(|a| a == "--cleanup") {
        cleanup_and_exit();
    }
    if std::env::args().any(|a| a == "--install-autostart") {
        let ok = services::set_autostart(true, native::is_elevated()).is_ok();
        std::process::exit(if ok { 0 } else { 1 });
    }
    let minimized = std::env::args().any(|a| a == "--minimized");

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            commands::overview,
            commands::search,
            commands::alerts,
            commands::alert_counts,
            commands::alert_decide,
            commands::devices,
            commands::device_detail,
            commands::connections,
            commands::intel_status,
            commands::intel_update,
            commands::feed_toggle,
            commands::list_add,
            commands::list_remove,
            commands::agents,
            commands::device_enroll,
            commands::device_revoke,
            commands::apk_share,
            commands::drives_list,
            commands::storage_status,
            commands::router_info,
            commands::router_configure,
            commands::router_undo,
            commands::router_forget,
            commands::set_monitoring,
            commands::search_suggest,
            commands::export_search,
            commands::ai_ask,
            commands::ai_preview,
            commands::ai_set_key,
            commands::ai_status,
            commands::device_rename,
            commands::leak_status,
            commands::leak_action,
            commands::leak_fix,
            commands::cleaner_last,
            commands::unblock_all,
            commands::cleaner_scan,
            commands::cleaner_run,
            commands::cleaner_undo,
            commands::cleaner_purge,
            commands::memory_status,
            commands::memory_trim,
            commands::settings_get,
            commands::settings_set,
            commands::app_info,
            commands::firewall_setup,
        ])
        .setup(move |app| {
            // Runs after the single-instance plugin: a second launch exits before it
            // ever opens the databases or starts listeners.
            let (core, rx) = Core::new(settings::data_dir());
            core::run_pipeline(core.clone(), rx);
            app.manage(core.clone());
            let _ = core.app.set(app.handle().clone());
            let open = MenuItem::with_id(app, "open", "Open OPH-S", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit (stops protection)", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &PredefinedMenuItem::separator(app)?, &quit])?;
            TrayIconBuilder::with_id("oph")
                .icon(tauri::image::Image::from_bytes(style_png(&core.settings().icon_style)).unwrap_or_else(|_| app.default_window_icon().cloned().expect("icon")))
                .tooltip("OPH-S — protection active")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, e| match e.id.as_ref() {
                    "open" => show_main(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, e| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            start_services(core.clone());
            if !minimized {
                show_main(app.handle());
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build OPH Sentinel");

    app.run(|_app, event| match event {
        // Closing the window destroys the WebView (freeing its memory) but the
        // protection services keep running in the tray.
        tauri::RunEvent::ExitRequested { code: None, api, .. } => api.prevent_exit(),
        // Quit from the tray: release the kernel ETW session so nothing is left running
        tauri::RunEvent::Exit => {
            let _ = native::run_hidden("logman", &["stop", "OPH-Sentinel-DNS", "-ets"]);
        }
        tauri::RunEvent::WindowEvent { event: tauri::WindowEvent::Destroyed, .. } => {
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_secs(2));
                native::trim_self();
            });
        }
        _ => {}
    });
}
