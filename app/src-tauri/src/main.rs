//! KuantaSign: firma con la tarjeta de Firma Digital los documentos que K360 le pide.
//!
//! Vive en la bandeja (en la Mac, en la barra de arriba) y escucha SOLO en 127.0.0.1:3517.
//! K360 le manda el PDF y el recuadro que la persona dibujó en el modal; KuantaSign muestra una
//! ventanita con quién firma y el PIN, firma en formato PAdES con sello de tiempo del SINPE y le
//! devuelve el PDF firmado. Solo atiende a los sitios de Kuanta (lista ORIGENES).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod firma;
mod ltv;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::sync::{mpsc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};

const PUERTO: u16 = 3517;
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Sitios que pueden pedir firmas. Cualquier otro recibe 403.
const ORIGENES: &[&str] = &[
    "https://payroll.kuantabridge.com",
    "http://localhost:50001",
    "http://127.0.0.1:50001",
];

#[derive(Deserialize)]
struct PedidoFirma { pdf: String, documento: Option<String>, recuadro: Option<RecuadroJson> }
#[derive(Deserialize, Clone, Copy)]
struct RecuadroJson { pagina: u32, x1: f64, y1: f64, x2: f64, y2: f64 }

/// El pedido en curso, que la ventanita del PIN completa o cancela.
struct Pendiente {
    pdf: Vec<u8>,
    documento: String,
    titular: String,
    recuadro: Option<firma::Recuadro>,
    respuesta: mpsc::Sender<Result<Vec<u8>, String>>,
}
static PENDIENTE: Mutex<Option<Pendiente>> = Mutex::new(None);

#[derive(Serialize)]
struct DatosPedido { documento: String, titular: String }

#[tauri::command]
fn datos_pedido() -> Option<DatosPedido> {
    PENDIENTE.lock().unwrap().as_ref().map(|p| DatosPedido { documento: p.documento.clone(), titular: p.titular.clone() })
}

/// La ventanita manda el PIN. Si es incorrecto vuelve el error y la ventana sigue abierta.
#[tauri::command]
async fn firmar_con_pin(app: AppHandle, pin: String) -> Result<(), String> {
    let (pdf, recuadro) = {
        let g = PENDIENTE.lock().unwrap();
        let p = g.as_ref().ok_or("No hay nada para firmar")?;
        (p.pdf.clone(), p.recuadro)
    };
    let resultado = tauri::async_runtime::spawn_blocking(move || firma::firmar_pdf(&pdf, recuadro, &pin))
        .await.map_err(|e| e.to_string())?;
    match resultado {
        Ok(firmado) => {
            if let Some(p) = PENDIENTE.lock().unwrap().take() { let _ = p.respuesta.send(Ok(firmado)); }
            cerrar_ventana(&app);
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn cancelar(app: AppHandle) {
    if let Some(p) = PENDIENTE.lock().unwrap().take() { let _ = p.respuesta.send(Err("Firma cancelada".into())); }
    cerrar_ventana(&app);
}

fn cerrar_ventana(app: &AppHandle) {
    let a = app.clone();
    tauri::async_runtime::spawn(async move { if let Some(v) = a.get_webview_window("pin") { let _ = v.close(); } });
}

fn abrir_ventana(app: &AppHandle) {
    let a = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(v) = a.get_webview_window("pin") { let _ = v.set_focus(); return; }
        let _ = WebviewWindowBuilder::new(&a, "pin", WebviewUrl::App("index.html".into()))
            .title("KuantaSign")
            .inner_size(440.0, 360.0)
            .resizable(false)
            .center()
            .always_on_top(true)
            .focused(true)
            .build();
    });
}

// ───────────────────────────── servidor local para K360 ─────────────────────────────

fn encabezados(origen: &str) -> Vec<tiny_http::Header> {
    [
        ("Access-Control-Allow-Origin", origen),
        ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
        ("Access-Control-Allow-Headers", "Content-Type"),
        // Chrome exige esto para que una página https hable con 127.0.0.1 (Private Network Access).
        ("Access-Control-Allow-Private-Network", "true"),
        ("Vary", "Origin"),
        ("Content-Type", "application/json"),
    ].iter().filter_map(|(k, v)| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).ok()).collect()
}

fn responder(req: tiny_http::Request, origen: &str, codigo: u16, cuerpo: serde_json::Value) {
    let mut r = tiny_http::Response::from_string(cuerpo.to_string()).with_status_code(codigo);
    for h in encabezados(origen) { r.add_header(h); }
    let _ = req.respond(r);
}

fn servidor(app: AppHandle) {
    let srv = match tiny_http::Server::http(("127.0.0.1", PUERTO)) {
        Ok(s) => s,
        Err(e) => { eprintln!("KuantaSign: no se pudo abrir el puerto {PUERTO}: {e}"); return; }
    };
    for mut req in srv.incoming_requests() {
        let origen = req.headers().iter().find(|h| h.field.equiv("Origin")).map(|h| h.value.as_str().to_string()).unwrap_or_default();
        if !ORIGENES.contains(&origen.as_str()) {
            let _ = req.respond(tiny_http::Response::from_string("Origen no autorizado").with_status_code(403));
            continue;
        }
        let ruta = req.url().split('?').next().unwrap_or("").to_string();
        match (req.method(), ruta.as_str()) {
            (tiny_http::Method::Options, _) => responder(req, &origen, 204, serde_json::json!({})),
            (tiny_http::Method::Get, "/estado") => {
                let tarjeta = firma::titular().map_err(|e| e.to_string());
                responder(req, &origen, 200, serde_json::json!({
                    "app": "KuantaSign", "version": VERSION,
                    "tarjeta": tarjeta.is_ok(), "titular": tarjeta.as_ref().ok(), "aviso": tarjeta.as_ref().err()
                }));
            }
            (tiny_http::Method::Post, "/firmar") => {
                let mut cuerpo = String::new();
                if std::io::Read::read_to_string(req.as_reader(), &mut cuerpo).is_err() { responder(req, &origen, 400, serde_json::json!({"error": "Pedido ilegible"})); continue; }
                let pedido: PedidoFirma = match serde_json::from_str(&cuerpo) { Ok(p) => p, Err(e) => { responder(req, &origen, 400, serde_json::json!({"error": format!("Pedido inválido: {e}")})); continue; } };
                let pdf = match B64.decode(pedido.pdf.as_bytes()) { Ok(b) => b, Err(_) => { responder(req, &origen, 400, serde_json::json!({"error": "PDF inválido"})); continue; } };
                let titular = match firma::titular() { Ok(t) => t, Err(e) => { responder(req, &origen, 409, serde_json::json!({"error": e.to_string()})); continue; } };
                if PENDIENTE.lock().unwrap().is_some() { responder(req, &origen, 409, serde_json::json!({"error": "Ya hay una firma en curso"})); continue; }

                let (tx, rx) = mpsc::channel();
                *PENDIENTE.lock().unwrap() = Some(Pendiente {
                    pdf,
                    documento: pedido.documento.unwrap_or_else(|| "Documento".into()),
                    titular,
                    recuadro: pedido.recuadro.map(|r| firma::Recuadro { pagina: r.pagina, x1: r.x1, y1: r.y1, x2: r.x2, y2: r.y2 }),
                    respuesta: tx,
                });
                abrir_ventana(&app);
                // Se responde en otro hilo para no frenar /estado mientras la persona digita el PIN.
                let o = origen.clone();
                std::thread::spawn(move || match rx.recv_timeout(Duration::from_secs(300)) {
                    Ok(Ok(firmado)) => responder(req, &o, 200, serde_json::json!({ "pdf": B64.encode(firmado) })),
                    Ok(Err(e)) => responder(req, &o, 499, serde_json::json!({ "error": e })),
                    Err(_) => { PENDIENTE.lock().unwrap().take(); responder(req, &o, 408, serde_json::json!({ "error": "Se acabó el tiempo para firmar" })); }
                });
            }
            _ => responder(req, &origen, 404, serde_json::json!({"error": "No existe"})),
        }
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|_, _, _| {}))
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, None))
        .invoke_handler(tauri::generate_handler![datos_pedido, firmar_con_pin, cancelar])
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // Arranca solo con la computadora.
            use tauri_plugin_autostart::ManagerExt;
            let _ = app.autolaunch().enable();

            use tauri::menu::{Menu, MenuItem};
            use tauri::tray::TrayIconBuilder;
            let estado = MenuItem::with_id(app, "estado", format!("KuantaSign {VERSION} · listo para firmar"), false, None::<&str>)?;
            let salir = MenuItem::with_id(app, "salir", "Salir", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&estado, &salir])?;
            TrayIconBuilder::with_id("kuantasign")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("KuantaSign")
                .menu(&menu)
                .on_menu_event(|app, e| if e.id.as_ref() == "salir" { app.exit(0) })
                .build(app)?;

            let h = app.handle().clone();
            std::thread::spawn(move || servidor(h));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("no se pudo iniciar KuantaSign")
        // Cerrar la ventanita no cierra la app: sigue en la bandeja.
        .run(|_, e| if let tauri::RunEvent::ExitRequested { api, code, .. } = e { if code.is_none() { api.prevent_exit(); } });
}
