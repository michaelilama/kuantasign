//! Prueba de KuantaSign: firma un PDF en formato PAdES (como Adobe y el Firmador) con la tarjeta
//! de Firma Digital de Costa Rica, desde Rust y sin Java.
//!
//!   prueba-firma tarjeta  entrada.pdf salida.pdf [ruta-del-controlador-pkcs11]
//!   prueba-firma archivo  entrada.pdf salida.pdf llave.p12 contraseña cadena1.pem [cadena2.pem…]
//!
//! El modo `archivo` firma con un certificado guardado en un .p12: sirve para probar todo
//! (PDF, CMS, sello de tiempo del SINPE, validación de K360) sin la tarjeta.
//!
//! Formato (el mismo que usa el Firmador, ver FirmadorPAdES.java): PAdES con SubFilter
//! ETSI.CAdES.detached, SHA-256, atributo signingCertificateV2, sello de tiempo del TSA del SINPE
//! (PAdES-B-T), hueco de 16 KB para la firma. La firma se agrega al final del PDF (actualización
//! incremental): el documento original queda intacto byte por byte.

use anyhow::{anyhow, bail, Context, Result};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::db::rfc5911::{ID_DATA, ID_SIGNED_DATA};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString, SetOfVec};
use der::{Decode, DecodePem, Encode, Sequence};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use std::fs;
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::serial_number::SerialNumber;
use x509_cert::Certificate;

const TSA_SINPE: &str = "http://tsa.sinpe.fi.cr/tsaHttp/";
const HUECO: usize = 16384; // bytes reservados para el CMS (se escriben en hexadecimal: el doble)

const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SIGNING_CERT_V2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const OID_TIMESTAMP_TOKEN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

// ───────────────────────────── quién firma ─────────────────────────────

trait Firmante {
    /// Certificado de firma y su cadena (sin la raíz si no hace falta).
    fn certificado(&self) -> &Certificate;
    fn cadena(&self) -> &[Certificate];
    /// Firma RSA PKCS#1 v1.5 con SHA-256 sobre `datos` (la tarjeta calcula el hash).
    fn firmar(&mut self, datos: &[u8]) -> Result<Vec<u8>>;
}

/// Tarjeta de Firma Digital por PKCS#11 (controlador oficial: IDEMIA o Athena).
struct Tarjeta {
    sesion: cryptoki::session::Session,
    llave: cryptoki::object::ObjectHandle,
    cert: Certificate,
    cadena: Vec<Certificate>,
}

fn controlador_por_defecto() -> Vec<&'static str> {
    if cfg!(target_os = "macos") {
        vec!["/Library/SCMiddleware/libidop11.dylib", "/Library/Application Support/Athena/libASEP11.dylib"]
    } else if cfg!(target_os = "windows") {
        vec!["C:\\Windows\\System32\\idoPKCS.dll", "C:\\Program Files\\Smart Card Middleware\\bin\\idoPKCS.dll", "C:\\Windows\\System32\\asepkcs.dll"]
    } else {
        vec!["/usr/lib/SCMiddleware/libidop11.so", "/usr/lib/x64-athena/libASEP11.so"]
    }
}

impl Tarjeta {
    fn abrir(ruta: Option<&str>, cadena: Vec<Certificate>) -> Result<Self> {
        use cryptoki::context::{CInitializeArgs, Pkcs11};
        use cryptoki::object::{Attribute as A, AttributeType, ObjectClass};
        use cryptoki::session::UserType;
        use cryptoki::types::AuthPin;

        let candidatos: Vec<String> = match ruta { Some(r) => vec![r.to_string()], None => controlador_por_defecto().iter().map(|s| s.to_string()).collect() };
        let lib = candidatos.iter().find(|p| std::path::Path::new(p).exists())
            .ok_or_else(|| anyhow!("No se encontró el controlador de la tarjeta (probé: {})", candidatos.join(", ")))?;
        println!("Controlador: {lib}");
        let pkcs11 = Pkcs11::new(lib)?;
        pkcs11.initialize(CInitializeArgs::OsThreads)?;
        let slot = *pkcs11.get_slots_with_token()?.first().ok_or_else(|| anyhow!("No hay tarjeta en el lector"))?;
        let sesion = pkcs11.open_ro_session(slot)?;

        // El certificado de FIRMA (la tarjeta también trae el de autenticación).
        let mut elegido: Option<(Certificate, Vec<u8>)> = None;
        for obj in sesion.find_objects(&[A::Class(ObjectClass::CERTIFICATE)])? {
            let attrs = sesion.get_attributes(obj, &[AttributeType::Value, AttributeType::Id])?;
            let (mut valor, mut id) = (vec![], vec![]);
            for a in attrs { match a { A::Value(v) => valor = v, A::Id(i) => id = i, _ => {} } }
            let Ok(cert) = Certificate::from_der(&valor) else { continue };
            let cn = cert.tbs_certificate.subject.to_string();
            println!("  certificado en la tarjeta: {cn}");
            if cn.contains("(FIRMA)") || elegido.is_none() { elegido = Some((cert, id)); }
        }
        let (cert, id) = elegido.ok_or_else(|| anyhow!("La tarjeta no tiene certificado de firma"))?;
        println!("Firmará como: {}", cert.tbs_certificate.subject);

        let pin = rpassword::prompt_password("PIN de la tarjeta: ")?;
        sesion.login(UserType::User, Some(&AuthPin::new(pin)))?;
        let llave = *sesion.find_objects(&[A::Class(ObjectClass::PRIVATE_KEY), A::Id(id)])?.first()
            .ok_or_else(|| anyhow!("No se encontró la llave privada del certificado de firma"))?;
        Ok(Tarjeta { sesion, llave, cert, cadena })
    }
}

impl Firmante for Tarjeta {
    fn certificado(&self) -> &Certificate { &self.cert }
    fn cadena(&self) -> &[Certificate] { &self.cadena }
    fn firmar(&mut self, datos: &[u8]) -> Result<Vec<u8>> {
        Ok(self.sesion.sign(&cryptoki::mechanism::Mechanism::Sha256RsaPkcs, self.llave, datos)?)
    }
}

/// Certificado en archivo .p12 (solo para pruebas sin tarjeta).
struct Archivo { llave: rsa::RsaPrivateKey, cert: Certificate, cadena: Vec<Certificate> }

impl Archivo {
    fn abrir(p12: &str, clave: &str, cadena: Vec<Certificate>) -> Result<Self> {
        use rsa::pkcs8::DecodePrivateKey;
        let ks = p12_keystore::KeyStore::from_pkcs12(&fs::read(p12)?, clave).map_err(|e| anyhow!("p12: {e:?}"))?;
        let (_, entrada) = ks.private_key_chain().ok_or_else(|| anyhow!("el .p12 no trae llave"))?;
        let llave = rsa::RsaPrivateKey::from_pkcs8_der(entrada.key())?;
        let cert = Certificate::from_der(entrada.chain()[0].as_der())?;
        Ok(Archivo { llave, cert, cadena })
    }
}

impl Firmante for Archivo {
    fn certificado(&self) -> &Certificate { &self.cert }
    fn cadena(&self) -> &[Certificate] { &self.cadena }
    fn firmar(&mut self, datos: &[u8]) -> Result<Vec<u8>> {
        let hash = Sha256::digest(datos);
        Ok(self.llave.sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &hash)?)
    }
}

// ───────────────────────────── PDF ─────────────────────────────

/// Escribe un objeto de lopdf como texto PDF (solo lo que aparece en catálogo y páginas).
fn objeto_a_texto(o: &lopdf::Object) -> String {
    use lopdf::Object::*;
    match o {
        Null => "null".into(),
        Boolean(b) => if *b { "true".into() } else { "false".into() },
        Integer(i) => i.to_string(),
        Real(r) => format!("{r}"),
        Name(n) => format!("/{}", std::string::String::from_utf8_lossy(n)),
        String(s, _) => format!("<{}>", hex::encode(s)),
        Array(a) => format!("[{}]", a.iter().map(objeto_a_texto).collect::<Vec<_>>().join(" ")),
        Dictionary(d) => dict_a_texto(d),
        Reference((n, g)) => format!("{n} {g} R"),
        Stream(_) => "null".into(),
    }
}
fn dict_a_texto(d: &lopdf::Dictionary) -> String {
    let mut s = String::from("<<");
    for (k, v) in d.iter() { s.push_str(&format!(" /{} {}", String::from_utf8_lossy(k), objeto_a_texto(v))); }
    s.push_str(" >>");
    s
}

struct Preparado { bytes: Vec<u8>, inicio_contents: usize, fin_contents: usize }

/// Dónde se dibuja la firma: página (1 = primera) y recuadro en puntos PDF (origen abajo-izquierda).
#[derive(Clone, Copy)]
struct Recuadro { pagina: u32, x1: f64, y1: f64, x2: f64, y2: f64 }

/// Texto PDF en WinAnsi (para tildes y eñes con Helvetica).
fn texto_pdf(t: &str) -> String {
    let mut s = String::from("(");
    for c in t.chars() {
        let b: u32 = c as u32;
        match c {
            '(' | ')' | '\\' => { s.push('\\'); s.push(c); }
            _ if b < 128 => s.push(c),
            _ if b < 256 => s.push_str(&format!("\\{:03o}", b)),
            _ => s.push('?'),
        }
    }
    s.push(')');
    s
}

/// Ancho aproximado de un texto en Helvetica (en unidades de 1 pt de tamaño).
fn ancho_texto(t: &str, negrita: bool) -> f64 {
    t.chars().map(|c| match c {
        'i' | 'l' | 'j' | '.' | ',' | ':' | '\'' | ' ' | '|' => 0.28,
        'I' | 'f' | 't' | 'r' | '-' | '(' | ')' => 0.36,
        'M' | 'W' | 'm' | 'w' => 0.85,
        'A'..='Z' => if negrita { 0.72 } else { 0.68 },
        '0'..='9' => 0.56,
        _ => if negrita { 0.58 } else { 0.54 },
    }).sum()
}

/// Círculo con curvas de Bézier (centro, radio).
fn circulo(cx: f64, cy: f64, r: f64) -> String {
    let k = 0.5523 * r;
    format!("{:.2} {:.2} m {:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c {:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c {:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c {:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c ",
        cx + r, cy,
        cx + r, cy + k, cx + k, cy + r, cx, cy + r,
        cx - k, cy + r, cx - r, cy + k, cx - r, cy,
        cx - r, cy - k, cx - k, cy - r, cx, cy - r,
        cx + k, cy - r, cx + r, cy - k, cx + r, cy)
}

/// Rectángulo con esquinas redondeadas (radios: abajo-izq, abajo-der, arriba-der, arriba-izq).
fn rect_redondo(x: f64, y: f64, w: f64, h: f64, r: [f64; 4]) -> String {
    let k = 0.5523;
    let [bi, bd, ad, ai] = r;
    format!(
        "{:.2} {:.2} m {:.2} {:.2} l {:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c {:.2} {:.2} l {:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c {:.2} {:.2} l {:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c {:.2} {:.2} l {:.2} {:.2} {:.2} {:.2} {:.2} {:.2} c h ",
        x + bi, y,
        x + w - bd, y, x + w - bd + bd * k, y, x + w, y + bd - bd * k, x + w, y + bd,
        x + w, y + h - ad, x + w, y + h - ad + ad * k, x + w - ad + ad * k, y + h, x + w - ad, y + h,
        x + ai, y + h, x + ai - ai * k, y + h, x, y + h - ai + ai * k, x, y + h - ai,
        x, y + bi, x, y + bi - bi * k, x + bi - bi * k, y, x + bi, y,
    )
}

/// Emblema de KuantaSign (círculo verde con pluma blanca) en un cuadro de `t` puntos con esquina en (x, y).
fn emblema(x: f64, y: f64, t: f64) -> String {
    // Se dibuja en un espacio de 100×100 con el eje Y hacia abajo (como el SVG del diseño).
    let s = t / 100.0;
    let mut c = format!("q {s:.4} 0 0 {:.4} {x:.2} {:.2} cm\n", -s, y + t);
    c.push_str(&format!("0.071 0.588 0.369 rg {}f\n", circulo(50.0, 50.0, 46.0)));
    c.push_str("1 1 1 rg 30 62 m 58 34 l 68 44 l 40 72 l 28 74 l h f\n");
    c.push_str("61 31 m 66 26 l 69 23 73 23 76 26 c 79 29 l 82 32 82 36 79 39 c 74 44 l h f\n");
    c.push_str("1 1 1 RG 4 w 1 J 26 80 m 74 80 l S\nQ\n");
    c
}

/// "MICHAEL ADRIAN ILAMA ARAYA" → "Michael Adrian Ilama Araya".
fn nombre_propio(n: &str) -> String {
    n.split_whitespace().map(|p| {
        let mut cs = p.chars();
        match cs.next() { Some(f) => f.to_uppercase().collect::<String>() + &cs.as_str().to_lowercase(), None => String::new() }
    }).collect::<Vec<_>>().join(" ")
}

/// Sello visible (diseño «opción 3»): arriba quién firmó; abajo una franja con el logo de
/// KuantaSign a la izquierda y, a la derecha, «Firma Digital Certificada · CA SINPE · Banco
/// Central de Costa Rica» con el ícono de GAUDI. Todo escala con el tamaño del recuadro.
fn apariencia(ancho: f64, alto: f64, nombre: &str, cedula: &str, fecha: &str) -> String {
    let e = (ancho / 310.0).min(alto / 80.0);          // escala respecto del diseño (310×80)
    let franja = (alto * 0.36).max(16.0 * e);
    let radio = 6.0 * e;
    let pad = 11.0 * e;
    let tinta = "0.078 0.125 0.102";
    let gris = "0.357 0.400 0.380";
    let verde = "0.071 0.588 0.369";
    let mut c = String::new();

    // Fondo blanco y franja verde clara abajo.
    c.push_str(&format!("q 1 1 1 rg {}f Q\n", rect_redondo(0.5, 0.5, ancho - 1.0, alto - 1.0, [radio; 4])));
    c.push_str(&format!("q 0.949 0.973 0.961 rg {}f Q\n", rect_redondo(0.5, 0.5, ancho - 1.0, franja, [radio, radio, 0.0, 0.0])));
    c.push_str(&format!("q 0.851 0.886 0.871 RG {:.2} w 0.5 {franja:.2} m {:.2} {franja:.2} l S Q\n", 0.8 * e, ancho - 0.5));
    c.push_str(&format!("q 0.851 0.886 0.871 RG {:.2} w {}S Q\n", 0.8 * e, rect_redondo(0.5, 0.5, ancho - 1.0, alto - 1.0, [radio; 4])));

    // Arriba: quién firmó.
    let disponible = ancho - pad * 2.0;
    let t_nombre = (13.5 * e).min(disponible / ancho_texto(nombre, true));
    let t_dato = (8.8 * e).min(disponible / ancho_texto(&format!("C\u{e9}dula {cedula} \u{b7} {fecha}"), false));
    let t_et = 8.0 * e;
    let alto_arriba = alto - franja;
    let bloque = t_et + 2.0 * e + t_nombre + 3.0 * e + t_dato;
    let mut y = franja + (alto_arriba + bloque) / 2.0 - t_et;
    c.push_str("BT\n");
    c.push_str(&format!("{gris} rg /Helv {t_et:.2} Tf 1 0 0 1 {pad:.2} {y:.2} Tm {} Tj\n", texto_pdf("Firmado digitalmente por")));
    y -= t_nombre + 2.0 * e;
    c.push_str(&format!("{tinta} rg /HelvB {t_nombre:.2} Tf 1 0 0 1 {pad:.2} {y:.2} Tm {} Tj\n", texto_pdf(nombre)));
    y -= t_dato + 3.0 * e;
    c.push_str(&format!("{tinta} rg /Helv {t_dato:.2} Tf 1 0 0 1 {pad:.2} {y:.2} Tm {} Tj\n", texto_pdf(&format!("C\u{e9}dula {cedula} \u{b7} {fecha}"))));
    c.push_str("ET\n");

    // Franja: logo KuantaSign a la izquierda.
    let t_icono = (franja * 0.62).min(16.0 * e);
    let y_icono = (franja - t_icono) / 2.0;
    c.push_str(&emblema(pad, y_icono, t_icono));
    let t_logo = (12.5 * e).min(franja * 0.5);
    let x_logo = pad + t_icono + 5.0 * e;
    let y_logo = (franja - t_logo * 0.72) / 2.0;
    c.push_str(&format!("BT /HelvB {t_logo:.2} Tf {tinta} rg 1 0 0 1 {x_logo:.2} {y_logo:.2} Tm (Kuanta) Tj {verde} rg (Sign) Tj ET\n"));

    // Franja: texto del BCCR alineado a la derecha y el ícono de GAUDI al final.
    let t_gaudi = (franja * 0.74).min(20.0 * e);
    let x_gaudi = ancho - pad - t_gaudi;
    c.push_str(&format!("q {t_gaudi:.2} 0 0 {t_gaudi:.2} {x_gaudi:.2} {:.2} cm /Gaudi Do Q\n", (franja - t_gaudi) / 2.0));
    let t_b = 7.6 * e;
    let l1 = "Firma Digital Certificada";
    let l2 = "CA SINPE \u{b7} Banco Central de Costa Rica";
    let derecha = x_gaudi - 6.0 * e;
    let yb = franja / 2.0;
    c.push_str("BT\n");
    c.push_str(&format!("{gris} rg /Helv {t_b:.2} Tf 1 0 0 1 {:.2} {:.2} Tm {} Tj\n", derecha - ancho_texto(l1, false) * t_b, yb + t_b * 0.15, texto_pdf(l1)));
    c.push_str(&format!("1 0 0 1 {:.2} {:.2} Tm {} Tj\n", derecha - ancho_texto(l2, false) * t_b, yb - t_b * 1.05, texto_pdf(l2)));
    c.push_str("ET\n");
    c
}

/// El ícono de GAUDI como imagen PDF: (diccionario+flujo RGB, diccionario+flujo de transparencia).
fn imagen_gaudi() -> Result<(Vec<u8>, Vec<u8>, u32, u32)> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let dec = png::Decoder::new(&include_bytes!("../recursos/gaudi.png")[..]);
    let mut lector = dec.read_info()?;
    let mut buf = vec![0; lector.output_buffer_size()];
    let info = lector.next_frame(&mut buf)?;
    let (w, h) = (info.width, info.height);
    let (mut rgb, mut alfa) = (Vec::with_capacity((w * h * 3) as usize), Vec::with_capacity((w * h) as usize));
    match info.color_type {
        png::ColorType::Rgba => for px in buf[..info.buffer_size()].chunks(4) { rgb.extend_from_slice(&px[..3]); alfa.push(px[3]); },
        png::ColorType::Rgb => for px in buf[..info.buffer_size()].chunks(3) { rgb.extend_from_slice(px); alfa.push(255); },
        o => bail!("ícono de GAUDI con formato no soportado: {o:?}"),
    }
    let comprimir = |d: &[u8]| -> Result<Vec<u8>> { let mut z = ZlibEncoder::new(Vec::new(), Compression::best()); z.write_all(d)?; Ok(z.finish()?) };
    Ok((comprimir(&rgb)?, comprimir(&alfa)?, w, h))
}

fn preparar_pdf(original: &[u8], nombre: &str, cedula: &str, recuadro: Option<Recuadro>) -> Result<Preparado> {
    let doc = lopdf::Document::load_mem(original).context("No se pudo leer el PDF")?;
    let raiz_ref = doc.trailer.get(b"Root")?.as_reference()?;
    let mut catalogo = doc.get_object(raiz_ref)?.as_dict()?.clone();
    let paginas = doc.get_pages();
    let num = recuadro.map(|r| r.pagina).unwrap_or(1);
    let pagina_id = *paginas.get(&num).ok_or_else(|| anyhow!("El PDF no tiene la página {num}"))?;
    let mut pagina = doc.get_object(pagina_id)?.as_dict()?.clone();

    let base = doc.max_id + 1;
    let (id_firma, id_campo, id_form, id_ap, id_img, id_alfa) = (base, base + 1, base + 2, base + 3, base + 4, base + 5);

    let mut annots = match pagina.get(b"Annots") {
        Ok(lopdf::Object::Array(a)) => a.clone(),
        Ok(lopdf::Object::Reference(r)) => doc.get_object(*r)?.as_array()?.clone(),
        _ => vec![],
    };
    annots.push(lopdf::Object::Reference((id_campo, 0)));
    pagina.set("Annots", lopdf::Object::Array(annots));
    catalogo.set("AcroForm", lopdf::Object::Reference((id_form, 0)));

    let ahora = chrono::Local::now();
    let fecha = format!("D:{}{}'{}'", ahora.format("%Y%m%d%H%M%S"), &ahora.format("%:z").to_string()[..3], &ahora.format("%:z").to_string()[4..]);
    let marcador_br = "/ByteRange [0 0000000000 0000000000 0000000000]";
    let contents = format!("/Contents <{}>", "0".repeat(HUECO * 2));

    let mut agregado: Vec<u8> = b"\n".to_vec();
    let mut offsets: Vec<(u32, usize)> = vec![];
    let escribir = |id: u32, cuerpo: String, agregado: &mut Vec<u8>, offsets: &mut Vec<(u32, usize)>| {
        offsets.push((id, original.len() + agregado.len()));
        agregado.extend_from_slice(format!("{id} 0 obj\n{cuerpo}\nendobj\n").as_bytes());
    };
    escribir(id_firma, format!("<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached {marcador_br} {contents} /M ({fecha}) /Name <{}> >>", hex::encode(nombre)), &mut agregado, &mut offsets);
    match recuadro {
        Some(r) => {
            let (ancho, alto) = ((r.x2 - r.x1).abs(), (r.y2 - r.y1).abs());
            let legible = nombre_propio(&nombre.split(',').find_map(|p| p.trim().strip_prefix("CN=")).unwrap_or(nombre).replace(" (FIRMA)", ""));
            let fecha_vista = format!("{} (hora de Costa Rica)", ahora.format("%d/%m/%Y %H:%M"));
            let ced = cedula.trim_start_matches("CPF-").trim_start_matches('0').to_string();
            let flujo = apariencia(ancho, alto, &legible, &ced, &fecha_vista);
            let (img, alfa, iw, ih) = imagen_gaudi()?;
            let mut obj_img = format!("{id_img} 0 obj\n<< /Type /XObject /Subtype /Image /Width {iw} /Height {ih} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /SMask {id_alfa} 0 R /Length {} >>\nstream\n", img.len()).into_bytes();
            obj_img.extend_from_slice(&img); obj_img.extend_from_slice(b"\nendstream\nendobj\n");
            let mut obj_alfa = format!("{id_alfa} 0 obj\n<< /Type /XObject /Subtype /Image /Width {iw} /Height {ih} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length {} >>\nstream\n", alfa.len()).into_bytes();
            obj_alfa.extend_from_slice(&alfa); obj_alfa.extend_from_slice(b"\nendstream\nendobj\n");
            offsets.push((id_img, original.len() + agregado.len())); agregado.extend_from_slice(&obj_img);
            offsets.push((id_alfa, original.len() + agregado.len())); agregado.extend_from_slice(&obj_alfa);
            escribir(id_ap, format!("<< /Type /XObject /Subtype /Form /BBox [0 0 {ancho:.2} {alto:.2}] /Resources << /Font << /Helv << /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >> /HelvB << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >> >> /XObject << /Gaudi {id_img} 0 R >> >> /Length {} >>\nstream\n{flujo}endstream", flujo.len()), &mut agregado, &mut offsets);
            escribir(id_campo, format!("<< /Type /Annot /Subtype /Widget /FT /Sig /T (KuantaSign{id_firma}) /V {id_firma} 0 R /Rect [{:.2} {:.2} {:.2} {:.2}] /F 4 /AP << /N {id_ap} 0 R >> /P {} {} R >>", r.x1.min(r.x2), r.y1.min(r.y2), r.x1.max(r.x2), r.y1.max(r.y2), pagina_id.0, pagina_id.1), &mut agregado, &mut offsets);
        }
        None => escribir(id_campo, format!("<< /Type /Annot /Subtype /Widget /FT /Sig /T (KuantaSign{id_firma}) /V {id_firma} 0 R /Rect [0 0 0 0] /F 132 /P {} {} R >>", pagina_id.0, pagina_id.1), &mut agregado, &mut offsets),
    }
    escribir(id_form, format!("<< /Fields [{id_campo} 0 R] /SigFlags 3 >>"), &mut agregado, &mut offsets);
    escribir(pagina_id.0, dict_a_texto(&pagina), &mut agregado, &mut offsets);
    escribir(raiz_ref.0, dict_a_texto(&catalogo), &mut agregado, &mut offsets);

    // Tabla de referencias de esta actualización (una subsección por objeto).
    let inicio_xref = original.len() + agregado.len();
    offsets.sort();
    agregado.extend_from_slice(b"xref\n");
    for (id, off) in &offsets { agregado.extend_from_slice(format!("{id} 1\n{off:010} 00000 n \n").as_bytes()); }
    let prev = encontrar_startxref(original)?;
    let mut trailer = format!("trailer\n<< /Size {} /Root {} {} R /Prev {prev}", id_alfa + 1, raiz_ref.0, raiz_ref.1);
    if let Ok(info) = doc.trailer.get(b"Info") { trailer.push_str(&format!(" /Info {}", objeto_a_texto(info))); }
    if let Ok(idd) = doc.trailer.get(b"ID") { trailer.push_str(&format!(" /ID {}", objeto_a_texto(idd))); }
    trailer.push_str(" >>\n");
    agregado.extend_from_slice(trailer.as_bytes());
    agregado.extend_from_slice(format!("startxref\n{inicio_xref}\n%%EOF\n").as_bytes());

    let mut bytes = original.to_vec();
    bytes.extend_from_slice(&agregado);

    // Dónde quedó el hueco: de '<' a '>' inclusive se excluye del hash.
    let pos_contents = buscar(&bytes, original.len(), b"/Contents <")? + "/Contents ".len();
    let inicio_contents = pos_contents;
    let fin_contents = pos_contents + HUECO * 2 + 2;
    let br = format!("/ByteRange [0 {:010} {:010} {:010}]", inicio_contents, fin_contents, bytes.len() - fin_contents);
    let pos_br = buscar(&bytes, original.len(), marcador_br.as_bytes())?;
    bytes[pos_br..pos_br + br.len()].copy_from_slice(br.as_bytes());
    Ok(Preparado { bytes, inicio_contents, fin_contents })
}

fn buscar(h: &[u8], desde: usize, aguja: &[u8]) -> Result<usize> {
    h[desde..].windows(aguja.len()).position(|w| w == aguja).map(|p| p + desde).ok_or_else(|| anyhow!("no se encontró {}", String::from_utf8_lossy(aguja)))
}
fn encontrar_startxref(pdf: &[u8]) -> Result<usize> {
    let pos = pdf.windows(9).rposition(|w| w == b"startxref").ok_or_else(|| anyhow!("PDF sin startxref"))?;
    let resto = String::from_utf8_lossy(&pdf[pos + 9..]);
    Ok(resto.split_whitespace().next().ok_or_else(|| anyhow!("startxref vacío"))?.parse()?)
}

// ───────────────────────────── CMS (PAdES) ─────────────────────────────

#[derive(Sequence)]
struct IssuerSerial { issuer: Vec<GeneralName>, serial: SerialNumber }
#[derive(Sequence)]
struct EssCertIdV2 { cert_hash: OctetString, issuer_serial: IssuerSerial }
#[derive(Sequence)]
struct SigningCertificateV2 { certs: Vec<EssCertIdV2> }

fn atributo(oid: ObjectIdentifier, valor: Any) -> Result<Attribute> {
    let mut values = SetOfVec::new();
    values.insert(valor)?;
    Ok(Attribute { oid, values })
}

fn sha256_alg() -> AlgorithmIdentifierOwned { AlgorithmIdentifierOwned { oid: OID_SHA256, parameters: None } }

fn armar_cms(f: &mut dyn Firmante, hash_doc: &[u8], con_sello: bool) -> Result<Vec<u8>> {
    let cert = f.certificado().clone();
    let tbs = &cert.tbs_certificate;

    let scv2 = SigningCertificateV2 { certs: vec![EssCertIdV2 {
        cert_hash: OctetString::new(Sha256::digest(cert.to_der()?).to_vec())?,
        issuer_serial: IssuerSerial { issuer: vec![GeneralName::DirectoryName(tbs.issuer.clone())], serial: tbs.serial_number.clone() },
    }]};

    let mut firmados = SetOfVec::new();
    firmados.insert(atributo(OID_CONTENT_TYPE, Any::encode_from(&ID_DATA)?)?)?;
    firmados.insert(atributo(OID_MESSAGE_DIGEST, Any::encode_from(&OctetString::new(hash_doc.to_vec())?)?)?)?;
    firmados.insert(atributo(OID_SIGNING_CERT_V2, Any::encode_from(&scv2)?)?)?;

    // Se firma el DER de los atributos como SET (tag 0x31), no como [0].
    let firma = f.firmar(&firmados.to_der()?)?;

    let mut no_firmados = None;
    if con_sello {
        let token = pedir_sello(&firma)?;
        let mut s = SetOfVec::new();
        s.insert(atributo(OID_TIMESTAMP_TOKEN, Any::from_der(&token)?)?)?;
        no_firmados = Some(s);
    }

    let signer = SignerInfo {
        version: cms::content_info::CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber { issuer: tbs.issuer.clone(), serial_number: tbs.serial_number.clone() }),
        digest_alg: sha256_alg(),
        signed_attrs: Some(firmados),
        signature_algorithm: AlgorithmIdentifierOwned { oid: OID_RSA, parameters: Some(Any::null()) },
        signature: OctetString::new(firma)?,
        unsigned_attrs: no_firmados,
    };

    let mut certs = CertificateSet(SetOfVec::new());
    certs.0.insert(CertificateChoices::Certificate(cert.clone()))?;
    for c in f.cadena() { let _ = certs.0.insert(CertificateChoices::Certificate(c.clone())); }

    let mut algs = SetOfVec::new();
    algs.insert(sha256_alg())?;
    let mut infos = SetOfVec::new();
    infos.insert(signer)?;
    let sd = SignedData {
        version: cms::content_info::CmsVersion::V1,
        digest_algorithms: algs,
        encap_content_info: EncapsulatedContentInfo { econtent_type: ID_DATA, econtent: None },
        certificates: Some(certs),
        crls: None,
        signer_infos: SignerInfos(infos),
    };
    Ok(ContentInfo { content_type: ID_SIGNED_DATA, content: Any::encode_from(&sd)? }.to_der()?)
}

// ───────────────────────────── sello de tiempo (TSA SINPE) ─────────────────────────────

#[derive(Sequence)]
struct MessageImprint { hash_algorithm: AlgorithmIdentifierOwned, hashed_message: OctetString }
#[derive(Sequence)]
struct TimeStampReq { version: u8, message_imprint: MessageImprint, nonce: der::asn1::Uint, cert_req: bool }

fn pedir_sello(firma: &[u8]) -> Result<Vec<u8>> {
    let nonce = { let mut n = rand::random::<[u8; 8]>(); n[0] &= 0x7f; n[0] |= 0x01; n };
    let req = TimeStampReq {
        version: 1,
        message_imprint: MessageImprint { hash_algorithm: sha256_alg(), hashed_message: OctetString::new(Sha256::digest(firma).to_vec())? },
        nonce: der::asn1::Uint::new(&nonce)?,
        cert_req: true,
    };
    let resp = ureq::post(TSA_SINPE).set("Content-Type", "application/timestamp-query").send_bytes(&req.to_der()?)
        .map_err(|e| anyhow!("TSA del SINPE: {e}"))?;
    let mut cuerpo = vec![];
    std::io::Read::read_to_end(&mut resp.into_reader(), &mut cuerpo)?;
    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
    let partes: Vec<Any> = Vec::<Any>::from_der(&cuerpo).map_err(|e| anyhow!("respuesta del TSA ilegible: {e}"))?;
    let estado: Vec<Any> = partes.first().ok_or_else(|| anyhow!("TSA sin estado"))?.decode_as()?;
    let codigo: u8 = estado.first().ok_or_else(|| anyhow!("TSA sin código"))?.decode_as()?;
    if codigo > 1 { bail!("El TSA del SINPE rechazó el pedido (estado {codigo})"); }
    Ok(partes.get(1).ok_or_else(|| anyhow!("TSA sin sello"))?.to_der()?)
}

// ───────────────────────────── principal ─────────────────────────────

fn leer_cadena(rutas: &[String]) -> Result<Vec<Certificate>> {
    let mut v = vec![];
    for r in rutas {
        let pem = fs::read_to_string(r)?;
        v.push(Certificate::from_pem(pem.as_bytes()).with_context(|| format!("certificado {r}"))?);
    }
    Ok(v)
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4 { bail!("uso: prueba-firma tarjeta|archivo entrada.pdf salida.pdf …"); }
    let original = fs::read(&a[2])?;
    let sin_sello = std::env::var("SIN_SELLO").is_ok();

    let mut firmante: Box<dyn Firmante> = match a[1].as_str() {
        "tarjeta" => {
            let rutas: Vec<String> = std::env::var("CADENA").map(|c| c.split(',').map(String::from).collect()).unwrap_or_default();
            let cadena = leer_cadena(&rutas)?;
            Box::new(Tarjeta::abrir(a.get(4).map(|s| s.as_str()), cadena)?)
        }
        "archivo" => Box::new(Archivo::abrir(&a[4], &a[5], leer_cadena(&a[6..])?)?),
        o => bail!("modo desconocido: {o}"),
    };

    let nombre = firmante.certificado().tbs_certificate.subject.to_string();
    let cedula = nombre.split(',').find_map(|p| p.trim().to_uppercase().strip_prefix("SERIALNUMBER=").map(String::from)).unwrap_or_default();
    let recuadro = match std::env::var("RECUADRO") {
        Ok(v) => { let n: Vec<f64> = v.split(',').map(|x| x.trim().parse().unwrap_or(0.0)).collect();
                   if n.len() != 5 { bail!("RECUADRO=pagina,x1,y1,x2,y2"); }
                   Some(Recuadro { pagina: n[0] as u32, x1: n[1], y1: n[2], x2: n[3], y2: n[4] }) }
        Err(_) => None,
    };
    let mut p = preparar_pdf(&original, &nombre, &cedula, recuadro)?;
    let mut h = Sha256::new();
    h.update(&p.bytes[..p.inicio_contents]);
    h.update(&p.bytes[p.fin_contents..]);
    let hash = h.finalize();

    let cms = armar_cms(firmante.as_mut(), &hash, !sin_sello)?;
    let hexa = hex::encode(&cms);
    if hexa.len() > HUECO * 2 { bail!("La firma ({} bytes) no cabe en el hueco de {HUECO}", cms.len()); }
    p.bytes[p.inicio_contents + 1..p.inicio_contents + 1 + hexa.len()].copy_from_slice(hexa.as_bytes());
    fs::write(&a[3], &p.bytes)?;
    println!("Firmado: {} ({} bytes de firma{})", a[3], cms.len(), if sin_sello { ", sin sello de tiempo" } else { ", con sello de tiempo del SINPE" });
    Ok(())
}
