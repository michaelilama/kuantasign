//! Validación a largo plazo (PAdES-LT): después de firmar se agrega al PDF un diccionario DSS con
//! las cadenas completas —la de quien firma y la del sello de tiempo del SINPE— y la prueba de que
//! ningún certificado estaba revocado al firmar (OCSP del SINPE para quien firma; listas de
//! revocación de las CA, que pesan menos de 1 KB). Sin esto Adobe avisa que el sello de tiempo
//! no se pudo verificar y que la firma no es «LTV»: dentro de unos años, vencidos los certificados,
//! ya no se podría comprobar.
use anyhow::{anyhow, bail, Context, Result};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Any, Decode, DecodePem, Encode, Sequence};
use sha1::Sha1;
use sha2::Digest;
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};
use x509_cert::serial_number::SerialNumber;
use x509_cert::Certificate;

use crate::firma::{dict_a_texto, encontrar_startxref, objeto_a_texto};

const OID_AIA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
const OID_CRL_DP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
const OID_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
const OID_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.2");
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_TIMESTAMP_TOKEN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
/// Una lista de revocación más grande que esto no se mete (la de la CA SINPE pesa 1.5 MB:
/// para quien firma se usa OCSP, que sí tiene).
const CRL_MAXIMA: usize = 300 * 1024;

/// Certificados de la jerarquía nacional que se conocen de antemano: así no hay que bajarlos.
fn conocidos() -> Vec<Certificate> {
    [
        include_str!("../recursos/raiz-nacional-v2.pem"),
        include_str!("../recursos/politica-persona-fisica-v2.pem"),
        include_str!("../recursos/sinpe-persona-fisica-v2-2031.pem"),
        include_str!("../recursos/politica-sellado-tiempo-v2.pem"),
    ]
    .iter()
    .filter_map(|p| Certificate::from_pem(p.as_bytes()).ok())
    .collect()
}

fn descargar(url: &str, tipo: Option<&str>, cuerpo: Option<&[u8]>) -> Result<Vec<u8>> {
    let agente = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(20)).build();
    let resp = match cuerpo {
        Some(b) => agente.post(url).set("Content-Type", tipo.unwrap_or("application/octet-stream")).send_bytes(b),
        None => agente.get(url).call(),
    }
    .map_err(|e| anyhow!("{url}: {e}"))?;
    let mut datos = vec![];
    std::io::Read::read_to_end(&mut std::io::Read::take(resp.into_reader(), (CRL_MAXIMA + 1) as u64), &mut datos)?;
    Ok(datos)
}

fn mismo(a: &Certificate, b: &Certificate) -> bool { a.to_der().ok() == b.to_der().ok() }
fn autofirmado(c: &Certificate) -> bool { c.tbs_certificate.subject == c.tbs_certificate.issuer }

/// Direcciones de una extensión: (OCSP, emisor) de AIA, o las de la lista de revocación.
fn uris_aia(c: &Certificate, metodo: ObjectIdentifier) -> Vec<String> {
    let Some(ext) = c.tbs_certificate.extensions.iter().flatten().find(|e| e.extn_id == OID_AIA) else { return vec![] };
    let Ok(aia) = AuthorityInfoAccessSyntax::from_der(ext.extn_value.as_bytes()) else { return vec![] };
    aia.0.iter().filter(|a| a.access_method == metodo).filter_map(|a| match &a.access_location {
        GeneralName::UniformResourceIdentifier(u) => Some(u.to_string()),
        _ => None,
    }).collect()
}
fn uris_crl(c: &Certificate) -> Vec<String> {
    let Some(ext) = c.tbs_certificate.extensions.iter().flatten().find(|e| e.extn_id == OID_CRL_DP) else { return vec![] };
    let Ok(dps) = CrlDistributionPoints::from_der(ext.extn_value.as_bytes()) else { return vec![] };
    dps.0.iter().filter_map(|d| d.distribution_point.as_ref()).flat_map(|n| match n {
        DistributionPointName::FullName(nombres) => nombres.iter().filter_map(|g| match g {
            GeneralName::UniformResourceIdentifier(u) => Some(u.to_string()),
            _ => None,
        }).collect::<Vec<_>>(),
        _ => vec![],
    }).collect()
}

/// El emisor de `c`: entre los ya conocidos o, si no, bajándolo de la dirección del certificado.
fn emisor(c: &Certificate, conocidos: &mut Vec<Certificate>) -> Result<Certificate> {
    if let Some(e) = conocidos.iter().find(|k| k.tbs_certificate.subject == c.tbs_certificate.issuer && !mismo(k, c)) {
        return Ok(e.clone());
    }
    for url in uris_aia(c, OID_CA_ISSUERS) {
        let Ok(datos) = descargar(&url, None, None) else { continue };
        let cert = Certificate::from_der(&datos).or_else(|_| Certificate::from_pem(&datos));
        if let Ok(e) = cert {
            if e.tbs_certificate.subject == c.tbs_certificate.issuer {
                conocidos.push(e.clone());
                return Ok(e);
            }
        }
    }
    bail!("no se encontró el emisor de {}", c.tbs_certificate.subject)
}

// OCSPRequest (RFC 6960), lo mínimo: un CertID sin extensiones ni firma.
#[derive(Sequence)]
struct CertId { hash_algorithm: AlgorithmIdentifierOwned, issuer_name_hash: OctetString, issuer_key_hash: OctetString, serial_number: SerialNumber }
#[derive(Sequence)]
struct Pedido { req_cert: CertId }
#[derive(Sequence)]
struct TbsRequest { request_list: Vec<Pedido> }
#[derive(Sequence)]
struct OcspRequest { tbs_request: TbsRequest }

/// Respuesta OCSP firmada por el SINPE para `c` (tal cual llega: es lo que va en el DSS).
fn ocsp(c: &Certificate, emisor: &Certificate, url: &str) -> Result<Vec<u8>> {
    let pedido = OcspRequest { tbs_request: TbsRequest { request_list: vec![Pedido { req_cert: CertId {
        hash_algorithm: AlgorithmIdentifierOwned { oid: OID_SHA1, parameters: Some(Any::null()) },
        issuer_name_hash: OctetString::new(Sha1::digest(emisor.tbs_certificate.subject.to_der()?).to_vec())?,
        issuer_key_hash: OctetString::new(Sha1::digest(emisor.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes()).to_vec())?,
        serial_number: c.tbs_certificate.serial_number.clone(),
    }}]}};
    let resp = descargar(url, Some("application/ocsp-request"), Some(&pedido.to_der()?))?;
    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] … } — 0 = successful
    let partes: Vec<Any> = Vec::<Any>::from_der(&resp).map_err(|e| anyhow!("respuesta OCSP ilegible: {e}"))?;
    if partes.first().map(|p| p.value()) != Some(&[0u8][..]) || partes.len() < 2 { bail!("el OCSP del SINPE no respondió bien"); }
    Ok(resp)
}

/// Lo que va en el DSS.
#[derive(Default)]
struct Pruebas { certs: Vec<Vec<u8>>, ocsps: Vec<Vec<u8>>, crls: Vec<Vec<u8>>, crl_bajadas: Vec<String> }

impl Pruebas {
    fn cert(&mut self, c: &Certificate) -> Result<()> {
        let d = c.to_der()?;
        if !self.certs.contains(&d) { self.certs.push(d); }
        Ok(())
    }
    /// Cadena de `hoja` hasta la raíz, con la prueba de no revocación de cada eslabón.
    fn cadena(&mut self, hoja: &Certificate, conocidos: &mut Vec<Certificate>) -> Result<()> {
        let mut c = hoja.clone();
        for _ in 0..8 {
            self.cert(&c)?;
            if autofirmado(&c) { return Ok(()); }
            let e = emisor(&c, conocidos)?;
            self.revocacion(&c, &e).with_context(|| format!("revocación de {}", c.tbs_certificate.subject))?;
            c = e;
        }
        bail!("cadena demasiado larga")
    }
    /// OCSP si el certificado lo tiene (quien firma); si no, la lista de revocación de su CA.
    fn revocacion(&mut self, c: &Certificate, emisor: &Certificate) -> Result<()> {
        for url in uris_aia(c, OID_OCSP) {
            if let Ok(r) = ocsp(c, emisor, &url) { self.ocsps.push(r); return Ok(()); }
        }
        let urls = uris_crl(c);
        if urls.iter().any(|u| self.crl_bajadas.contains(u)) { return Ok(()); }
        for url in &urls {
            let Ok(crl) = descargar(url, None, None) else { continue };
            if crl.len() > CRL_MAXIMA { bail!("la lista de revocación {url} es demasiado grande"); }
            self.crl_bajadas.extend(urls.iter().cloned());
            if !self.crls.contains(&crl) { self.crls.push(crl); }
            return Ok(());
        }
        bail!("no se pudo comprobar la revocación (ni OCSP ni lista de revocación)")
    }
}

/// El CMS de la última firma del PDF (el contenido de su /Contents, sin el relleno de ceros).
fn ultima_firma(pdf: &[u8]) -> Result<Vec<u8>> {
    let aguja = b"/Contents <";
    let pos = pdf.windows(aguja.len()).rposition(|w| w == aguja).ok_or_else(|| anyhow!("el PDF no está firmado"))? + aguja.len();
    let fin = pos + pdf[pos..].iter().position(|&b| b == b'>').ok_or_else(|| anyhow!("firma sin cierre"))?;
    let hexa = std::str::from_utf8(&pdf[pos..fin])?;
    let crudo = hex::decode(hexa)?;
    // DER: el largo real sale del encabezado de la SEQUENCE; lo demás es relleno.
    let mut lector = der::SliceReader::new(&crudo).map_err(|e| anyhow!("firma ilegible: {e}"))?;
    let enc = <der::Header as der::Decode>::decode(&mut lector).map_err(|e| anyhow!("firma ilegible: {e}"))?;
    let total = u32::from(enc.length) as usize + u32::from(enc.encoded_len()?) as usize;
    Ok(crudo[..total].to_vec())
}

fn certs_de(sd: &SignedData) -> Vec<Certificate> {
    sd.certificates.iter().flat_map(|s| s.0.iter()).filter_map(|c| match c {
        cms::cert::CertificateChoices::Certificate(c) => Some(c.clone()),
        _ => None,
    }).collect()
}

/// Agrega el DSS (PAdES-LT) a un PDF recién firmado, en una actualización incremental que no
/// toca lo firmado.
pub fn agregar(pdf: &[u8]) -> Result<Vec<u8>> {
    let cms_der = ultima_firma(pdf)?;
    let ci = ContentInfo::from_der(&cms_der).map_err(|e| anyhow!("CMS ilegible: {e}"))?;
    let sd: SignedData = ci.content.decode_as().map_err(|e| anyhow!("SignedData ilegible: {e}"))?;
    let firmante = sd.signer_infos.0.iter().next().ok_or_else(|| anyhow!("firma sin firmante"))?;
    let certs = certs_de(&sd);
    let cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(ias) = &firmante.sid else { bail!("firmante sin emisor y serie") };
    let hoja = certs.iter().find(|c| c.tbs_certificate.serial_number == ias.serial_number && c.tbs_certificate.issuer == ias.issuer)
        .ok_or_else(|| anyhow!("la firma no trae el certificado de quien firma"))?;

    let mut conocidos = conocidos();
    conocidos.extend(certs.iter().cloned());
    let mut pruebas = Pruebas::default();
    pruebas.cadena(hoja, &mut conocidos).context("cadena de quien firma")?;

    // Sello de tiempo del SINPE: su certificado (TSA SINPE) y la cadena hasta la raíz.
    let token = firmante.unsigned_attrs.iter().flat_map(|a| a.iter()).find(|a| a.oid == OID_TIMESTAMP_TOKEN)
        .and_then(|a| a.values.iter().next()).ok_or_else(|| anyhow!("la firma no tiene sello de tiempo"))?;
    let tci = ContentInfo::from_der(&token.to_der()?).map_err(|e| anyhow!("sello de tiempo ilegible: {e}"))?;
    let tsd: SignedData = tci.content.decode_as().map_err(|e| anyhow!("sello de tiempo ilegible: {e}"))?;
    let tsa_certs = certs_de(&tsd);
    conocidos.extend(tsa_certs.iter().cloned());
    let tsa = tsd.signer_infos.0.iter().next().and_then(|si| match &si.sid {
        cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(i) => tsa_certs.iter().find(|c| c.tbs_certificate.serial_number == i.serial_number),
        _ => tsa_certs.first(),
    }).ok_or_else(|| anyhow!("el sello de tiempo no trae el certificado del TSA"))?;
    pruebas.cadena(tsa, &mut conocidos).context("cadena del sello de tiempo")?;

    escribir_dss(pdf, &cms_der, &pruebas)
}

fn escribir_dss(pdf: &[u8], cms_der: &[u8], p: &Pruebas) -> Result<Vec<u8>> {
    let doc = lopdf::Document::load_mem(pdf).context("No se pudo releer el PDF firmado")?;
    let raiz_ref = doc.trailer.get(b"Root")?.as_reference()?;
    let mut catalogo = doc.get_object(raiz_ref)?.as_dict()?.clone();

    let mut siguiente = doc.max_id + 1;
    let mut agregado: Vec<u8> = b"\n".to_vec();
    let mut offsets: Vec<(u32, usize)> = vec![];
    let mut flujo = |datos: &[u8], agregado: &mut Vec<u8>, offsets: &mut Vec<(u32, usize)>| -> u32 {
        let id = siguiente;
        siguiente += 1;
        offsets.push((id, pdf.len() + agregado.len()));
        agregado.extend_from_slice(format!("{id} 0 obj\n<< /Length {} >>\nstream\n", datos.len()).as_bytes());
        agregado.extend_from_slice(datos);
        agregado.extend_from_slice(b"\nendstream\nendobj\n");
        id
    };
    let refs = |ids: &[u32]| ids.iter().map(|i| format!("{i} 0 R")).collect::<Vec<_>>().join(" ");
    let certs: Vec<u32> = p.certs.iter().map(|d| flujo(d, &mut agregado, &mut offsets)).collect();
    let ocsps: Vec<u32> = p.ocsps.iter().map(|d| flujo(d, &mut agregado, &mut offsets)).collect();
    let crls: Vec<u32> = p.crls.iter().map(|d| flujo(d, &mut agregado, &mut offsets)).collect();

    // VRI: lo que valida ESTA firma, bajo el SHA-1 (en mayúsculas) de su /Contents.
    let vri_clave = hex::encode_upper(Sha1::digest(cms_der));
    let id_dss = siguiente;
    offsets.push((id_dss, pdf.len() + agregado.len()));
    agregado.extend_from_slice(format!(
        "{id_dss} 0 obj\n<< /Type /DSS /Certs [{c}] /OCSPs [{o}] /CRLs [{r}] /VRI << /{vri_clave} << /Type /VRI /Cert [{c}] /OCSP [{o}] /CRL [{r}] >> >> >>\nendobj\n",
        c = refs(&certs), o = refs(&ocsps), r = refs(&crls)).as_bytes());

    catalogo.set("DSS", lopdf::Object::Reference((id_dss, 0)));
    let mut ext = lopdf::Dictionary::new();
    ext.set("BaseVersion", lopdf::Object::Name(b"1.7".to_vec()));
    ext.set("ExtensionLevel", lopdf::Object::Integer(5));
    let mut exts = match catalogo.get(b"Extensions") { Ok(lopdf::Object::Dictionary(d)) => d.clone(), _ => lopdf::Dictionary::new() };
    exts.set("ESIC", lopdf::Object::Dictionary(ext));
    catalogo.set("Extensions", lopdf::Object::Dictionary(exts));
    offsets.push((raiz_ref.0, pdf.len() + agregado.len()));
    agregado.extend_from_slice(format!("{} {} obj\n{}\nendobj\n", raiz_ref.0, raiz_ref.1, dict_a_texto(&catalogo)).as_bytes());

    let inicio_xref = pdf.len() + agregado.len();
    offsets.sort();
    agregado.extend_from_slice(b"xref\n");
    for (id, off) in &offsets {
        let gen = if *id == raiz_ref.0 { raiz_ref.1 } else { 0 };
        agregado.extend_from_slice(format!("{id} 1\n{off:010} {gen:05} n \n").as_bytes());
    }
    let mut trailer = format!("trailer\n<< /Size {} /Root {} {} R /Prev {}", id_dss + 1, raiz_ref.0, raiz_ref.1, encontrar_startxref(pdf)?);
    if let Ok(info) = doc.trailer.get(b"Info") { trailer.push_str(&format!(" /Info {}", objeto_a_texto(info))); }
    if let Ok(idd) = doc.trailer.get(b"ID") { trailer.push_str(&format!(" /ID {}", objeto_a_texto(idd))); }
    trailer.push_str(" >>\n");
    agregado.extend_from_slice(trailer.as_bytes());
    agregado.extend_from_slice(format!("startxref\n{inicio_xref}\n%%EOF\n").as_bytes());

    let mut bytes = pdf.to_vec();
    bytes.extend_from_slice(&agregado);
    Ok(bytes)
}

#[cfg(test)]
mod pruebas {
    /// Agrega el DSS a un PDF ya firmado con la tarjeta (no hace falta la tarjeta ni el PIN):
    /// `LTV_ENTRADA=… LTV_SALIDA=… cargo test ltv_sobre_pdf -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn ltv_sobre_pdf() {
        let entrada = std::env::var("LTV_ENTRADA").expect("LTV_ENTRADA");
        let salida = std::env::var("LTV_SALIDA").expect("LTV_SALIDA");
        let pdf = std::fs::read(entrada).unwrap();
        let con = super::agregar(&pdf).unwrap();
        std::fs::write(salida, &con).unwrap();
        println!("DSS agregado: {} → {} bytes", pdf.len(), con.len());
    }
}
