# KuantaSign

Firma documentos PDF con la **tarjeta de Firma Digital de Costa Rica**, desde los sistemas de
Kuanta Bridge (K360 / Payroll360): la persona dibuja en el documento dónde va la firma, digita el
PIN y el PDF queda firmado en formato **PAdES** (como Adobe), con sello de tiempo del **SINPE** y un
sello visible.

- Corre en la bandeja (Windows) o en la barra de menú (macOS) y arranca con la computadora.
- Escucha solo en `127.0.0.1:3517` y solo atiende a los sitios autorizados de Kuanta.
- Usa el controlador oficial de la tarjeta (PKCS#11: IDEMIA o Athena), el mismo que instala el
  paquete de Firma Digital.

Hecho en Rust/Tauri. El formato de firma sigue al **Firmador** (https://firmador.libre.cr,
https://codeberg.org/firmador/firmador), del que KuantaSign es una obra derivada.

## Licencia

GNU General Public License v3.0 o posterior (ver `LICENSE`).
