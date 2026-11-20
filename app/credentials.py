"""Opt-in durable API credentials. Legacy environment keys remain the default."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

SCHEMA_VERSION = "1"
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_SID = re.compile(r"S-\d+(?:-\d+)+\Z", re.IGNORECASE)
_REPOSITORY = Path(__file__).resolve().parent.parent
_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_DIRECTORY_ACCESS = 0x001201DF  # generic read/write plus FILE_DELETE_CHILD
_FILE_ACCESS = 0x0013019F  # generic read/write plus DELETE
_OBJECT_INHERIT_ACE = 0x01
_CONTAINER_INHERIT_ACE = 0x02
_NO_PROPAGATE_INHERIT_ACE = 0x04
_INHERIT_ONLY_ACE = 0x08
_INHERITED_ACE = 0x10
_SE_DACL_PROTECTED = 0x1000
_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


class CredentialBackendError(RuntimeError):
    """Sanitized fail-closed backend error."""


@dataclass(frozen=True)
class AuthenticatedCredential:
    credential_id: str
    developer_id: str


def backend_name(env=None):
    if env is None:
        from app.startup import runtime_environment
        env = runtime_environment()
    return env.get("AGENTVERIFY_CREDENTIAL_BACKEND", "legacy")


def configuration_errors(env=None):
    if env is None:
        from app.startup import runtime_environment
        env = runtime_environment()
    backend = backend_name(env)
    if backend == "legacy":
        return []
    if backend != "sqlite":
        return ["Unsupported credential backend"]
    errors = []
    path = env.get("AGENTVERIFY_CREDENTIAL_DB", "")
    if not path or not Path(path).is_absolute():
        errors.append("Durable credential database path must be absolute")
    if not _SID.fullmatch(env.get("AGENTVERIFY_CREDENTIAL_OWNER_SID", "").strip()):
        errors.append("Durable credential owner SID is required")
    if not _SID.fullmatch(env.get("AGENTVERIFY_CREDENTIAL_SERVICE_SID", "").strip()):
        errors.append("Durable credential service SID is required")
    if len(env.get("AGENTVERIFY_CREDENTIAL_PEPPER", "")) < 32:
        errors.append("Durable credential pepper must be at least 32 characters")
    if env.get("AGENTVERIFY_API_KEYS", "").strip():
        errors.append("Durable and legacy credential sources cannot be combined")
    return errors


def _settings(env=None):
    if env is None:
        from app.startup import runtime_environment
        env = runtime_environment()
    if configuration_errors(env):
        raise CredentialBackendError("Credential backend configuration invalid")
    path = Path(env["AGENTVERIFY_CREDENTIAL_DB"])
    policy = (env["AGENTVERIFY_CREDENTIAL_OWNER_SID"].strip(),
              env["AGENTVERIFY_CREDENTIAL_SERVICE_SID"].strip())
    _validate_storage(path, policy, require_file=False)
    return path, env["AGENTVERIFY_CREDENTIAL_PEPPER"].encode(), policy


def _inside(path, root):
    try:
        return os.path.commonpath((os.path.normcase(path), os.path.normcase(root))) == os.path.normcase(root)
    except ValueError:
        return False


if os.name == "nt":
    _advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x1
    _DACL_SECURITY_INFORMATION = 0x4
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    _INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _ACCESS_DENIED_ACE_TYPE = 1

    class _ACL_SIZE_INFORMATION(ctypes.Structure):
        _fields_ = (("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD),
                    ("AclBytesFree", wintypes.DWORD))

    class _ACE_HEADER(ctypes.Structure):
        _fields_ = (("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte),
                    ("AceSize", wintypes.WORD))

    class _TRUSTEE(ctypes.Structure):
        _fields_ = (("pMultipleTrustee", ctypes.c_void_p), ("MultipleTrusteeOperation", ctypes.c_int),
                    ("TrusteeForm", ctypes.c_int), ("TrusteeType", ctypes.c_int),
                    ("ptstrName", ctypes.c_void_p))

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = (("dwFileAttributes", wintypes.DWORD), ("ftCreationTime", wintypes.FILETIME),
                    ("ftLastAccessTime", wintypes.FILETIME), ("ftLastWriteTime", wintypes.FILETIME),
                    ("dwVolumeSerialNumber", wintypes.DWORD), ("nFileSizeHigh", wintypes.DWORD),
                    ("nFileSizeLow", wintypes.DWORD), ("nNumberOfLinks", wintypes.DWORD),
                    ("nFileIndexHigh", wintypes.DWORD), ("nFileIndexLow", wintypes.DWORD))

    _advapi.GetNamedSecurityInfoW.argtypes = (wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    _advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    _advapi.GetSecurityDescriptorDacl.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL))
    _advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    _advapi.GetSecurityDescriptorControl.argtypes = (ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD))
    _advapi.GetSecurityDescriptorControl.restype = wintypes.BOOL
    _advapi.GetAclInformation.argtypes = (ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int)
    _advapi.GetAclInformation.restype = wintypes.BOOL
    _advapi.GetAce.argtypes = (ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p))
    _advapi.GetAce.restype = wintypes.BOOL
    _advapi.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
    _advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    _advapi.ConvertStringSidToSidW.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p))
    _advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
    _advapi.BuildTrusteeWithSidW.argtypes = (ctypes.POINTER(_TRUSTEE), ctypes.c_void_p)
    _advapi.GetEffectiveRightsFromAclW.argtypes = (ctypes.c_void_p, ctypes.POINTER(_TRUSTEE),
                                                    ctypes.POINTER(wintypes.DWORD))
    _advapi.GetEffectiveRightsFromAclW.restype = wintypes.DWORD
    _kernel.GetFileAttributesW.argtypes = (wintypes.LPCWSTR,)
    _kernel.GetFileAttributesW.restype = wintypes.DWORD
    _kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    _kernel.CreateFileW.restype = wintypes.HANDLE
    _kernel.GetFileInformationByHandle.argtypes = (wintypes.HANDLE,
                                                    ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION))
    _kernel.GetFileInformationByHandle.restype = wintypes.BOOL


def _local_free(pointer):
    if pointer:
        _kernel.LocalFree(pointer)


def _sid_text(pointer):
    text = wintypes.LPWSTR()
    if not _advapi.ConvertSidToStringSidW(pointer, ctypes.byref(text)):
        raise CredentialBackendError("Credential storage security invalid")
    try:
        return text.value.upper()
    finally:
        _local_free(text)


def _sid_pointer(value):
    pointer = ctypes.c_void_p()
    if not value or not _advapi.ConvertStringSidToSidW(value, ctypes.byref(pointer)):
        raise CredentialBackendError("Credential storage security invalid")
    return pointer


def _security_state(path, owner_sid, service_sid, required_access, *, directory):
    if os.name != "nt":
        raise CredentialBackendError("Durable credential storage requires Windows ACL validation")
    owner = ctypes.c_void_p(); dacl = ctypes.c_void_p(); descriptor = ctypes.c_void_p()
    result = _advapi.GetNamedSecurityInfoW(str(path), _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION, ctypes.byref(owner), None,
        ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if result or not descriptor or not owner:
        _local_free(descriptor)
        raise CredentialBackendError("Credential storage security unavailable")
    service_pointer = None
    try:
        present = wintypes.BOOL(); defaulted = wintypes.BOOL(); checked_dacl = ctypes.c_void_p()
        if not _advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
                ctypes.byref(checked_dacl), ctypes.byref(defaulted)) or not present or not checked_dacl:
            raise CredentialBackendError("Credential storage security invalid")
        if checked_dacl.value != dacl.value:
            raise CredentialBackendError("Credential storage security invalid")
        control = wintypes.WORD(); revision = wintypes.DWORD()
        if not _advapi.GetSecurityDescriptorControl(descriptor, ctypes.byref(control),
                                                     ctypes.byref(revision)):
            raise CredentialBackendError("Credential storage security invalid")
        if directory and not control.value & _SE_DACL_PROTECTED:
            raise CredentialBackendError("Credential storage inheritance unprotected")
        owner_text = _sid_text(owner)
        if owner_text != owner_sid.upper():
            raise CredentialBackendError("Credential storage owner invalid")
        approved = {owner_sid.upper(), service_sid.upper(), _SYSTEM_SID, _ADMINISTRATORS_SID}
        info = _ACL_SIZE_INFORMATION()
        if not _advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
            raise CredentialBackendError("Credential storage security invalid")
        entries = []
        for index in range(info.AceCount):
            ace = ctypes.c_void_p()
            if not _advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise CredentialBackendError("Credential storage security invalid")
            header = ctypes.cast(ace, ctypes.POINTER(_ACE_HEADER)).contents
            if header.AceType not in (_ACCESS_ALLOWED_ACE_TYPE, _ACCESS_DENIED_ACE_TYPE) or header.AceSize < 12:
                raise CredentialBackendError("Credential storage security ambiguous")
            mask = wintypes.DWORD.from_address(ace.value + 4).value
            trustee = _sid_text(ctypes.c_void_p(ace.value + 8))
            if trustee not in approved:
                raise CredentialBackendError("Credential storage trustee invalid")
            flags = header.AceFlags
            if header.AceType == _ACCESS_DENIED_ACE_TYPE:
                raise CredentialBackendError("Credential storage deny ACE prohibited")
            if flags & (_NO_PROPAGATE_INHERIT_ACE | _INHERIT_ONLY_ACE):
                raise CredentialBackendError("Credential storage inheritance ambiguous")
            if directory:
                if flags & _INHERITED_ACE or not flags & _OBJECT_INHERIT_ACE:
                    raise CredentialBackendError("Credential storage file inheritance invalid")
            elif flags & (_OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE):
                raise CredentialBackendError("Credential file inheritance invalid")
            entries.append((header.AceType, header.AceFlags, mask, trustee))
        if directory:
            inheritable = {entry[3] for entry in entries
                           if entry[0] == _ACCESS_ALLOWED_ACE_TYPE and
                           entry[1] & _OBJECT_INHERIT_ACE}
            if not approved <= inheritable:
                raise CredentialBackendError("Credential storage inheritable trustees missing")
        service_pointer = _sid_pointer(service_sid)
        trustee = _TRUSTEE(); _advapi.BuildTrusteeWithSidW(ctypes.byref(trustee), service_pointer)
        effective = wintypes.DWORD()
        if _advapi.GetEffectiveRightsFromAclW(dacl, ctypes.byref(trustee), ctypes.byref(effective)):
            raise CredentialBackendError("Credential storage effective access unavailable")
        if effective.value & required_access != required_access:
            raise CredentialBackendError("Credential storage service access insufficient")
        return (owner_text, tuple(entries), effective.value, control.value)
    finally:
        _local_free(service_pointer)
        _local_free(descriptor)


def _attributes(path):
    value = _kernel.GetFileAttributesW(str(path)) if os.name == "nt" else _INVALID_FILE_ATTRIBUTES
    if value == _INVALID_FILE_ATTRIBUTES:
        raise CredentialBackendError("Credential storage path unavailable")
    return value


def _file_identity(path, *, directory=False):
    flags = 0x00200000 | 0x02000000  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
    handle = _kernel.CreateFileW(str(path), 0x00020000, 0x7, None, 3, flags, None)
    if handle == _INVALID_HANDLE_VALUE:
        raise CredentialBackendError("Credential storage identity unavailable")
    try:
        info = _BY_HANDLE_FILE_INFORMATION()
        if not _kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise CredentialBackendError("Credential storage identity unavailable")
        if info.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise CredentialBackendError("Credential storage reparse points prohibited")
        return (info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow,
                info.dwFileAttributes)
    finally:
        _kernel.CloseHandle(handle)


def _validate_storage(path, policy, *, require_file):
    path = Path(path)
    owner_sid, service_sid = policy
    if os.name != "nt" or not path.is_absolute() or not owner_sid or not service_sid:
        raise CredentialBackendError("Credential storage policy invalid")
    resolved = path.resolve(strict=False)
    if _inside(str(resolved), str(_REPOSITORY)):
        raise CredentialBackendError("Credential storage must be external")
    anchor = Path(path.anchor)
    current = anchor
    for part in path.parts[1:]:
        current /= part
        if current.exists() or current == path.parent:
            if _attributes(current) & _FILE_ATTRIBUTE_REPARSE_POINT:
                raise CredentialBackendError("Credential storage reparse points prohibited")
    if not path.parent.is_dir():
        raise CredentialBackendError("Credential storage parent unavailable")
    directory_state = (_file_identity(path.parent, directory=True),
                       _security_state(path.parent, owner_sid, service_sid,
                                       _DIRECTORY_ACCESS, directory=True))
    file_state = None
    if path.exists():
        if not path.is_file() or _attributes(path) & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise CredentialBackendError("Credential database path invalid")
        file_state = (_file_identity(path),
                      _security_state(path, owner_sid, service_sid, _FILE_ACCESS, directory=False))
    elif require_file:
        raise CredentialBackendError("Credential backend unavailable")
    sidecars = {}
    for suffix in _SIDECAR_SUFFIXES:
        sidecar = Path(str(path) + suffix)
        if sidecar.exists():
            if not sidecar.is_file() or _attributes(sidecar) & _FILE_ATTRIBUTE_REPARSE_POINT:
                raise CredentialBackendError("Credential sidecar path invalid")
            sidecars[suffix] = (_file_identity(sidecar),
                _security_state(sidecar, owner_sid, service_sid, _FILE_ACCESS, directory=False))
    return resolved, directory_state, file_state, tuple(sorted(sidecars.items()))


def _verifier(secret, pepper):
    return hmac.new(pepper, secret.encode("utf-8"), hashlib.sha256).hexdigest()


def _connect(path, *, create=False, policy=None):
    db = None
    try:
        if policy is None:
            raise CredentialBackendError("Credential storage policy invalid")
        before = _validate_storage(path, policy, require_file=not create)
        db = sqlite3.connect(path, timeout=5, isolation_level=None)
        after = _validate_storage(path, policy, require_file=True)
        if (before[0:2] != after[0:2] or
                (before[2] is not None and before[2] != after[2]) or before[3] != after[3]):
            raise CredentialBackendError("Credential storage changed during connection")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        return db
    except (OSError, sqlite3.Error) as exc:
        if db is not None:
            db.close()
        raise CredentialBackendError("Credential backend unavailable") from exc
    except Exception:
        if db is not None:
            db.close()
        raise


def migrate(path, *, env=None):
    """Explicit migration; authentication never creates or upgrades schema."""
    env = os.environ if env is None else env
    configured_path, _, policy = _settings(env)
    path = Path(path)
    if path != configured_path:
        raise ValueError("Migration path must match configured credential storage")
    db = _connect(path, create=True, policy=policy)
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("CREATE TABLE IF NOT EXISTS credential_schema (version TEXT NOT NULL)")
        row = db.execute("SELECT version FROM credential_schema").fetchone()
        if row is None:
            db.execute("INSERT INTO credential_schema(version) VALUES (?)", (SCHEMA_VERSION,))
        elif row[0] != SCHEMA_VERSION:
            raise CredentialBackendError("Unsupported credential schema")
        db.execute("""CREATE TABLE IF NOT EXISTS credentials (
            credential_id TEXT PRIMARY KEY,
            developer_id TEXT NOT NULL,
            verifier TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL CHECK(status IN ('active','rotated','revoked')),
            issued_at TEXT NOT NULL,
            revoked_at TEXT,
            replaces TEXT REFERENCES credentials(credential_id)
        )""")
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _check_schema(db):
    try:
        schema_columns = {row[1] for row in db.execute("PRAGMA table_info(credential_schema)")}
        rows = db.execute("SELECT version FROM credential_schema").fetchall()
        if schema_columns != {"version"} or rows != [(SCHEMA_VERSION,)]:
            raise CredentialBackendError("Credential schema invalid")
        columns = {row[1] for row in db.execute("PRAGMA table_info(credentials)")}
        if columns != {"credential_id", "developer_id", "verifier", "status", "issued_at", "revoked_at", "replaces"}:
            raise CredentialBackendError("Credential schema invalid")
    except sqlite3.Error as exc:
        raise CredentialBackendError("Credential schema unavailable") from exc


def issue(developer_id, *, env=None, secret=None, replaces=None):
    if not isinstance(developer_id, str) or not _LABEL.fullmatch(developer_id):
        raise ValueError("Invalid developer identifier")
    path, pepper, policy = _settings(env)
    secret = secret or "avp_" + secrets.token_urlsafe(32)
    if len(secret) < 32:
        raise ValueError("Credential is too short")
    verifier = _verifier(secret, pepper)
    credential_id = "ak_" + verifier[:32]
    db = _connect(path, policy=policy)
    try:
        db.execute("BEGIN IMMEDIATE")
        _check_schema(db)
        db.execute("INSERT INTO credentials VALUES (?,?,?,?,?,?,?)",
                   (credential_id, developer_id, verifier, "active",
                    datetime.now(timezone.utc).isoformat(), None, replaces))
        db.commit()
        return secret, credential_id
    except (sqlite3.Error, CredentialBackendError) as exc:
        db.rollback()
        if isinstance(exc, CredentialBackendError):
            raise
        raise CredentialBackendError("Credential issuance failed") from exc
    finally:
        db.close()


def revoke(credential_id, *, env=None, reason="revoked"):
    if reason not in {"revoked", "rotated"}:
        raise ValueError("Invalid terminal credential state")
    path, _, policy = _settings(env)
    db = _connect(path, policy=policy)
    try:
        db.execute("BEGIN IMMEDIATE")
        _check_schema(db)
        changed = db.execute("UPDATE credentials SET status=?, revoked_at=? WHERE credential_id=? AND status='active'",
                             (reason, datetime.now(timezone.utc).isoformat(), credential_id)).rowcount
        if changed != 1:
            raise CredentialBackendError("Credential is not active")
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def rotate(credential_id, *, env=None, secret=None):
    path, pepper, policy = _settings(env)
    secret = secret or "avp_" + secrets.token_urlsafe(32)
    if len(secret) < 32:
        raise ValueError("Credential is too short")
    verifier = _verifier(secret, pepper)
    replacement_id = "ak_" + verifier[:32]
    db = _connect(path, policy=policy)
    try:
        db.execute("BEGIN IMMEDIATE")
        _check_schema(db)
        row = db.execute("SELECT developer_id FROM credentials WHERE credential_id=? AND status='active'",
                         (credential_id,)).fetchone()
        if row is None:
            raise CredentialBackendError("Credential is not active")
        now = datetime.now(timezone.utc).isoformat()
        db.execute("INSERT INTO credentials VALUES (?,?,?,?,?,?,?)",
                   (replacement_id, row[0], verifier, "active", now, None, credential_id))
        db.execute("UPDATE credentials SET status='rotated', revoked_at=? WHERE credential_id=?",
                   (now, credential_id))
        db.commit()
        return secret, replacement_id
    except (sqlite3.Error, CredentialBackendError) as exc:
        db.rollback()
        if isinstance(exc, CredentialBackendError):
            raise
        raise CredentialBackendError("Credential rotation failed") from exc
    finally:
        db.close()


def authenticate(secret, *, env=None):
    path, pepper, policy = _settings(env)
    verifier = _verifier(secret, pepper)
    db = _connect(path, policy=policy)
    try:
        _check_schema(db)
        row = db.execute("SELECT credential_id, developer_id FROM credentials WHERE verifier=? AND status='active'",
                         (verifier,)).fetchone()
        return None if row is None else AuthenticatedCredential(*row)
    except CredentialBackendError:
        raise
    except sqlite3.Error as exc:
        raise CredentialBackendError("Credential authentication failed") from exc
    finally:
        db.close()


def healthcheck(*, env=None):
    path, _, policy = _settings(env)
    db = _connect(path, policy=policy)
    try:
        _check_schema(db)
        db.execute("SELECT 1").fetchone()
        return True
    except sqlite3.Error as exc:
        raise CredentialBackendError("Credential health check failed") from exc
    finally:
        db.close()


def diagnostic_state(env=None):
    """Low-cardinality state only; never paths, developer IDs or secrets."""
    backend = backend_name(env)
    return {"backend": backend, "configured": not configuration_errors(env)}
