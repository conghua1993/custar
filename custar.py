"""
CSTA (custar) encrypted archive format — pack / unpack.

Format notes follow readme.txt (little-endian throughout).
"""

from __future__ import annotations

import os
import struct
import zlib
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass
from hashlib import scrypt
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable

ProgressCallback = Callable[[int, int, str], None]  # done, total, path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CSTA"
CSTC_MAGIC = b"CSTC"
VERSION = 1
HEADER_SIZE = 48
FLAG_ZLIB = 0x0001

TYPE_DIRECTORY = 1
TYPE_FILE = 2
TYPE_SYMLINK = 3

STORE = 0
ZLIB_METHOD = 1

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32
NONCE_LEN = 12
SALT_LEN = 16
GCM_TAG_LEN = 16

ZLIB_LEVEL = 6
ZLIB_MAX_SIZE = 8 * 1024 * 1024  # >= 8 MiB -> STORE
CHUNK_PLAINTEXT_MAX = 1 << 30  # 1 GiB


@dataclass
class CatalogEntry:
    path: str
    type: int
    data_offset: int = 0
    cipher_len: int = 0
    raw_size: int = 0
    comp_method: int = STORE
    file_nonce: bytes = b""
    link_target: str = ""


def derive_key(password: str | bytes, salt: bytes) -> bytes:
    pw = password.encode("utf-8") if isinstance(password, str) else password
    return scrypt(pw, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_LEN)


def _normalize_rel_path(path: str) -> str:
    p = path.replace("\\", "/").strip("/")
    parts = [x for x in p.split("/") if x not in ("", ".")]
    if not parts or any(x == ".." for x in parts):
        raise ValueError(f"invalid archive path: {path!r}")
    return "/".join(parts)


def _compress_payload(raw: bytes) -> tuple[bytes, int]:
    if len(raw) == 0 or len(raw) >= ZLIB_MAX_SIZE:
        return raw, STORE
    compressed = zlib.compress(raw, ZLIB_LEVEL)
    if len(compressed) < len(raw):
        return compressed, ZLIB_METHOD
    return raw, STORE


def _decompress_payload(payload: bytes, comp_method: int, raw_size: int) -> bytes:
    if comp_method == STORE:
        data = payload
    elif comp_method == ZLIB_METHOD:
        data = zlib.decompress(payload)
    else:
        raise ValueError(f"unknown comp_method: {comp_method}")
    if raw_size and len(data) != raw_size:
        raise ValueError(f"raw size mismatch: got {len(data)}, expected {raw_size}")
    return data


def _encrypt_single(key: bytes, nonce: bytes, plaintext: bytes, entry_index: int) -> bytes:
    aad = struct.pack("<I", entry_index)
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def _decrypt_single(key: bytes, nonce: bytes, ciphertext: bytes, entry_index: int) -> bytes:
    aad = struct.pack("<I", entry_index)
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def _chunk_aad(file_nonce: bytes, entry_index: int, chunk_index: int) -> bytes:
    # file_nonce binds chunks in AAD together with entry_index + chunk_index
    return file_nonce + struct.pack("<II", entry_index, chunk_index)


def _encrypt_chunked(key: bytes, file_nonce: bytes, plaintext: bytes, entry_index: int) -> bytes:
    aes = AESGCM(key)
    chunks: list[tuple[bytes, bytes]] = []
    offset = 0
    chunk_index = 0
    while offset < len(plaintext):
        piece = plaintext[offset : offset + CHUNK_PLAINTEXT_MAX]
        chunk_nonce = os.urandom(NONCE_LEN)
        ct = aes.encrypt(chunk_nonce, piece, _chunk_aad(file_nonce, entry_index, chunk_index))
        chunks.append((chunk_nonce, ct))
        offset += len(piece)
        chunk_index += 1

    out = bytearray()
    out += CSTC_MAGIC
    out += struct.pack("<BBHI", 1, 0, 0, len(chunks))  # ver, flags, reserved, n_chunks
    for chunk_nonce, ct in chunks:
        out += chunk_nonce
        out += struct.pack("<I", len(ct))
        out += ct
    return bytes(out)


def _decrypt_chunked(key: bytes, file_nonce: bytes, blob: bytes, entry_index: int) -> bytes:
    if len(blob) < 4 + 8 or blob[:4] != CSTC_MAGIC:
        raise ValueError("invalid CSTC blob")
    ver, flags, _reserved, n_chunks = struct.unpack_from("<BBHI", blob, 4)
    if ver != 1:
        raise ValueError(f"unsupported CSTC version: {ver}")
    pos = 12
    aes = AESGCM(key)
    parts: list[bytes] = []
    for chunk_index in range(n_chunks):
        if pos + NONCE_LEN + 4 > len(blob):
            raise ValueError("truncated CSTC chunk header")
        chunk_nonce = blob[pos : pos + NONCE_LEN]
        pos += NONCE_LEN
        (ct_len,) = struct.unpack_from("<I", blob, pos)
        pos += 4
        if pos + ct_len > len(blob):
            raise ValueError("truncated CSTC chunk ciphertext")
        ct = blob[pos : pos + ct_len]
        pos += ct_len
        parts.append(aes.decrypt(chunk_nonce, ct, _chunk_aad(file_nonce, entry_index, chunk_index)))
    if flags:
        pass  # reserved
    return b"".join(parts)


def encrypt_payload(key: bytes, file_nonce: bytes, payload: bytes, entry_index: int) -> bytes:
    if len(payload) > CHUNK_PLAINTEXT_MAX:
        return _encrypt_chunked(key, file_nonce, payload, entry_index)
    return _encrypt_single(key, file_nonce, payload, entry_index)


def decrypt_blob(key: bytes, file_nonce: bytes, blob: bytes, entry_index: int) -> bytes:
    if blob.startswith(CSTC_MAGIC):
        return _decrypt_chunked(key, file_nonce, blob, entry_index)
    return _decrypt_single(key, file_nonce, blob, entry_index)


def encode_catalog(entries: list[CatalogEntry]) -> bytes:
    out = bytearray()
    out += struct.pack("<I", len(entries))
    for e in entries:
        path_b = e.path.encode("utf-8")
        if len(path_b) > 0xFFFF:
            raise ValueError(f"path too long: {e.path!r}")
        out += struct.pack("<H", len(path_b))
        out += path_b
        out += struct.pack("<B", e.type)
        if e.type == TYPE_DIRECTORY:
            continue
        if e.type == TYPE_FILE:
            out += struct.pack("<QQQ", e.data_offset, e.cipher_len, e.raw_size)
            out += struct.pack("<B", e.comp_method)
            if len(e.file_nonce) != NONCE_LEN:
                raise ValueError("file_nonce must be 12 bytes")
            out += e.file_nonce
        elif e.type == TYPE_SYMLINK:
            target_b = e.link_target.encode("utf-8")
            if len(target_b) > 0xFFFF:
                raise ValueError("symlink target too long")
            out += struct.pack("<H", len(target_b))
            out += target_b
        else:
            raise ValueError(f"unknown entry type: {e.type}")
    return bytes(out)


def decode_catalog(data: bytes) -> list[CatalogEntry]:
    if len(data) < 4:
        raise ValueError("catalog too short")
    (count,) = struct.unpack_from("<I", data, 0)
    pos = 4
    entries: list[CatalogEntry] = []
    for _ in range(count):
        if pos + 3 > len(data):
            raise ValueError("truncated catalog entry")
        (path_len,) = struct.unpack_from("<H", data, pos)
        pos += 2
        path = data[pos : pos + path_len].decode("utf-8")
        pos += path_len
        (typ,) = struct.unpack_from("<B", data, pos)
        pos += 1
        e = CatalogEntry(path=path, type=typ)
        if typ == TYPE_DIRECTORY:
            pass
        elif typ == TYPE_FILE:
            e.data_offset, e.cipher_len, e.raw_size = struct.unpack_from("<QQQ", data, pos)
            pos += 24
            (e.comp_method,) = struct.unpack_from("<B", data, pos)
            pos += 1
            e.file_nonce = data[pos : pos + NONCE_LEN]
            pos += NONCE_LEN
        elif typ == TYPE_SYMLINK:
            (target_len,) = struct.unpack_from("<H", data, pos)
            pos += 2
            e.link_target = data[pos : pos + target_len].decode("utf-8")
            pos += target_len
        else:
            raise ValueError(f"unknown entry type: {typ}")
        entries.append(e)
    return entries


def _build_header(
    flags: int,
    salt: bytes,
    catalog_offset: int,
    catalog_len: int,
    catalog_nonce: bytes,
) -> bytes:
    body = struct.pack(
        "<HH16sQI12s",
        VERSION,
        flags,
        salt,
        catalog_offset,
        catalog_len,
        catalog_nonce,
    )
    return MAGIC + body


def parse_header(buf: bytes) -> tuple[int, int, bytes, int, int, bytes]:
    if len(buf) < HEADER_SIZE or buf[:4] != MAGIC:
        raise ValueError("not a CSTA archive (bad magic)")
    version, flags, salt, catalog_offset, catalog_len, catalog_nonce = struct.unpack(
        "<HH16sQI12s", buf[4:HEADER_SIZE]
    )
    if version != VERSION:
        raise ValueError(f"unsupported CSTA version: {version}")
    return version, flags, salt, catalog_offset, catalog_len, catalog_nonce


def _iter_source_entries(src: Path) -> list[tuple[str, Path, int]]:
    """Return (archive_path, fs_path, type) sorted by archive path."""
    src = src.resolve()
    items: list[tuple[str, Path, int]] = []

    if src.is_file() or src.is_symlink():
        name = _normalize_rel_path(src.name)
        if src.is_symlink():
            items.append((name, src, TYPE_SYMLINK))
        else:
            items.append((name, src, TYPE_FILE))
        return items

    if not src.is_dir():
        raise FileNotFoundError(src)

    root_name = _normalize_rel_path(src.name)
    items.append((root_name, src, TYPE_DIRECTORY))

    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirpath_p = Path(dirpath)
        rel_dir = dirpath_p.relative_to(src).as_posix()
        base = root_name if rel_dir == "." else f"{root_name}/{rel_dir}"

        # stable order
        dirnames.sort()
        filenames.sort()

        for d in dirnames:
            p = dirpath_p / d
            ap = _normalize_rel_path(f"{base}/{d}")
            if p.is_symlink():
                items.append((ap, p, TYPE_SYMLINK))
            else:
                items.append((ap, p, TYPE_DIRECTORY))

        for f in filenames:
            p = dirpath_p / f
            ap = _normalize_rel_path(f"{base}/{f}")
            if p.is_symlink():
                items.append((ap, p, TYPE_SYMLINK))
            else:
                items.append((ap, p, TYPE_FILE))

    # de-duplicate while preserving first occurrence, then sort
    seen: set[str] = set()
    unique: list[tuple[str, Path, int]] = []
    for ap, fp, typ in items:
        if ap in seen:
            continue
        seen.add(ap)
        unique.append((ap, fp, typ))
    unique.sort(key=lambda x: x[0])
    return unique


def _process_file(
    key: bytes,
    entry_index: int,
    fs_path: Path,
    file_nonce: bytes,
) -> tuple[int, bytes, int, int]:
    raw = fs_path.read_bytes()
    raw_size = len(raw)
    payload, comp_method = _compress_payload(raw)
    del raw
    ciphertext = encrypt_payload(key, file_nonce, payload, entry_index)
    del payload
    return entry_index, ciphertext, raw_size, comp_method


def pack(
    src: str | Path,
    dst: str | Path,
    password: str,
    workers: int = 0,
) -> None:
    """Compress/encrypt `src` (file or directory) into CSTA archive `dst`.

    Ciphertext is written to disk as each file finishes; at most `workers`
    file payloads are held in memory at once.
    """
    src_path = Path(src)
    dst_path = Path(dst)
    if workers <= 0:
        workers = min(32, (os.cpu_count() or 4) * 2)

    collected = _iter_source_entries(src_path)
    if not collected:
        raise ValueError("nothing to pack")

    # Avoid packing the destination if it sits inside the source tree
    try:
        dst_resolved = dst_path.resolve()
        src_resolved = src_path.resolve()
        if src_resolved.is_dir() and dst_resolved.is_relative_to(src_resolved):
            collected = [
                (ap, fp, typ)
                for ap, fp, typ in collected
                if fp.resolve() != dst_resolved
            ]
    except (OSError, ValueError):
        pass

    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    catalog_nonce = os.urandom(NONCE_LEN)

    entries: list[CatalogEntry] = []
    file_jobs: list[tuple[int, Path, bytes]] = []  # entry_index, path, nonce

    for ap, fp, typ in collected:
        if typ == TYPE_DIRECTORY:
            entries.append(CatalogEntry(path=ap, type=TYPE_DIRECTORY))
        elif typ == TYPE_SYMLINK:
            target = os.readlink(fp)
            entries.append(
                CatalogEntry(path=ap, type=TYPE_SYMLINK, link_target=str(target))
            )
        else:
            nonce = os.urandom(NONCE_LEN)
            idx = len(entries)
            entries.append(
                CatalogEntry(
                    path=ap,
                    type=TYPE_FILE,
                    file_nonce=nonce,
                )
            )
            file_jobs.append((idx, fp, nonce))

    flags = 0
    body_len = 0
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dst_path, "wb") as out:
        # Placeholder header; rewritten after body + catalog lengths are known.
        out.write(b"\x00" * HEADER_SIZE)

        if file_jobs:
            job_iter = iter(file_jobs)
            in_flight: set = set()

            def _fill(pool: ThreadPoolExecutor) -> None:
                while len(in_flight) < workers:
                    try:
                        idx, fp, nonce = next(job_iter)
                    except StopIteration:
                        return
                    in_flight.add(pool.submit(_process_file, key, idx, fp, nonce))

            with ThreadPoolExecutor(max_workers=workers) as pool:
                _fill(pool)
                while in_flight:
                    done, in_flight = wait(in_flight, return_when=FIRST_COMPLETED)
                    for fut in done:
                        entry_index, ciphertext, raw_size, comp_method = fut.result()
                        e = entries[entry_index]
                        e.data_offset = body_len
                        e.cipher_len = len(ciphertext)
                        e.raw_size = raw_size
                        e.comp_method = comp_method
                        if comp_method == ZLIB_METHOD:
                            flags |= FLAG_ZLIB
                        out.write(ciphertext)
                        body_len += len(ciphertext)
                    _fill(pool)

        plain_catalog = encode_catalog(entries)
        header_prefix = MAGIC + struct.pack("<HH", VERSION, flags)
        catalog_ct = AESGCM(key).encrypt(catalog_nonce, plain_catalog, header_prefix)
        catalog_offset = HEADER_SIZE + body_len
        catalog_len = len(catalog_ct)
        header = _build_header(flags, salt, catalog_offset, catalog_len, catalog_nonce)
        out.write(catalog_ct)
        out.seek(0)
        out.write(header)


def _safe_dest(root: Path, rel: str) -> Path:
    rel_norm = _normalize_rel_path(rel)
    dest = (root / PurePosixPath(rel_norm)).resolve()
    root_resolved = root.resolve()
    if not dest.is_relative_to(root_resolved):
        raise ValueError(f"path escapes destination root: {rel}")
    return dest


def _extract_one_file(
    key: bytes,
    entry_index: int,
    entry: CatalogEntry,
    dest: Path,
    src_path: Path,
) -> None:
    """Read one blob from the archive, decrypt/decompress, and write `dest`."""
    with open(src_path, "rb") as f:
        f.seek(HEADER_SIZE + entry.data_offset)
        blob = f.read(entry.cipher_len)
    if len(blob) != entry.cipher_len:
        raise ValueError(f"truncated ciphertext for {entry.path}")
    payload = decrypt_blob(key, entry.file_nonce, blob, entry_index)
    del blob
    data = _decompress_payload(payload, entry.comp_method, entry.raw_size)
    del payload
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)


def unpack(
    src: str | Path,
    dst: str | Path,
    password: str,
    workers: int = 0,
    progress: ProgressCallback | None = None,
) -> None:
    """Decrypt/decompress CSTA archive `src` into directory `dst`.

    If `progress` is set, it is called as progress(done, total, path) after
    each file is extracted (dirs/symlinks are not counted).

    Files are extracted with bounded concurrency; ciphertext is not preloaded
    into memory (important for large archives).
    """
    src_path = Path(src)
    dst_path = Path(dst)
    if workers <= 0:
        workers = min(32, (os.cpu_count() or 4) * 2)

    with open(src_path, "rb") as f:
        header = f.read(HEADER_SIZE)
        _version, _flags, salt, catalog_offset, catalog_len, catalog_nonce = parse_header(
            header
        )
        if catalog_offset < HEADER_SIZE:
            raise ValueError("invalid catalog_offset")
        f.seek(catalog_offset)
        catalog_ct = f.read(catalog_len)
        if len(catalog_ct) != catalog_len:
            raise ValueError("truncated catalog")

        key = derive_key(password, salt)
        header_prefix = header[:8]
        plain_catalog = AESGCM(key).decrypt(catalog_nonce, catalog_ct, header_prefix)
        entries = decode_catalog(plain_catalog)

    # materialize dirs / symlinks first
    dst_path.mkdir(parents=True, exist_ok=True)
    file_work: list[tuple[int, CatalogEntry, Path]] = []

    for idx, e in enumerate(entries):
        dest = _safe_dest(dst_path, e.path)
        if e.type == TYPE_DIRECTORY:
            dest.mkdir(parents=True, exist_ok=True)
        elif e.type == TYPE_SYMLINK:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists() or dest.is_symlink():
                dest.unlink()
            os.symlink(e.link_target, dest)
        elif e.type == TYPE_FILE:
            file_work.append((idx, e, dest))
        else:
            raise ValueError(f"unknown entry type: {e.type}")

    total = len(file_work)
    if file_work:
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {
                pool.submit(
                    _extract_one_file, key, idx, entry, dest, src_path
                ): entry.path
                for idx, entry, dest in file_work
            }
            for fut in as_completed(futs):
                fut.result()
                done += 1
                if progress is not None:
                    progress(done, total, futs[fut])
    elif progress is not None:
        progress(0, 0, "")


def pack_paths(
    paths: Iterable[str | Path],
    dst: str | Path,
    password: str,
    workers: int = 0,
) -> None:
    """Convenience: pack a single path (file or directory)."""
    paths = list(paths)
    if len(paths) != 1:
        raise ValueError("pack_paths currently accepts exactly one source path")
    pack(paths[0], dst, password, workers=workers)
