Overall layout (little-endian throughout):

[Header 48B, plaintext]
[File Body: encrypted file ciphertexts, concatenated]
[Catalog: AES-GCM encrypted directory table]

1. Header (48 bytes, plaintext)
-------------------------------

Offset Size Field           Description
---------------------------------------------------------
0      4    magic           b"CSTA"
4      2    version         currently 1
6      2    flags           bit0 = FLAG_ZLIB (0x0001)
8      16   salt            scrypt salt
24     8    catalog_offset  start offset of encrypted catalog
32     4    catalog_len     length of encrypted catalog (incl. GCM tag)
36     12   catalog_nonce   nonce used to encrypt the catalog

Layout: magic + <HH + 16s + QI + 12s

Body range: [48, catalog_offset)

2. File Body (ciphertext region)
--------------------------------

Each regular file occupies one contiguous ciphertext blob in the body:

payload    = zlib(raw) or raw (STORE if zlib not smaller / empty / >=8MiB)
ciphertext = AES-256-GCM(payload)  # includes 16-byte auth tag

Large payloads (>1 GiB) use chunked AES-GCM (OpenSSL 32-bit length limit):

body blob starts with magic b"CSTC"
  CSTC | ver:u8 | flags:u8 | reserved:u16 | n_chunks:u32
then n_chunks times:
  chunk_nonce:12 | ct_len:u32 | ciphertext(ct_len, incl. tag)

Catalog file_nonce is a binding nonce (in AAD with entry_index + chunk_index).
Each chunk plaintext is at most 1 GiB.

- data_offset : offset relative to body start (i.e. relative to file offset 48)
- cipher_len  : ciphertext length including GCM tag (or full CSTC blob)
- read_at     : 48 + data_offset, length cipher_len

Directories and symlinks do NOT write into the body.

3. Catalog (trailing, wholly encrypted)
-----------------------------------------

Pipeline:
1. Encode plaintext catalog with encode_catalog(...)
2. AES-256-GCM encrypt; AAD = magic || version || flags (first 8 header bytes)
3. Store ciphertext at catalog_offset, length catalog_len

Plaintext catalog structure:

count: u32

Repeated count times:
  path_len : u16
  path     : UTF-8 bytes (path_len)
  type     : u8  # 1=DIRECTORY, 2=FILE, 3=SYMLINK

  if type == DIRECTORY:
    (no extra fields)

  if type == FILE:
    data_offset : u64
    cipher_len  : u64
    raw_size    : u64
    comp_method : u8  # 0=STORE, 1=ZLIB
    file_nonce  : 12 bytes

  if type == SYMLINK:
    target_len  : u16
    link_target : UTF-8 bytes

Path rules: forward slashes, relative paths only; no ".." or empty segments.

4. Crypto and compression
-------------------------

Key derivation : scrypt(password, salt, N=2^14, r=8, p=1) -> 32 bytes
Cipher         : AES-256-GCM, 12-byte nonce
File AAD       : entry_index as u32 LE (index in catalog)
Catalog AAD    : first 8 header bytes (CSTA + version + flags)
Compression    : zlib level 6; if not smaller (or empty file) use STORE

Per-file transform chain:

raw -> [zlib?] -> AES-GCM -> write into body

5. Unpack read order
--------------------

1. Read 48-byte Header; verify magic "CSTA" and version
2. Derive master_key via scrypt
3. Read and decrypt Catalog using catalog_offset / catalog_len
4. For each FILE entry:
   seek(48 + data_offset) -> read(cipher_len) -> decrypt -> decompress -> write

6.usage
python compress.py <待压缩路径> <输出.cst> -p 密码 [-j 线程数]
python decompress.py <输入.cst> <输出目录> -p 密码 [-j 线程数]