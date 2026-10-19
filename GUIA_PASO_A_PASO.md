# 📋 Guía rápida paso a paso — OctaCrypt

Todo se hace desde la terminal con el comando `octacrypt`. Funciona igual en Windows, Linux y macOS.
Se asume OctaCrypt instalado (`pip install octacrypt` o `pip install -e .` desde el repo).

> **Sobre las contraseñas:** `--prompt-password` la pide de forma oculta (recomendado).
> `--password valor` la escribe en la línea de comandos (solo para scripts/pruebas).

---

## 🗺️ Resumen rápido

| Quiero... | Comando |
|---|---|
| Crear claves | `octacrypt keygen --type rsa --out misclaves --prompt-password` |
| Ver una clave | `cat misclaves_public.pem` (Windows: `type misclaves_public.pem`) |
| Cifrar un archivo | `octacrypt encrypt doc.pdf --key miClave` |
| Descifrarlo | `octacrypt decrypt doc.pdf.enc --key miClave` |
| Cifrar para otra persona | `octacrypt hybrid-encrypt doc.pdf --pub ajena_public.pem` |
| Cifrado post-cuántico | `octacrypt pq-encrypt doc.pdf --pub kem_public.pem` |
| Cifrar una carpeta | `octacrypt encrypt-dir carpeta/ --key miClave` |
| Cifrar un mensaje de texto | `octacrypt msg-encrypt "hola" --password miClave` |
| Firmar un archivo | `octacrypt sign doc.pdf --priv firma_private.pem --password pw` |
| Verificar una firma | `octacrypt verify doc.pdf --pub firma_public.pem --sig doc.pdf.sig` |
| Interfaz gráfica (TUI) | `octacrypt-tui` |

---

## 1️⃣ Crear claves

**Paso 1 — Elegir el tipo de clave:**

| `--type` | Sirve para |
|---|---|
| `rsa` | Cifrar archivos/mensajes para otras personas |
| `ed25519` | Firmar archivos (probar quién los creó) |
| `mlkem` | Cifrado post-cuántico (futuro quantum) |
| `mldsa` | Firmas post-cuánticas |

**Paso 2 — Ejecutar keygen** (el ejemplo usa RSA, aplica para todos):

```bash
octacrypt keygen --type rsa --bits 4096 --out misclaves --prompt-password
```

- `--out misclaves` → nombre base de los archivos generados.
- `--prompt-password` → protege la clave privada con contraseña (siempre recomendado).
- Variantes: `--bits` solo para `rsa`; `--variant mlkem768|mlkem1024` para `mlkem`;
  `--variant mldsa44|mldsa65|mldsa87` para `mldsa` (por defecto: `mlkem768` y `mldsa65`).

```bash
octacrypt keygen --type ed25519 --out firma --prompt-password
octacrypt keygen --type mlkem  --out kem  --prompt-password
octacrypt keygen --type mldsa  --out dsa  --prompt-password
```

**Paso 3 — Guardar el resultado.** Siempre se crean dos archivos:

| Archivo | Contenido | ¿Se comparte? |
|---|---|---|
| `misclaves_private.pem` | Clave privada (SECRETA) | ❌ Nunca. Guárdala en copia de seguridad |
| `misclaves_public.pem` | Clave pública | ✅ Darla a quien necesite |

---

## 2️⃣ Ver / sacar las claves

1. **Ver el contenido** de cualquier clave:

   ```bash
   cat misclaves_public.pem      # Linux / macOS
   type misclaves_public.pem     # Windows
   ```

2. **Enviar tu clave pública** a otra persona: simplemente comparte el archivo
   `*_public.pem` (correo, chat, USB...). Ella lo usará para cifrarte algo.

3. **Respaldar tu clave privada**: copia `*_private.pem` a un lugar seguro
   (USB cifrado, disco externo). Si la pierdes, **no podrás descifrar nada**.

4. **Distinguirlas**: la privada siempre termina en `_private.pem` y, si la
   protegiste, el archivo contiene `ENCRYPTED`. La pública es un archivo corto.

---

## 3️⃣ Cifrar y descifrar archivos

### Opción A — Con contraseña (AES-256, para tu propio uso)

```bash
octacrypt encrypt doc.pdf --key miClave          # crea doc.pdf.enc
octacrypt decrypt doc.pdf.enc --key miClave       # recupera doc.pdf
```

- ¿Quieres ChaCha20 en vez de AES? Agrega `--alg chacha20` **en ambos** comandos.

### Opción B — Cifrado híbrido RSA (para enviar a otra persona)

```bash
# Tú (con la clave PÚBLICA de la persona que recibirá)
octacrypt hybrid-encrypt doc.pdf --pub ajena_public.pem      # crea doc.pdf.henc

# La otra persona (con su clave PRIVADA)
octacrypt hybrid-decrypt doc.pdf.henc --priv ajena_private.pem --password suClave
```

`--password` solo es necesario si su clave privada está protegida; si no, omítelo.

### Opción C — Cifrado post-cuántico ML-KEM (mismo patrón, resiste a la computación cuántica)

```bash
octacrypt pq-encrypt doc.pdf --pub kem_public.pem            # crea doc.pdf.pqenc
octacrypt pq-decrypt doc.pdf.pqenc --priv kem_private.pem --password miClave
```

---

## 4️⃣ Cifrar una carpeta completa

```bash
octacrypt encrypt-dir documentos/ --key miClave    # crea documentos.enc/
octacrypt dir-info documentos.enc/                 # ver qué contiene (sin clave)
octacrypt decrypt-dir documentos.enc/ --key miClave  # restaura documentos/
```

- Preserva la estructura interna (subcarpetas y nombres).
- `--alg chacha20` también está disponible.

---

## 5️⃣ Cifrar un mensaje de texto (para pegar en un chat)

**Paso 1 — Cifrar** (elige un modo):

```bash
octacrypt msg-encrypt "código WiFi 1234" --password miClave
octacrypt msg-encrypt "secreto" --pub ajena_public.pem
octacrypt msg-encrypt "secreto" --pub-pq kem_public.pem
```

El resultado es una línea **base64**: cópiala y envíala por el chat que quieras.

**Paso 2 — Descifrar** (con el modo que se usó):

```bash
octacrypt msg-decrypt "<base64>" --password miClave
octacrypt msg-decrypt "<base64>" --priv ajena_private.pem --priv-password suClave
octacrypt msg-decrypt "<base64>" --priv-pq kem_private.pem --priv-password miClave
```

- La contraseña de la **clave privada** va en `--priv-password` (no en `--password`,
  que es la contraseña del mensaje en modo simétrico).
- **Opcional — firmar el mensaje** al cifrar:
  `--sign-priv firma_private.pem --sign-password pw`
  y verificarlo al descifrar: `--verify-pub firma_public.pem`.

---

## 6️⃣ Firmar y verificar (autenticidad)

```bash
# Firmar (con tu clave privada Ed25519 protegida con contraseña)
octacrypt sign informe.txt --priv firma_private.pem --password miClave   # crea informe.txt.sig

# Verificar (cualquiera con tu clave pública puede hacerlo, sin contraseña)
octacrypt verify informe.txt --pub firma_public.pem --sig informe.txt.sig
```

- ✅ = firma válida / ❌ = archivo alterado (el comando sale con error).
- Para firmar **texto corto** directo: `sign "hola" --priv ... --password ... -m`.
- **Versión post-cuántica** (ML-DSA): mismos pasos con `pq-sign` / `pq-verify`,
  usando claves `--type mldsa` y la extensión `.pqsig`.

---

## 7️⃣ Hash (huella digital, no se puede descifrar)

```bash
octacrypt hash doc.pdf --sha256              # huella SHA-256 de un archivo
octacrypt hash "texto" --sha512              # huella de un texto directo
octacrypt hash "contraseña" --bcrypt         # hash tipo contraseña
octacrypt hash "contraseña" --bcrypt --verify "$2b$12$..."   # verificar → True/False
```

También está `--scrypt`. En `bcrypt`/`scrypt` el `--verify` compara contra el hash guardado.

---

## 🧩 Referencia rápida de extensiones

| Extensión | Generada por | Se descifra con |
|---|---|---|
| `.enc` | `encrypt` / `encrypt-dir` | `decrypt` / `decrypt-dir` |
| `.henc` | `hybrid-encrypt` | `hybrid-decrypt` |
| `.pqenc` | `pq-encrypt` | `pq-decrypt` |
| `.sig` | `sign` | `verify` |
| `.pqsig` | `pq-sign` | `pq-verify` |

**Regla de oro:** la clave **privada** nunca se comparte; la **pública** se comparte
con todos. La contraseña de la clave privada no va en ningún archivo: guárdala de memoria.
