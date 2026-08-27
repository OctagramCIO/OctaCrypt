# 📖 Guía de Usuario - OctaCrypt

Bienvenido a OctaCrypt. Esta guía te explica cómo usar el programa paso a paso, sin necesidad de saber programación.

---

## 🚀 ¿Cómo instalar OctaCrypt?

Tienes dos opciones:

### Opción 1 — Ejecutable portable (más fácil, recomendado)

No necesitas instalar nada. Solo descarga y usa.

1. Ve a [github.com/OctagramCIO/OctaCrypt/releases](https://github.com/OctagramCIO/OctaCrypt/releases)
2. Descarga la versión más reciente:
   - `octacrypt-tui.exe` → interfaz visual con menús (recomendado para nuevos usuarios)
   - `octacrypt.exe` → comandos de texto (para usuarios avanzados)
3. Guarda los archivos en una carpeta de tu elección
4. ¡Listo! No necesitas instalar Python ni nada más

---

### Opción 2 — Desde el código fuente (requiere Python 3.10+)

```bash
git clone https://github.com/OctagramCIO/OctaCrypt.git
cd OctaCrypt
pip install -e .
```

---

## 🖥️ Usando la interfaz visual (TUI) — Recomendado

La TUI es la forma más fácil de usar OctaCrypt. Tiene menús interactivos - solo usa las flechas del teclado y Enter.

### Abrir la TUI

```bash
# Si descargaste el ejecutable
.\octacrypt-tui.exe          # Windows
./octacrypt-tui              # Linux / macOS

# Si instalaste desde código fuente
octacrypt-tui
```

### Menú principal

Al abrir verás estas opciones:

```
» Cifrar archivo
  Descifrar archivo
  Cifrar directorio
  Descifrar directorio
  Cifrar / Descifrar mensaje
  Firmar / Verificar archivo
  Generar claves
  Hash
  Acerca de OctaCrypt
  Salir
```

Usa las **flechas ↑↓** para moverte y **Enter** para seleccionar.

---

## 🔒 Caso 1 — Cifrar un archivo

**Objetivo:** proteger un archivo con contraseña.

### Usando la TUI:
1. Selecciona **"Cifrar archivo"**
2. Escribe la ruta del archivo (o arrástralo a la terminal)
3. Selecciona el algoritmo — elige **AES-256-GCM** si tienes dudas
4. Escribe una contraseña segura
5. Listo — se crea el archivo `.enc` en la misma carpeta

### Usando la terminal:
```bash
octacrypt encrypt documento.pdf --key mipassword
```

El archivo cifrado se llama `documento.pdf.enc`. El original no se borra.

---

## 🔓 Caso 2 — Descifrar un archivo

**Objetivo:** recuperar un archivo cifrado.

### Usando la TUI:
1. Selecciona **"Descifrar archivo"**
2. Selecciona el modo **"Simetrico (password)"**
3. Escribe la ruta del archivo `.enc`
4. Escribe la contraseña que usaste al cifrar
5. Se recupera el archivo original

### Usando la terminal:
```bash
octacrypt decrypt documento.pdf.enc --key mipassword
```

---

## 📁 Caso 3 — Cifrar una carpeta completa

**Objetivo:** proteger todos los archivos de una carpeta de una sola vez.

### Usando la TUI:
1. Selecciona **"Cifrar directorio"**
2. Escribe la ruta de la carpeta
3. Selecciona el algoritmo
4. Escribe una contraseña
5. Se crea una carpeta nueva con todos los archivos cifrados

### Usando la terminal:
```bash
octacrypt encrypt-dir mis_documentos/ --key mipassword
```

Se crea la carpeta `mis_documentos.enc/` con todos los archivos cifrados.

Para descifrar:
```bash
octacrypt decrypt-dir mis_documentos.enc/ --key mipassword
```

---

## ✉️ Caso 4 — Cifrar un mensaje de texto

**Objetivo:** enviar un mensaje cifrado a alguien.

### Usando la TUI:
1. Selecciona **"Cifrar / Descifrar mensaje"**
2. Selecciona **"Cifrar mensaje"**
3. Escribe el mensaje
4. Elige el modo **"Simetrico (password)"**
5. Escribe una contraseña
6. Copia el resultado (texto en base64) y envíaselo a la otra persona

La otra persona usa la misma contraseña para descifrar.

### Usando la terminal:
```bash
# Cifrar
octacrypt msg-encrypt "Hola, esto es secreto" --password mipassword

# Descifrar (pega el texto base64 entre comillas)
octacrypt msg-decrypt "base64aqui..." --password mipassword
```

---

## 🔑 Caso 5 — Generar un par de claves

**Objetivo:** crear claves para cifrado avanzado o firmas digitales.

### Usando la TUI:
1. Selecciona **"Generar claves"**
2. Elige el tipo:
   - **RSA-4096** → para cifrar archivos para un destinatario específico
   - **Ed25519** → para firmar archivos (verificar que no fueron alterados)
   - **ML-KEM** → para cifrado post-cuántico (resiste computadoras cuánticas)
   - **ML-DSA** → para firmas post-cuánticas
3. Escribe un nombre base (ej: `mikey`)
4. Elige si proteger la clave privada con contraseña (**recomendado: Sí**)
5. Se crean dos archivos:
   - `mikey_private.pem` → tu clave privada — **guárdala en lugar seguro, nunca la compartas**
   - `mikey_public.pem` → tu clave pública — puedes compartirla libremente

### Usando la terminal:
```bash
octacrypt keygen --type rsa --bits 4096 --out mikey --prompt-password
octacrypt keygen --type ed25519 --out signkey --prompt-password
```

---

## 🔐 Caso 6 — Cifrado híbrido (para enviar a alguien)

**Objetivo:** cifrar un archivo para que solo una persona específica pueda abrirlo.

Esto funciona así:
- La otra persona te da su **clave pública** (`su_clave_public.pem`)
- Tú cifras el archivo con esa clave
- Solo ella puede abrirlo con su **clave privada**

```bash
# Cifrar para el destinatario
octacrypt encrypt documento.pdf --alg hybrid --pub su_clave_public.pem

# El destinatario descifra con su clave privada
octacrypt decrypt documento.pdf.enc --alg hybrid --priv mikey_private.pem
```

---

## 🔏 Caso 7 — Firmar un archivo

**Objetivo:** garantizar que un archivo no fue alterado.

```bash
# Firmar
octacrypt sign documento.pdf --priv signkey_private.pem

# Se crea documento.pdf.sig — envía ambos archivos al destinatario

# Verificar (el destinatario)
octacrypt verify documento.pdf --pub signkey_public.pem --sig documento.pdf.sig
```

Si el archivo fue alterado, la verificación fallará.

---

## #️⃣ Caso 8 — Calcular el hash de un archivo

**Objetivo:** verificar que un archivo no fue modificado comparando su huella digital.

```bash
octacrypt hash documento.pdf --sha256
octacrypt hash documento.pdf --sha512
```

Guarda el resultado. Si en el futuro el hash cambia, el archivo fue modificado.

---

## 🔐 Caso 9 — Cifrado y firmas post-cuánticas (resistentes a computadoras cuánticas)

**Objetivo:** proteger tus datos contra futuras computadoras cuánticas, que podrían romper RSA y Ed25519.

### Generar claves post-cuánticas

```bash
# Clave para cifrado (ML-KEM): pública → cifra, privada → descifra
octacrypt keygen --type mlkem --out pqenc --prompt-password

# Clave para firmas (ML-DSA)
octacrypt keygen --type mldsa --out pqsign --prompt-password
```

### Cifrar y descifrar un archivo para un destinatario

```bash
# Cifrar con la clave pública ML-KEM del destinatario
octacrypt pq-encrypt documento.pdf --pub pqenc_public.pem

# Descifrar con tu clave privada ML-KEM
octacrypt pq-decrypt documento.pdf.pqenc --priv pqenc_private.pem --password tu_contraseña
```

### Firmar y verificar

```bash
# Firmar
octacrypt pq-sign documento.pdf --priv pqsign_private.pem --password tu_contraseña

# Verificar (el destinatario)
octacrypt pq-verify documento.pdf --pub pqsign_public.pem --sig documento.pdf.pqsig
```

> ℹ️ Las claves y firmas post-cuánticas son más grandes que las clásicas (una firma ML-DSA-65 ocupa ~3 KB). Esto es normal y es el precio de la resistencia cuántica.

---

## 🛡️ Consejos de seguridad

- **Usa contraseñas largas y únicas** — mínimo 16 caracteres, mezcla letras, números y símbolos
- **Nunca compartas tu clave privada** — si alguien la tiene, puede descifrar todo lo que cifraste
- **Haz una copia de seguridad de tus claves** — si las pierdes, no podrás recuperar tus archivos
- **Protege tu clave privada con contraseña** — si alguien roba el archivo `.pem`, no podrá usarla sin la contraseña
- **No pierdas tu contraseña** — no hay forma de recuperarla, los archivos cifrados serán irrecuperables
- **Verifica los hashes** — antes de confiar en un archivo importante, verifica que su hash coincide

---

## ❓ Preguntas frecuentes

**¿Qué pasa si olvido mi contraseña?**
No hay forma de recuperar los archivos. La contraseña es la única llave. Guárdala en un lugar seguro.

**¿Qué algoritmo debo usar?**
Para uso general: **AES-256-GCM**. Si usas dispositivos móviles o sin aceleración de hardware: **ChaCha20-Poly1305**. Para enviar a una persona específica: **Híbrido RSA**. Para máxima resistencia al futuro (datos que deben seguir siendo secretos cuando existan computadoras cuánticas): **ML-KEM post-cuántico**. Para firmas a prueba de cuántica: **ML-DSA**.

**¿Puedo abrir el archivo `.enc` en otro programa?**
No. Solo OctaCrypt puede abrirlos. El formato es propio de OctaCrypt.

**¿Es seguro compartir mi clave pública?**
Sí. La clave pública está diseñada para compartirse. La privada nunca.

**¿OctaCrypt borra el archivo original al cifrar?**
No. El archivo original se mantiene. Si quieres eliminarlo, bórralo manualmente después de verificar que el cifrado funcionó.

**¿Funciona en Mac y Linux?**
Sí, desde el código fuente. Los ejecutables `.exe` son solo para Windows. Para Mac/Linux instala desde código fuente.

---

## 🆘 ¿Necesitas ayuda?

- Revisa el [README](README.md) para documentación técnica
- Reporta problemas en [GitHub Issues](https://github.com/OctagramCIO/OctaCrypt/issues)
- Para vulnerabilidades de seguridad, sigue las instrucciones en [SECURITY.md](SECURITY.md)

---

<div align="center">

*OctaCrypt — Tu información, bajo tu control.*

*Built with responsibility. Audited by transparency. Protected by ethics.*

</div>