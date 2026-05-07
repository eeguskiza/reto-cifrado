# Quien de verdad sabe de qué habla, no encuentra razones para levantar la voz.

Brute-force CUDA contra la construcción de **cifraronline.com**
(AES-128-ECB + passraw + null padding + MD5 verify) sobre el espacio
combinatorio `.LLLLLLLL1NNN.` (≈ 5,96 × 10¹³ candidatas).

Pico medido en RTX 5070 Ti: ~6 GH/s. Avg sostenido ~4,3 GH/s.
Barrido completo en ~3 h 50 min.

## Construcción

```
key       = password.encode() + b'\x00' * (16 - len(password.encode()))
message   = plaintext + MD5(plaintext).hexdigest().encode()
padded    = message + b'\x00' * ((16 - len(message) % 16) % 16)
ciphertext = AES-128-ECB.encrypt(padded, key)
```

Validación de hit: prefijo `Leonardo da Vinc` (kernel) + prefijo-32
LF/CRLF (CPU) + `MD5(plaintext_clean)` igual a los 32 chars finales
(CPU). Ver `DECISIONS.md` para la historia.

## Estructura del password

14 caracteres `.LLLLLLLL1NNN.`: 8 letras (4 vocales + 4 consonantes,
1 mayúscula no en pos 1) + año `NNN` ∈ 000..999.

## Requisitos

- Linux o WSL2 con GPU NVIDIA visible (`nvidia-smi`).
- CUDA Toolkit ≥ 12.8 con `nvcc` en PATH.
- Rust ≥ 1.75.
- Compute capability ≥ 8.9 (Ada). Nativo a 12.0 (Blackwell).

## Build

```bash
cargo build --release
```

`build.rs` detecta `nvcc` y compila a PTX para `sm_120` (fallback `sm_89`).
Binario: `target/release/quattro-crack`.

## Setup WSL2 (una vez)

```bash
# CUDA Toolkit (NO instales drivers — los provee Windows).
wget https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get update && sudo apt-get install -y cuda-toolkit-13-0
echo 'export PATH=/usr/local/cuda-13.0/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda-13.0/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc

# Symlink NVML para la TUI (opcional).
mkdir -p ~/lib-nvml-shim
ln -sf /usr/lib/wsl/lib/libnvidia-ml.so.1 ~/lib-nvml-shim/libnvidia-ml.so
echo 'export LD_LIBRARY_PATH=$HOME/lib-nvml-shim:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

## Uso

```bash
quattro-crack inspect ./data/cifrado.txt   # metadatos del fichero objetivo
quattro-crack plan --save                  # crea state/plan.toml
quattro-crack run                          # lanza barrido (TUI auto)
quattro-crack run --resume                 # reanuda tras Ctrl+C
quattro-crack status                       # progreso actual
quattro-crack reset --yes                  # borra state/
quattro-crack benchmark --duration 30      # mide GH/s del kernel
```

Ctrl+C: termina el batch en curso, persiste atómicamente, sale con
código 0. Segundo Ctrl+C aborta inmediato (130).

Para barrido nocturno en tmux:

```bash
LD_LIBRARY_PATH="$HOME/lib-nvml-shim:$LD_LIBRARY_PATH" \
  tmux new -s qc -d './target/release/quattro-crack run'
```

## Tests

```bash
cargo test --release    # 105 tests + 10 ignored (diagnóstico opt-in)
cargo clippy --release --all-targets -- -D warnings
```

El test ancla es `tests/d035_cifraronline_construction.rs::test_experimental_vector_bit_exact`:
cifra un vector experimental conocido y compara byte-a-byte contra
cifraronline.com. Si falla, la construcción está mal.

## Estructura

```
src/                        Rust: combinatorics, reference, cuda, runner,
                            state, plan, tui, gpu_metrics, signal,
                            ciphertext, kdf, main
kernels/                    CUDA: brute_passraw_aes128_ecb (activo),
                            aes/md5/gen primitivas, dump helpers
tests/                      d035 (ancla), parity, adversarial, resume,
                            throughput, primitivas FIPS-197 / RFC 1321
DECISIONS.md                registro de decisiones no obvias
```

## Licencia

MIT OR Apache-2.0.
