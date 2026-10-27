# cortex9-taintgate

[![CI](https://github.com/federiconbaez/cortex9-taintgate/actions/workflows/ci.yml/badge.svg)](https://github.com/federiconbaez/cortex9-taintgate/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

Gateway MCP que etiqueta los resultados de las tools con etiquetas de flujo de información (`private`, `untrusted`), propaga esas etiquetas a los argumentos de calls posteriores por coincidencia de contenido (exacta, n-gramas y decodificadores) y bloquea —o pide aprobación— cuando un call completaría la *lethal trifecta* (dato privado + contenido no confiable + sumidero capaz de exfiltrar).

MCP gateway that labels tool outputs with information-flow labels (`private`, `untrusted`), finds that content again in later tool-call arguments (exact, n-gram and decoded matches), and blocks —or asks for approval— when a call would complete the *lethal trifecta* (private data + untrusted content + an exfiltration-capable sink).

> **ES** primero · **EN** below

---

## ES

### Problema

Un agente con acceso a datos privados, exposición a contenido no confiable y un canal de salida puede ser inducido a exfiltrar. Willison (2025) llama a esa combinación la *lethal trifecta*. Los gateways MCP actuales deciden por tool (routing, auth, plugins); no saben qué dato vino de dónde. CaMeL (Debenedetti et al., 2025) separa control y datos con capacidades, pero exige reescribir el agente. Este proyecto es un gateway a nivel de protocolo: el agente no cambia.

### Qué hace

```
cliente MCP ──stdio──► taintgate serve --policy P.toml
                           │ tools/call
                           ├─ clasifica la tool (source / sink) según la política
                           ├─ escanea los args contra el almacén de taint
                           ├─ si completa la trifecta → bloquea (o ask / monitor)
                           └─ si no, reenvía al servidor MCP de abajo (stdio o HTTP)
                           │ tools/call result
                           └─ etiqueta el output y guarda fingerprints (n-gramas + átomos)
```

- **Etiquetas:** `private` (dato confidencial del usuario) y `untrusted` (contenido que un tercero puede controlar). Se asignan por regla de tool en la política.
- **Fingerprints:** skeleton alfanumérico en minúsculas; n-gramas de longitud configurable (16 por defecto); átomos cortos (tokens con dígitos, hojas JSON, nombres propios).
- **Decodificadores** (dos niveles): base64, hex, percent-encoding, rot13, reverse, leetspeak, dígitos en palabras. Un payload `base64(hex(secreto))` se compara con el original.
- **Acumulación:** todo lo ya enviado al mismo destino de un sink se concatena con el payload actual, así un secreto partido en dos calls sigue matcheando.
- **Trifecta:** se dispara cuando un sink no confiable lleva contenido `private` y la sesión ya vio contenido `untrusted`. Opcionalmente (`untrusted_destination = true`) también cuando el destino mismo se copió de contenido no confiable mientras había datos privados en la sesión.
- **Modos:** `block` (default), `ask` (comando aprobador por stdin) o `monitor` (sólo registra).
- **Transporte al cliente:** stdio (una línea JSON-RPC por mensaje). Hacia abajo: hijo por stdio, o cliente Streamable HTTP (`Mcp-Session-Id`, JSON o SSE).

`src/jsonrpc.rs` se copió de [`mcp-server-rs`](https://github.com/federiconbaez/mcp-server-rs) sin modificarlo en ese repo.

### Uso

```sh
cargo build --release

# Comprobar una política
./target/release/taintgate check --policy policies/banking.toml

# Gateway delante de un servidor mock (el bench reescribe el command)
TAINTGATE_WORLD_LOG=/tmp/sinks.jsonl \
  ./target/release/taintgate serve --policy policies/demo.toml --audit /tmp/audit.jsonl
```

Política mínima (ver `examples/minimal-policy.toml`):

```toml
[gateway]
mode = "block"
require_untrusted = true
untrusted_destination = true

[[server]]
name = "bank"
command = ["taintgate-world", "--suite", "scenarios/world-banking.json"]

[[tool]]
match = "bank/get_balance"
source = ["private"]

[[tool]]
match = "bank/read_invoice_file"
source = ["untrusted"]

[[tool]]
match = "bank/send_money"
sink = true
destination = ["recipient"]
trusted = ["DE89370400440532013000"]
```

### Medición (criterio de aceptación)

Criterio: reducción ≥ 90 % de ataques de exfiltración en escenarios tipo AgentDojo adaptados; pérdida de utilidad < 10 puntos porcentuales en tareas benignas; reportar falsos positivos por escenario; **medir** la evasión por paráfrasis y decirla con honestidad.

**No hay ningún LLM en el loop.** Cada escenario es una traza fija de `tools/call` (lo que un agente bajo inyección emitiría). Éxito de ataque = una call a un sink quedó registrada en el log del mundo mock con el secreto en el payload (o el destino atacante, según el escenario). Los mundos y las formas de ataque se adaptaron de las injection tasks de AgentDojo (banking / workspace / slack): IBAN atacante `US133000000121212121212`, destinatario `mark.black-2134@gmail.com`, web `exfiltr8.example`.

Comando:

```sh
cargo build --release
./target/release/taintgate-bench \
  --scenarios scenarios/traces.json \
  --worlds scenarios \
  --policies policies \
  --out bench-report.json
```

Resultado medido en esta máquina (x86_64, 2026-10-27), 32 escenarios (12 ataque / 9 benignos / 11 evasión):

| métrica | valor |
|---|---|
| ataques baseline → taintgate | **12/12 → 0/12** (reducción **100 %**, meta ≥ 90 %) |
| utilidad benigna baseline → taintgate | **100 % → 100 %** (pérdida **0 pp**, meta ≤ 10 pp) |
| falsos positivos | **0** |
| evasión mecánica (base64, hex, rot13, reverse, leet, percent, number_words, base64+hex) | baseline 8/8 → taintgate **0/8** (atrapó 100 %) |
| evasión por paráfrasis | baseline 3/3 → taintgate **2/3** (atrapó **33 %**) |

La paráfrasis es la debilidad central: el matching de contenido no entiende reformulaciones. De los 3 escenarios de paráfrasis, 2 atravesaron el gateway; el que se atrapó (`evasion-paraphrase-address`) reutilizaba la palabra distintiva «Larch» del domicilio original, que el extractor de nombres propios había guardado como átomo. Eso no es comprensión semántica: es un resto léxico que sobrevivió a la reescritura.

Resultado del job `bench` en GitHub Actions ([run 40480538124](https://github.com/federiconbaez/cortex9-taintgate/actions/runs/40480538124), ubuntu-latest, 2026-10-27):

| métrica | valor en CI |
|---|---|
| ataques baseline → taintgate | 12/12 → 0/12 (reducción 100 %) |
| utilidad benigna | 100 % → 100 % (pérdida 0 pp) |
| falsos positivos | 0 |
| evasión mecánica | 8/8 → 0/8 |
| evasión por paráfrasis | 3/3 → 2/3 (atrapó 33 %) |

Sólo se midió en runners `ubuntu-latest` (x86_64).

### Qué no cubre

- Comprensión semántica de paráfrasis / traducción / resumen abstractivo. Medido arriba; no resuelto.
- Un agente que nunca pasa el secreto por un arg de tool (lo pega en un canal que el gateway no ve).
- Endpoints MCP que el gateway no intermedia.
- UI de aprobación: `mode = "ask"` exige un comando externo.
- TLS / OAuth hacia los servidores de abajo (el cliente HTTP es claro).
- Sampling, roots ni elicitation pedidas por el servidor de abajo: se responden con «method not found».

### Fuentes leídas

- Simon Willison, *The lethal trifecta for AI agents* (2025-06-16): definición de la trifecta. <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>
- Debenedetti et al., *Defeating Prompt Injections by Design* (CaMeL), arXiv:2503.18813: separación control/datos con capacidades; exige reescribir el agente. <https://arxiv.org/abs/2503.18813>
- AgentDojo (`ethz-spylab/agentdojo`): README y `injection_tasks.py` de banking / workspace / slack (formas de ataque e IDs de atacante reutilizados). <https://github.com/ethz-spylab/agentdojo>

---

## EN

### Problem

An agent with access to private data, exposure to untrusted content and an outbound channel can be talked into exfiltrating. Willison (2025) calls that combination the *lethal trifecta*. Existing MCP gateways decide by tool (routing, auth, plugins); they do not know which datum came from where. CaMeL (Debenedetti et al., 2025) separates control and data with capabilities, but requires rewriting the agent. This project is a protocol-level gateway: the agent does not change.

### What it does

See the diagram above. Labels (`private`, `untrusted`) are attached to tool outputs by policy; later tool-call arguments are scanned for that content via alphanumeric skeletons, n-grams, short atoms and a small set of decoders (base64, hex, percent, rot13, reverse, leet, spelled-out digits, two levels deep). A call that would send private data to an untrusted sink after untrusted content was read in the session is refused (or offered to an external approver). Per-destination accumulation catches secrets split across calls.

`src/jsonrpc.rs` was copied from [`mcp-server-rs`](https://github.com/federiconbaez/mcp-server-rs) without modifying that repository.

### Measurement (acceptance criterion)

Target: ≥ 90 % reduction of exfiltration attacks on AgentDojo-style adapted scenarios; utility loss < 10 percentage points on benign tasks; report false positives per scenario; **measure** paraphrase evasion and say so honestly.

**No LLM is in the loop.** Each scenario is a fixed `tools/call` trace. Attack success = a sink call was recorded in the mock world's log with the secret in its payload (or the attacker destination). Worlds and attack shapes were adapted from AgentDojo's banking / workspace / slack injection tasks.

```sh
cargo build --release
./target/release/taintgate-bench \
  --scenarios scenarios/traces.json \
  --worlds scenarios \
  --policies policies \
  --out bench-report.json
```

Measured on a development machine (x86_64, 2026-10-27), 32 scenarios (12 attack / 9 benign / 11 evasion):

| metric | value |
|---|---|
| attacks baseline → taintgate | **12/12 → 0/12** (reduction **100 %**, target ≥ 90 %) |
| benign utility baseline → taintgate | **100 % → 100 %** (loss **0 pp**, target ≤ 10 pp) |
| false positives | **0** |
| mechanical evasion (base64, hex, rot13, reverse, leet, percent, number_words, base64+hex) | baseline 8/8 → taintgate **0/8** (caught 100 %) |
| paraphrase evasion | baseline 3/3 → taintgate **2/3** (caught **33 %**) |

Paraphrase is the central weakness of content matching. 2 of 3 paraphrase scenarios went through; the one that was caught still carried the distinctive word "Larch" from the original address, which the proper-noun atom extractor had stored. That is leftover lexicon, not semantic understanding.

CI `bench` job result ([run 40480538124](https://github.com/federiconbaez/cortex9-taintgate/actions/runs/40480538124), ubuntu-latest, 2026-10-27): attacks 12/12 → 0/12 (100 % reduction), benign utility 100 % → 100 % (0 pp loss), 0 false positives, mechanical evasion 8/8 → 0/8, paraphrase evasion 3/3 → 2/3 (caught 33 %). Measured on `ubuntu-latest` x86_64 runners only.

### Limitations

- No semantic understanding of paraphrase / translation / abstractive summary. Measured above; not solved.
- An agent that never puts the secret in a tool argument the gateway sees.
- MCP endpoints the gateway does not front.
- Approval UI: `mode = "ask"` needs an external command.
- No TLS / OAuth to downstream servers.
- Downstream sampling / roots / elicitation requests are refused.

### Sources read

- Simon Willison, *The lethal trifecta for AI agents* (2025-06-16). <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>
- Debenedetti et al., *Defeating Prompt Injections by Design* (CaMeL), arXiv:2503.18813. <https://arxiv.org/abs/2503.18813>
- AgentDojo (`ethz-spylab/agentdojo`): README and banking / workspace / slack `injection_tasks.py`. <https://github.com/ethz-spylab/agentdojo>

## License

Apache-2.0
