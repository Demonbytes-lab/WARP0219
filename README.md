<div align="center">

# Noxara WARP Profile — February Ragexe (2026-02-19)

**A ready-to-use [WARP](https://gitlab.com/4144/Warp) profile for the unpacked February 2026-02-19 `Ragexe` client.**
Maintained by **Noxara Solutions**.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Client](https://img.shields.io/badge/client-2026--02--19-orange.svg)](#the-client)
[![Discord](https://img.shields.io/badge/Discord-join%20us-5865F2.svg?logo=discord&logoColor=white)](https://discord.gg/KngCJ7aMrJ)
[![Reports](https://img.shields.io/badge/bugs-report%20here-brightgreen.svg)](../../issues)

</div>

---

## What is this?

This repo is a **drop-in WARP session** — the `.yml` profile plus the patch scripts, inputs and tables — pre-configured
for the **unpacked February 2026-02-19 `Ragexe`**. Instead of hunting down individual patches, resolving conflicts and
re-anchoring everything for a fresh client, you point WARP at a clean exe, load this profile, and get a fully patched,
server-ready client in one pass.

It's built and maintained by **Noxara Solutions** for the RO development community. Everyone's welcome to use it, fork it,
and build on it.

> **Not a patched exe.** This repo ships a *recipe*, not a binary. You bring the clean, unpacked Ragexe; WARP + this
> profile do the rest. No client binaries are distributed here.

---

## The client

| | |
|---|---|
| **Client** | `Ragexe` — February 2026-02-19 |
| **Internal BuildDate** | `20260211` |
| **PE TimeDateStamp** | `0x698BD9AB` |
| **ImageBase** | `0x00400000` |
| **State** | Unpacked / Themida-free (patch-ready) |

> ⚠️ This profile is anchored to the **unpacked** February client. A packed/protected exe, or a different client date,
> will fail pattern matches. Unpack first, and make sure your build date matches.

---

## What's inside

```
.
├── session_february.yml      # ← load this in WARP
├── Patches/                  # patch group registry (categories shown in the UI)
├── Scripts/
│   ├── Patches/              # the patch scripts (.qjs)
│   ├── Support/              # shared helpers
│   └── Init/                 # bootstrap
├── Inputs/                   # assets consumed by patches (fonts, images, tables…)
├── Tables/                   # patch + input metadata
├── Languages/                # translation tables
└── Outputs/                  # (generated) logs + your patched exe land here
```

---

## Requirements

- A **clean, unpacked** February 2026-02-19 `Ragexe.exe`.
- Windows (WARP is Windows-only at time of writing).

---

## Quick start (GUI)

1. **Download WARP** and open it.
2. **Clone or download** this repo somewhere local.
3. In WARP, **File → Load Session** and pick `session_february.yml`.
4. Set the **source** to your clean unpacked `Ragexe.exe`, and pick an **output** path.
5. Review the selected patches (tweak to taste), then **Apply / Save**.
6. Ship the patched exe with your GRF/data setup. Done.

## Quick start (headless / CI)

Prefer the command line? WARP ships a console runner:

```bat
WARP_console.exe -using session_february.yml -from "Ragexe.exe" -to "Ragexe_patched.exe"
```

Check `Outputs\*.warplog` and `SkippedPatches.log` after a run — a clean bake leaves `SkippedPatches.log`
empty. A patch listed in a session but missing from the tree is *silently ignored*, so always skim the log.

---

## What it does

This profile bundles a curated set of the community's most-used quality-of-life and customization patches,
re-anchored for the February client — think along the lines of:

- **Startup & login** — skip intros/ads, service-select flow, window title & icon, connection tweaks.
- **UI & HUD** — resized chat / NPC / status / equip windows, custom colors, EXP numbers, cleaner layouts.
- **Quality of life** — case-insensitive search, chat fixes, `@`/`/` command niceties, camera & zoom, font control.
- **Fonts & text** — charset fixes, code page, custom fonts, plain-text descriptions, message strings.
- **Rendering** — map quality, flag animation, effect toggles, misc performance patches.

The **authoritative list is the session file itself** — open `session_february.yml` (or the WARP UI) to see exactly
what's enabled. Nothing here is mandatory; enable/disable per your server's needs.

---

## Found a bug?

Client patching is anchor-sensitive — if a patch mis-fires on your setup, we want to know.

- 🐛 **Open an issue** right here on GitHub → **[Issues](../../issues)** (please include your client build date, the
  patch name, and the `Outputs\*.warplog` line).
- 💬 **Or open a ticket on Discord** → **[discord.gg/KngCJ7aMrJ](https://discord.gg/KngCJ7aMrJ)**

The more detail (build date, patch, log excerpt, repro steps), the faster we can re-anchor it.

---

## Credits

- **[WARP](https://gitlab.com/4144/Warp)** — *Win App Revamp Package* by **Neo-Mind**, with **Ai4rei/AN**,
  **Andrei Karas (4144)**, **Shinryo** and the wider RO dev community. This profile is nothing without their engine
  and patch library.
- Individual patch authors are credited in-file (see each `.qjs` header).
- **February profile assembly, re-anchoring & maintenance** — **Noxara Solutions**.

If your patch is included and you'd like different attribution (or removal), reach out on Discord.

---

## License

Released under the **[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0)**, matching WARP and its
patch scripts. You're free to use, modify and redistribute under the same terms. See [`LICENSE`](LICENSE) for details.

---

<div align="center">

**Noxara Solutions** · built for the Ragnarok community
[Discord](https://discord.gg/KngCJ7aMrJ) · [Report a bug](../../issues)

</div>
