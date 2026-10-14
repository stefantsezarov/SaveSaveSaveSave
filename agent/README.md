# SaveSaveSaveSave for agents

The engine behind [savesavesavesave.xyz](https://savesavesavesave.xyz), for AI agents and scripts: check a message, an npm package, a crypto address, or two addresses against each other **before acting**.

- **MCP server** for Claude, Cursor, VS Code, Windsurf and any MCP client
- **CLI** for scripts and CI
- **Library** for Node.js

Read-only, zero dependencies, and the same code the website runs (CI fails if they drift apart).

## MCP server

Claude Code: `claude mcp add savesavesavesave -- npx -y savesavesavesave mcp`

Other clients: add this to the MCP configuration (for example `claude_desktop_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "savesavesavesave": { "command": "npx", "args": ["-y", "savesavesavesave", "mcp"] }
  }
}
```

| Tool | Use it before… | Network |
|---|---|---|
| `scan_message` | following instructions in a DM, email, web page, README or prompt | none, local |
| `check_package` | `npm install` | npm registry, OSV.dev |
| `scan_address` | paying, approving or buying a token | GoPlus Security, our Worker |
| `compare_addresses` | sending to an address copied from history | none, local |

## CLI

```
npx savesavesavesave message "Reply with your 12-word phrase to restore access"
npx savesavesavesave package crossenv
npx savesavesavesave address 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 1
npx savesavesavesave compare <expected> <actual>
npx savesavesavesave deps . --markdown      # check a project's npm dependencies
```

Output is JSON. Exit code: `0` PASS, `1` CAUTION or unknown, `2` FAIL, `3` usage error. The exit code makes it usable as a CI gate.

## GitHub Action

Checks a project's direct npm dependencies on pull requests (exact versions from `package-lock.json`, and flags git, URL or other non-registry sources). Fails the job at FAIL, or also at CAUTION with `fail-on: caution`.

```yaml
on:
  pull_request:
    paths: ['**/package.json', '**/package-lock.json']
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: stefantsezarov/SaveSaveSaveSave@v0.1.4
```

Transitive dependencies are not checked. Only names and versions are sent, to npm and OSV.dev.

## Library

```js
const s = require('savesavesavesave');
s.scanMessage(text);                          // synchronous, local
await s.checkPackage('ethers@6.13.0');
await s.scanAddress(addr, { chain: '1', mode: 'token' });
s.compareAddresses(expected, actual);
```

## Result contract (1.0)

Every result keeps its existing fields (`verdict`, `label`, `summary`, `checks`, `not_checked` and so on) and adds one `contract` block:

```json
"contract": {
  "contract_version": "1.0",
  "status": "completed",
  "assessment": { "risk_level": "none_found", "coverage": "partial", "meaning": "No covered risk was found. This is not a statement that the item is safe." },
  "not_checked": ["The package code was not downloaded or analysed.", "..."],
  "provenance": { "tool_package_version": "0.1.5", "engine_version": "0.2.0", "processed_locally": false, "as_of": "2026-10-14T00:00:00.000Z" }
}
```

| Field | Values | Meaning |
| --- | --- | --- |
| `status` | `completed`, `insufficient_evidence` | Whether the check produced an assessment at all |
| `assessment.risk_level` | `high`, `medium`, `none_found`, `unknown` | FAIL, CAUTION, PASS, INSUFFICIENT DATA. There is no `safe` value |
| `assessment.coverage` | `full`, `partial`, `none` | Share of this tool's own checks that returned usable data |
| `not_checked` | list of strings | What the check could not see. Never empty |
| `provenance.as_of` | ISO time or `null` | When remote data was read; `null` for local checks |

The contract carries **no allow/deny decision**. Whether an action may go ahead is a policy you control, applied on your machine: see `guard` below.

## Pre-install guard

`guard` checks what an install command would bring in and applies a policy **you** choose. The scan supplies evidence; the decision is made on your machine and cannot be changed by anything a package, a registry or a web page says.

```sh
npx savesavesavesave@0.1.5 guard --mode guard -- npm install some-package
# exit 0 allow, 1 review, 2 deny, 3 usage error
```

| Mode | FAIL | CAUTION or not enough data | Check failed or timed out | Not from the registry (git, URL, path) | PASS with partial coverage |
| --- | --- | --- | --- | --- | --- |
| `observe` | allow (reports deny) | allow | allow | allow | allow |
| `guard` (default) | deny | review | review | review | allow |
| `strict` | deny | deny | deny | deny | deny |

It understands `npm`, `pnpm`, `yarn` and `bun` installs, `npm ci` and a bare `npm install` (it then checks package.json and the lockfile), `npx`/`pnpm dlx`/`yarn dlx`/`bunx`, and installs chained with `&&`, `;` or `|`. The mode can also be set with `SAVESAVESAVESAVE_GUARD_MODE`.

### Claude Code hook

Add to `.claude/settings.json` in your project (pin the version you reviewed):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [ { "type": "command", "command": "npx -y savesavesavesave@0.1.5 hook claude-code --mode guard" } ] }
    ]
  }
}
```

For `strict`, also add `"timeout": 120` and `"onFailure": "block"` to the hook entry (Claude Code 2.1.295 or later). Without `onFailure`, Claude Code runs the command if the hook itself times out or cannot start, for example when npx cannot download the package.

The hook only ever answers `deny` (FAIL) or `ask` (review). It never answers `allow`, so a clean result cannot skip your own permission prompt. Commands without an install pass through untouched.

### What it does not do

The guard sees the commands it is shown. An agent that installs through a route the hook does not inspect, such as a shell script file, a package manager it does not know, or a downloaded binary, is not stopped by it. For hard enforcement, add network or filesystem controls on the host. It never downloads or runs package code.

## Security model

- **Read-only.** No tool writes files, runs commands, or holds keys or secrets. There is nothing here that can change the website or its repository.
- **Local first.** Message scans and address comparisons never leave the machine.
- **Network allowlist, enforced in code:** `api.gopluslabs.io`, our Worker, `registry.npmjs.org`, `api.npmjs.org`, `api.osv.dev`. HTTPS only, redirects refused, and a 20-second timeout for each response to start.
- **Untrusted output is labelled.** Results quote the scanned text and third-party data. Every result says so, so an agent does not follow instructions hidden inside it.
- **Strict inputs.** Unknown tool arguments are rejected, and input is capped at 200,000 characters.
- **Zero dependencies.** A security tool should not bring its own supply chain.

## Limits

Verdicts are automated risk assessments, not guarantees; PASS means no covered risk was found. Every result lists what was not checked.

Full reference for agent developers: https://savesavesavesave.xyz/agents

Licence: AGPL-3.0-only. Source: https://github.com/stefantsezarov/SaveSaveSaveSave
