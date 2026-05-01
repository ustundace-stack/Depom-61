import { useState } from 'react'

const VERDICT_META = {
  Clean:       { color: 'text-green-600',  bg: 'bg-green-50',  label: 'Clean'       },
  Suspicious:  { color: 'text-yellow-600', bg: 'bg-yellow-50', label: 'Suspicious'  },
  Quarantined: { color: 'text-red-600',    bg: 'bg-red-50',    label: 'Quarantined' },
  Skipped:     { color: 'text-gray-500',   bg: 'bg-gray-50',   label: 'Skipped'     },
  Error:       { color: 'text-rose-700',   bg: 'bg-rose-50',   label: 'Error'       },
}

const SEV_COLOR = {
  Low:      'bg-blue-100 text-blue-700',
  Medium:   'bg-yellow-100 text-yellow-700',
  High:     'bg-orange-100 text-orange-700',
  Critical: 'bg-red-100 text-red-700',
}

function Badge({ label, cls }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>{label}</span>
  )
}

function ScanEntryRow({ entry, expanded, onToggle }) {
  const meta = VERDICT_META[entry.verdict] ?? VERDICT_META.Error
  return (
    <div className={`border rounded mb-2 ${meta.bg}`}>
      <button
        className="w-full text-left px-4 py-2 flex items-center gap-3"
        onClick={onToggle}
      >
        <span className={`font-mono text-xs truncate flex-1 ${meta.color}`}>
          {entry.path}
        </span>
        <Badge label={meta.label} cls={`${meta.color} border`} />
        {entry.severity && (
          <Badge label={entry.severity} cls={SEV_COLOR[entry.severity] ?? ''} />
        )}
        {entry.dry_run && (
          <Badge label="DRY-RUN" cls="bg-purple-100 text-purple-700" />
        )}
        <span className="text-gray-400 text-xs">{expanded ? '▲' : '▼'}</span>
      </button>

      {expanded && (
        <div className="px-4 pb-3 text-xs space-y-2">
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-gray-600">
            <span>SHA-256</span><span className="truncate">{entry.sha256 || '—'}</span>
            <span>Size</span><span>{entry.size_bytes.toLocaleString()} B</span>
            <span>Entropy</span><span>{entry.entropy.toFixed(4)}</span>
            {entry.magic_hit && <><span>Magic</span><span>{entry.magic_hit}</span></>}
            {entry.quarantine_path && (
              <><span>Quarantine</span><span className="truncate">{entry.quarantine_path}</span></>
            )}
          </div>

          {entry.matched_rules.length > 0 && (
            <div>
              <p className="font-semibold text-gray-700 mb-1">Matched Rules</p>
              {entry.matched_rules.map((r, i) => (
                <div key={i} className="flex gap-2 items-start mb-1">
                  <Badge label={r.severity} cls={SEV_COLOR[r.severity] ?? ''} />
                  <span className="text-gray-600">{r.rule_id}</span>
                  <code className="text-red-700 break-all">{r.evidence}</code>
                </div>
              ))}
            </div>
          )}

          {entry.cot_trace.length > 0 && (
            <details>
              <summary className="cursor-pointer text-gray-500 hover:text-gray-800">
                CoT Trace ({entry.cot_trace.length} steps)
              </summary>
              <pre className="mt-1 bg-gray-900 text-green-400 p-2 rounded overflow-x-auto text-xs">
                {entry.cot_trace.join('\n')}
              </pre>
            </details>
          )}

          {entry.error && (
            <p className="text-red-600 font-mono">{entry.error}</p>
          )}
        </div>
      )}
    </div>
  )
}

export default function Scanner() {
  const [target, setTarget]           = useState('')
  const [dryRun, setDryRun]           = useState(true)
  const [recursive, setRecursive]     = useState(true)
  const [maxSizeMb, setMaxSizeMb]     = useState(512)
  const [quarantineDir, setQuarantineDir] = useState('/tmp/quarantine')
  const [whitelist, setWhitelist]     = useState('*.log,*.txt,*.md,*.json,*.toml,*.yaml,*.yml')
  const [blacklist, setBlacklist]     = useState('*.exe,*.bat,*.cmd,*.vbs,*.ps1,*.sh,*.dll,*.so,*.enc,*.locked,*.crypto,*.ransom')
  const [report, setReport]           = useState(null)
  const [loading, setLoading]         = useState(false)
  const [error, setError]             = useState(null)
  const [expanded, setExpanded]       = useState({})
  const [filterVerdict, setFilterVerdict] = useState('All')

  const toggle = (i) => setExpanded(prev => ({ ...prev, [i]: !prev[i] }))

  const parseCsv = (str) => str.split(',').map(s => s.trim()).filter(Boolean)

  const handleScan = async () => {
    if (!target) { setError('Target path is required.'); return }
    setLoading(true); setError(null); setReport(null); setExpanded({})

    try {
      // In production Tauri build: const { invoke } = await import('@tauri-apps/api/core')
      // For dev/preview we simulate the response structure.
      const invoke = window.__TAURI__?.core?.invoke ?? simulateInvoke

      const result = await invoke('run_scan', {
        target,
        dryRun,
        quarantineDir,
        whitelist: parseCsv(whitelist),
        blacklist: parseCsv(blacklist),
        recursive,
        maxFileSizeMb: maxSizeMb,
      })
      setReport(result)
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  // Browser-only simulation (no Tauri runtime)
  const simulateInvoke = async (_cmd, args) => ({
    scan_id: 'SIM-' + Math.random().toString(36).slice(2),
    started_at: new Date().toISOString(),
    finished_at: new Date().toISOString(),
    dry_run: args.dryRun,
    target_path: args.target,
    total_files: 3,
    clean: 1, suspicious: 1, quarantined: 1, skipped: 0, errors: 0,
    entries: [
      {
        path: `${args.target}/readme.txt`, sha256: 'abc123', size_bytes: 1024,
        verdict: 'Clean', severity: null, matched_rules: [], entropy: 3.1,
        magic_hit: null, quarantine_path: null, dry_run: args.dryRun,
        cot_trace: ['[CoT:1] Target', '[CoT:2] Size OK', '[CoT:10] VERDICT: Clean'],
        scanned_at: new Date().toISOString(), error: null,
      },
      {
        path: `${args.target}/payload.exe`, sha256: 'def456', size_bytes: 204800,
        verdict: args.dryRun ? 'Suspicious' : 'Quarantined',
        severity: 'High',
        matched_rules: [{ rule_id: 'RULE_000', severity: 'High', description: 'cmd.exe /c', evidence: 'cmd.exe /c del /f' }],
        entropy: 7.8, magic_hit: 'MZ PE executable',
        quarantine_path: args.dryRun ? `${args.quarantineDir}/payload.exe.infected` : null,
        dry_run: args.dryRun,
        cot_trace: ['[CoT:1] Target', '[CoT:6] Magic=MZ PE executable', '[CoT:7] Entropy=7.8000', '[CoT:10] VERDICT: Threat detected'],
        scanned_at: new Date().toISOString(), error: null,
      },
      {
        path: `${args.target}/data.enc`, sha256: 'ghi789', size_bytes: 8192,
        verdict: args.dryRun ? 'Suspicious' : 'Quarantined',
        severity: 'Medium',
        matched_rules: [], entropy: 7.5, magic_hit: null,
        quarantine_path: `${args.quarantineDir}/data.enc.infected`,
        dry_run: args.dryRun,
        cot_trace: ['[CoT:1] Target', '[CoT:4] BLACKLIST hit', '[CoT:7] Entropy=7.5000', '[CoT:10] VERDICT: Threat detected'],
        scanned_at: new Date().toISOString(), error: null,
      },
    ],
  })

  const verdicts = ['All', 'Clean', 'Suspicious', 'Quarantined', 'Skipped', 'Error']
  const filtered = report?.entries?.filter(e =>
    filterVerdict === 'All' || e.verdict === filterVerdict
  ) ?? []

  return (
    <div className="max-w-4xl mx-auto p-6 font-sans">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Blue Team — Defensive File Scanner</h1>
        <p className="text-sm text-gray-500 mt-1">
          Tauri 2.0 · Rust engine · CoT reasoning · Dry-Run safe
        </p>
      </div>

      {/* Config panel */}
      <div className="bg-white border rounded-lg p-4 mb-6 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Target Path</label>
            <input
              className="w-full border rounded px-3 py-2 text-sm font-mono"
              placeholder="/path/to/scan"
              value={target}
              onChange={e => setTarget(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Quarantine Dir</label>
            <input
              className="w-full border rounded px-3 py-2 text-sm font-mono"
              value={quarantineDir}
              onChange={e => setQuarantineDir(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Whitelist (CSV globs)</label>
            <input
              className="w-full border rounded px-3 py-2 text-sm font-mono"
              value={whitelist}
              onChange={e => setWhitelist(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Blacklist (CSV globs)</label>
            <input
              className="w-full border rounded px-3 py-2 text-sm font-mono"
              value={blacklist}
              onChange={e => setBlacklist(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Max File Size (MB)</label>
            <input
              type="number" min={1} max={4096}
              className="w-full border rounded px-3 py-2 text-sm"
              value={maxSizeMb}
              onChange={e => setMaxSizeMb(Number(e.target.value))}
            />
          </div>
          <div className="flex items-center gap-6 pt-5">
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={dryRun} onChange={e => setDryRun(e.target.checked)} />
              <span className="font-medium text-purple-700">Dry-Run (simulate only)</span>
            </label>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={recursive} onChange={e => setRecursive(e.target.checked)} />
              Recursive
            </label>
          </div>
        </div>

        <button
          className={`w-full py-2 rounded font-semibold text-white transition ${
            loading ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
          }`}
          disabled={loading}
          onClick={handleScan}
        >
          {loading ? 'Scanning…' : dryRun ? 'Run Dry-Scan' : 'Run Live Scan'}
        </button>

        {dryRun && (
          <p className="text-xs text-purple-600 text-center">
            Dry-Run active — no files will be moved or modified.
          </p>
        )}
      </div>

      {error && (
        <div className="bg-red-50 border border-red-300 text-red-700 rounded p-3 mb-4 text-sm">
          {error}
        </div>
      )}

      {/* Summary */}
      {report && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
            {[
              { label: 'Total',       val: report.total_files,  cls: 'text-gray-700' },
              { label: 'Clean',       val: report.clean,        cls: 'text-green-600' },
              { label: 'Suspicious',  val: report.suspicious,   cls: 'text-yellow-600' },
              { label: 'Quarantined', val: report.quarantined,  cls: 'text-red-600' },
              { label: 'Errors',      val: report.errors,       cls: 'text-rose-700' },
            ].map(({ label, val, cls }) => (
              <div key={label} className="bg-white border rounded p-3 text-center">
                <p className={`text-2xl font-bold ${cls}`}>{val}</p>
                <p className="text-xs text-gray-500">{label}</p>
              </div>
            ))}
          </div>

          <div className="flex gap-2 mb-3 flex-wrap">
            {verdicts.map(v => (
              <button
                key={v}
                onClick={() => setFilterVerdict(v)}
                className={`px-3 py-1 rounded text-xs font-medium border transition ${
                  filterVerdict === v
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-600 border-gray-300 hover:border-blue-400'
                }`}
              >
                {v}
              </button>
            ))}
          </div>

          <div>
            {filtered.length === 0 && (
              <p className="text-gray-400 text-sm text-center py-6">No entries for this filter.</p>
            )}
            {filtered.map((entry, i) => (
              <ScanEntryRow
                key={i}
                entry={entry}
                expanded={!!expanded[i]}
                onToggle={() => toggle(i)}
              />
            ))}
          </div>
        </>
      )}
    </div>
  )
}
