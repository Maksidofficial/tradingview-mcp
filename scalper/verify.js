#!/usr/bin/env node
/**
 * Post-session verification tool.
 * Reads JSONL logs from scalper/logs/ and outputs a performance report.
 *
 * Usage: node scalper/verify.js [YYYY-MM-DD]
 */

import { readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const LOG_DIR = join(dirname(fileURLToPath(import.meta.url)), 'logs');
const date    = process.argv[2] ?? new Date().toISOString().slice(0, 10);

// ── Load events ────────────────────────────────────────────────────────────────

function loadLog(filepath) {
  try {
    return readFileSync(filepath, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean);
  } catch { return []; }
}

function listDates() {
  try {
    return readdirSync(LOG_DIR)
      .filter(f => f.endsWith('.jsonl'))
      .map(f => f.replace('.jsonl', ''));
  } catch { return []; }
}

if (process.argv[2] === '--list') {
  const dates = listDates();
  console.log('Available session logs:');
  dates.forEach(d => console.log(`  ${d}`));
  process.exit(0);
}

const events = loadLog(join(LOG_DIR, `${date}.jsonl`));
if (events.length === 0) {
  console.error(`No log found for ${date}. Run: node scalper/verify.js --list`);
  process.exit(1);
}

// ── Parse event types ─────────────────────────────────────────────────────────

const edges    = events.filter(e => e.type === 'edge');
const signals  = events.filter(e => e.type === 'signal');
const trades   = events.filter(e => e.type === 'trade');
const outcomes = events.filter(e => e.type === 'outcome');
const skips    = events.filter(e => e.type === 'skip');
const warns    = events.filter(e => e.type === 'warn');

// ── Latency analysis ──────────────────────────────────────────────────────────

const latencies = trades.map(t => t.latency_ms).filter(Boolean).sort((a, b) => a - b);
function percentile(arr, p) {
  if (!arr.length) return null;
  const idx = Math.floor(arr.length * p / 100);
  return arr[Math.min(idx, arr.length - 1)];
}

// ── P&L analysis ──────────────────────────────────────────────────────────────

const completedTrades = outcomes.filter(o => o.pnl != null);
const wins  = completedTrades.filter(o => o.pnl > 0);
const losses = completedTrades.filter(o => o.pnl <= 0);
const totalPnl = completedTrades.reduce((s, o) => s + o.pnl, 0);
const avgPnl   = completedTrades.length ? totalPnl / completedTrades.length : 0;

// ── Edge detection accuracy ───────────────────────────────────────────────────

const edgeMap = new Map();
edges.forEach(e => edgeMap.set(e._ts, e));

let correctEdges = 0, totalCompletedEdges = 0;
// For each outcome, check if the corresponding edge direction matched
outcomes.forEach(o => {
  if (o.pnl == null) return;
  totalCompletedEdges++;
  if (o.pnl > 0) correctEdges++;
});

// ── Skip reasons ──────────────────────────────────────────────────────────────

const skipReasons = {};
skips.forEach(s => { skipReasons[s.reason] = (skipReasons[s.reason] ?? 0) + 1; });

// ── Signal conflict rate ──────────────────────────────────────────────────────

const conflictedSignals = signals.filter(s => s.conflicts && s.conflicts.length > 0);

// ── Report ────────────────────────────────────────────────────────────────────

const B = '\x1b[1m', R = '\x1b[0m', G = '\x1b[32m', Y = '\x1b[33m', RD = '\x1b[31m';

console.log(`\n${B}═══ Scalper Verification Report — ${date} ═══${R}\n`);

console.log(`${B}ACTIVITY${R}`);
console.log(`  Edges detected:  ${edges.length}`);
console.log(`  Trades taken:    ${trades.length}  (${skips.length} skipped)`);
console.log(`  Outcomes logged: ${completedTrades.length}`);
if (warns.length) console.log(`  ${Y}Slow executions: ${warns.length}${R}`);

console.log(`\n${B}P&L${R}`);
const pnlColor = totalPnl >= 0 ? G : RD;
console.log(`  Total:   ${pnlColor}${totalPnl >= 0 ? '+' : ''}${totalPnl.toFixed(4)} USDC${R}`);
console.log(`  Wins:    ${wins.length}  Losses: ${losses.length}  WR: ${completedTrades.length ? (wins.length / completedTrades.length * 100).toFixed(1) : '--'}%`);
console.log(`  Avg P&L: ${avgPnl >= 0 ? '+' : ''}${avgPnl.toFixed(4)} USDC/trade`);

console.log(`\n${B}LATENCY${R}`);
if (latencies.length) {
  const p50 = percentile(latencies, 50);
  const p95 = percentile(latencies, 95);
  const p99 = percentile(latencies, 99);
  const latColor = p99 > 100 ? RD : p95 > 80 ? Y : G;
  console.log(`  p50: ${p50?.toFixed(1)}ms  p95: ${p95?.toFixed(1)}ms  p99: ${latColor}${p99?.toFixed(1)}ms${R}`);
} else {
  console.log('  No latency data');
}

console.log(`\n${B}EDGE ACCURACY${R}`);
if (totalCompletedEdges > 0) {
  const acc = (correctEdges / totalCompletedEdges * 100).toFixed(1);
  const accColor = Number(acc) > 55 ? G : Number(acc) > 45 ? Y : RD;
  console.log(`  ${accColor}${correctEdges}/${totalCompletedEdges} correct (${acc}%)${R}`);
} else {
  console.log('  No completed trades to evaluate');
}

console.log(`\n${B}SIGNAL ANALYSIS${R}`);
console.log(`  Signals generated: ${signals.length}`);
console.log(`  With conflicts:    ${conflictedSignals.length} (${signals.length ? (conflictedSignals.length / signals.length * 100).toFixed(1) : '--'}%)`);

console.log(`\n${B}SKIP REASONS${R}`);
if (Object.keys(skipReasons).length === 0) {
  console.log('  None');
} else {
  Object.entries(skipReasons)
    .sort((a, b) => b[1] - a[1])
    .forEach(([reason, count]) => console.log(`  ${pad(reason, 28)} ${count}`));
}

console.log(`\n${B}EDGE DISTRIBUTION${R}`);
const upEdges   = edges.filter(e => e.direction === 'UP').length;
const downEdges = edges.filter(e => e.direction === 'DOWN').length;
console.log(`  UP edges: ${upEdges}  DOWN edges: ${downEdges}`);
if (edges.length) {
  const avgLag = edges.reduce((s, e) => s + (e.lag_pct ?? 0), 0) / edges.length;
  console.log(`  Avg lag: ${(avgLag * 100).toFixed(3)}%`);
}

console.log('');

function pad(s, n) { s = String(s); return s + ' '.repeat(Math.max(0, n - s.length)); }
