import { CONFIG } from './config.js';

const RESET  = '\x1b[0m';
const BOLD   = '\x1b[1m';
const GREEN  = '\x1b[32m';
const RED    = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN   = '\x1b[36m';
const DIM    = '\x1b[2m';
const BLUE   = '\x1b[34m';
const MAGENTA = '\x1b[35m';

function bar(score, width = 12) {
  const filled = Math.round(Math.min(1, Math.max(0, score)) * width);
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}

function pct(n) {
  if (n == null) return '  N/A  ';
  const s = (n * 100).toFixed(2);
  return n >= 0 ? `+${s}%` : `${s}%`;
}

function price(n) {
  return n != null ? `$${n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}` : '--';
}

function pad(s, n) {
  s = String(s ?? '');
  return s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length);
}

function timeStr(ts) {
  return new Date(ts).toISOString().slice(11, 19);
}

let _lineCount = 0;

function render({ binance, pm, signal, forceGraph, risk, recentTrades, edge }) {
  const b   = binance ?? {};
  const up  = pm?.up  ?? {};
  const dn  = pm?.down ?? {};

  const spotChange  = b.price && b.price_60s ? (b.price - b.price_60s) / b.price_60s : null;
  const upMid       = up.mid;
  const dnMid       = dn.mid;
  const lagPct      = edge?.lag_pct;
  const edgeMark    = edge ? `${edge.direction} ${(lagPct * 100).toFixed(2)}%` : '──';
  const edgeColor   = edge ? GREEN : DIM;
  const changeColor = spotChange == null ? DIM : spotChange >= 0 ? GREEN : RED;

  const fg = forceGraph ?? {};
  const bullPct = fg.bull_score ?? 0;
  const bearPct = fg.bear_score ?? 0;
  const conv    = fg.convergence ?? 0;
  const biasColor = fg.bias === 'BULL' ? GREEN : fg.bias === 'BEAR' ? RED : DIM;

  const rs = risk ?? {};
  const pnlColor = rs.dailyPnL >= 0 ? GREEN : RED;
  const capUsed  = rs.dailyCapUsed ?? 0;
  const capColor = capUsed > 0.8 ? RED : capUsed > 0.5 ? YELLOW : GREEN;

  const mode = CONFIG.PAPER_TRADE ? `${YELLOW}PAPER${RESET}` : `${RED}LIVE${RESET}`;
  const sigDir = signal?.direction ?? '──';
  const sigConf = signal?.confidence != null ? `${(signal.confidence * 100).toFixed(0)}%` : '--';
  const sigColor = sigDir === 'UP' ? GREEN : sigDir === 'DOWN' ? RED : DIM;

  const W = 72;
  const line = (s) => `│ ${s} │\n`;
  const sep  = (l, r) => `├─ ${pad(l, 23)} ─┼─ ${pad(r, 38)} ─┤\n`;

  let out = '';

  // Clear previous render
  if (_lineCount > 0) {
    out += `\x1b[${_lineCount}A\x1b[0J`;
  }

  out += `┌─ ${BOLD}BTC 5M SCALPER${RESET} `;
  out += `─`.repeat(W - 18) + `┐\n`;

  // Row 1: price + PM
  out += `│ BTC  ${BOLD}${changeColor}${price(b.price)}${RESET}  ${changeColor}${pct(spotChange)}${RESET}`;
  out += `  │  PM UP: ${CYAN}${upMid != null ? upMid.toFixed(3) : '--'}${RESET}  DOWN: ${CYAN}${dnMid != null ? dnMid.toFixed(3) : '--'}${RESET}       │\n`;

  // Row 2: edge
  out += `│ ${DIM}Lag: ${lagPct != null ? (lagPct * 100).toFixed(2) + '%' : '--'}${RESET}              `;
  out += `│  Edge: ${edgeColor}${pad(edgeMark, 14)}${RESET}  Liq: ${up.askDepth != null ? '$' + up.askDepth.toFixed(0) : '--'}         │\n`;

  out += sep('SIGNALS', 'FORCE GRAPH (Mirofish)');

  // Force graph rows
  const bScore = Math.min(1, bullPct);
  const rScore = Math.min(1, bearPct);
  const biasStr = pad(`${fg.bias ?? '--'}`, 4);

  out += `│  Signal: ${sigColor}${pad(sigDir, 5)}${RESET} conf: ${pad(sigConf, 4)}      │  ${GREEN}BULL${RESET} ${bar(bScore)}  ${bScore.toFixed(2)}         │\n`;
  out += `│  RSI: ${pad(signal?.rsi?.toFixed(1) ?? '--', 6)}                   │  ${RED}BEAR${RESET} ${bar(rScore)}  ${rScore.toFixed(2)}         │\n`;
  out += `│  MACD: ${pad(signal?.macd?.toFixed(2) ?? '--', 8)}                 │  Conv: ${biasColor}${conv.toFixed(2)}${RESET}  Bias: ${biasColor}${biasStr}${RESET}         │\n`;
  out += `│  CQ net flow: ${pad(rs.cqFlow != null ? rs.cqFlow.toFixed(0) : '--', 8)}        │                                           │\n`;

  // Trades header
  out += `├─ TRADES ${'─'.repeat(W - 11)}┤\n`;
  out += `│  ${DIM}#   Time      Dir   Cost     Entry   Latency${RESET}`;
  out += `${'─'.repeat(W - 49)} │\n`;

  const trades = (recentTrades ?? []).slice(-5);
  for (let i = 0; i < Math.max(trades.length, 2); i++) {
    const t = trades[i];
    if (!t) { out += `│  ${DIM}──${RESET}${' '.repeat(W - 5)}│\n`; continue; }
    const tColor = (t.pnl ?? 0) >= 0 ? GREEN : RED;
    const dir    = t.direction ?? '--';
    const dColor = dir === 'UP' ? GREEN : RED;
    out += `│  ${pad(i + 1, 3)} ${timeStr(t.ts ?? t.entryTs ?? 0)}  ${dColor}${pad(dir, 5)}${RESET} `;
    out += `$${pad((t.costUsdc ?? t.cost_usdc ?? 0).toFixed(2), 8)} `;
    out += `${pad((t.entryPrice ?? 0).toFixed(3), 7)} `;
    out += `${tColor}${pad(t.pnl != null ? pct(t.pnl / (t.costUsdc ?? 1)) : 'open', 8)}${RESET}`;
    out += `${pad(t.latencyMs != null ? t.latencyMs.toFixed(0) + 'ms' : '--', 6)}`;
    out += `${' '.repeat(Math.max(0, W - 67))}│\n`;
  }

  // P&L footer
  out += `├─ P&L ${'─'.repeat(W - 7)}┤\n`;
  out += `│  Today: ${pnlColor}${(rs.dailyPnL ?? 0) >= 0 ? '+' : ''}${(rs.dailyPnL ?? 0).toFixed(2)} USDC${RESET}`;
  out += `  Cap: ${capColor}${(capUsed * 100).toFixed(1)}%${RESET}`;
  out += `  Trades: ${rs.totalTrades ?? 0}`;
  out += `  Mode: ${mode}`;
  out += `${' '.repeat(Math.max(0, W - 57))}│\n`;

  out += `└${'─'.repeat(W + 2)}┘\n`;

  const lines = out.split('\n').length - 1;
  _lineCount = lines;

  process.stdout.write(out);
}

function clear() {
  if (_lineCount > 0) process.stdout.write(`\x1b[${_lineCount}A\x1b[0J`);
  _lineCount = 0;
}

export { render, clear };
