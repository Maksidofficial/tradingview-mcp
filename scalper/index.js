#!/usr/bin/env node
/**
 * Polymarket BTC UP/DOWN 5MIN Scalper
 *
 * Usage:
 *   node scalper/index.js              # paper mode (default)
 *   PAPER_TRADE=false node scalper/index.js  # live mode
 *   CQ_API_KEY=xxx node scalper/index.js     # with CryptoQuant flows
 */

import { CONFIG } from './config.js';
import * as binance    from './feeds/binance.js';
import * as polymarket from './feeds/polymarket.js';
import * as cq         from './feeds/cryptoquant.js';
import * as tv         from './feeds/tradingview.js';
import { MirofishGraph } from './engine/force_graph.js';
import { detectEdge }    from './engine/edge_detector.js';
import { aggregate }     from './engine/signal.js';
import { RiskManager }   from './execution/risk.js';
import { Executor }      from './execution/executor.js';
import { render, clear } from './display.js';

// ── State ──────────────────────────────────────────────────────────────────────

const weights   = MirofishGraph.loadWeights();
const graph     = new MirofishGraph(weights);
const risk      = new RiskManager();
let   executor  = null;

let   lastFgResult  = null;
let   lastSignal    = null;
let   lastEdge      = null;
let   tvSignals     = null;
let   _fgTimer      = null;
let   _displayTimer = null;
let   _running      = false;

// ── Feed callbacks ─────────────────────────────────────────────────────────────

function onTick(_tick) {
  // Tick arrives at high frequency — let the graph timer consume it
}

function onKline(kline) {
  if (kline.isFinal) {
    // Fresh 5m candle: refresh TV signals (non-blocking)
    tv.getTVSignals().then(s => { tvSignals = s; }).catch(() => {});
  }
}

async function onBookUpdate(_book) {
  const bState  = binance.getState();
  const pmState = polymarket.getState();

  // Update force graph node for PM lag signal
  if (lastEdge) {
    graph._setNode('sp_lag', Math.min(1, lastEdge.lag_pct / 0.008));
    graph._setNode('sp_momentum_prob', lastEdge.momentumProb * 2 - 1);
  }

  // Detect edge
  const edge = detectEdge(bState, pmState);
  lastEdge = edge;

  if (!edge) return;

  // Aggregate signals
  const sig = aggregate({
    binance:     bState,
    tradingview: tvSignals,
    cryptoquant: cq.getState(),
    polymarket:  pmState,
    forceGraph:  lastFgResult,
  });
  lastSignal = sig;

  // Execute
  await executor.execute(edge, sig);
}

// ── Main ───────────────────────────────────────────────────────────────────────

async function start() {
  _running = true;

  process.stdout.write('\x1b[?25l');  // hide cursor
  process.stdout.write('\x1b[2J\x1b[H');  // clear screen

  console.log('  BTC 5M Scalper starting…');
  console.log(`  Mode: ${CONFIG.PAPER_TRADE ? 'PAPER' : 'LIVE'}`);
  console.log(`  Capital: $${CONFIG.CAPITAL_USDC}`);
  if (CONFIG.CQ_API_KEY) console.log('  CryptoQuant: enabled');
  console.log('');

  // ── 1. Polymarket market discovery ──────────────────────────────────
  process.stdout.write('  Discovering Polymarket markets…');
  let pmTokens;
  try {
    pmTokens = await polymarket.start();
    if (!pmTokens.upTokenId && !pmTokens.downTokenId) {
      process.stdout.write(' not found (continuing without PM feed)\n');
    } else {
      process.stdout.write(` UP: ${pmTokens.upTokenId?.slice(0, 12)}… DOWN: ${pmTokens.downTokenId?.slice(0, 12)}…\n`);
    }
  } catch (err) {
    process.stdout.write(` failed (${err.message})\n`);
  }

  // ── 2. Binance WebSocket ─────────────────────────────────────────────
  process.stdout.write('  Connecting Binance WebSocket…');
  binance.connect(onTick, onKline);
  await new Promise(r => setTimeout(r, 1500));
  process.stdout.write(` ${binance.getState().connected ? 'OK' : 'FAILED'}\n`);

  // ── 3. CryptoQuant poll ──────────────────────────────────────────────
  cq.start();

  // ── 4. TradingView (best-effort) ─────────────────────────────────────
  tv.isAvailable().then(ok => {
    if (!ok) process.stderr.write('  [tv] TradingView not reachable — TV signals disabled\n');
    else     process.stdout.write('  TradingView: connected\n');
  });

  // ── 5. Polymarket CLOB book update listener ──────────────────────────
  polymarket.on('book_update', onBookUpdate);

  // ── 6. Executor ──────────────────────────────────────────────────────
  executor = new Executor(risk, graph);

  // ── 7. Force graph tick (50ms) ───────────────────────────────────────
  _fgTimer = setInterval(() => {
    graph.setSignals({
      binance:     binance.getState(),
      tradingview: tvSignals,
      cryptoquant: cq.getState(),
      polymarket:  polymarket.getState(),
    });
    lastFgResult = graph.tick();
  }, CONFIG.FORCE_GRAPH_TICK_MS);

  // ── 8. Initial TV signal fetch ────────────────────────────────────────
  tv.getTVSignals().then(s => { tvSignals = s; }).catch(() => {});

  await new Promise(r => setTimeout(r, 500));
  process.stdout.write('\x1b[2J\x1b[H');

  // ── 9. Display refresh (200ms) ────────────────────────────────────────
  _displayTimer = setInterval(() => {
    const rs = risk.stats();
    render({
      binance:     binance.getState(),
      pm:          polymarket.getState(),
      signal:      lastSignal,
      forceGraph:  lastFgResult,
      risk:        rs,
      recentTrades: risk.tradesLog.slice(-10),
      edge:        lastEdge,
    });
  }, CONFIG.DISPLAY_INTERVAL_MS);
}

function shutdown() {
  _running = false;
  clearInterval(_fgTimer);
  clearInterval(_displayTimer);
  clear();
  process.stdout.write('\x1b[?25h');  // restore cursor
  binance.disconnect();
  polymarket.stop();
  cq.stop();

  const rs = risk.stats();
  console.log('\n  Session summary:');
  console.log(`  Trades:  ${rs.totalTrades}`);
  console.log(`  P&L:     ${rs.dailyPnL >= 0 ? '+' : ''}${rs.dailyPnL.toFixed(2)} USDC`);
  console.log(`  Exposure:${rs.dailyExposure.toFixed(2)} USDC`);

  graph.saveWeights();
  process.exit(0);
}

process.on('SIGINT',  shutdown);
process.on('SIGTERM', shutdown);

start().catch(err => {
  process.stdout.write('\x1b[?25h');
  console.error('Fatal startup error:', err);
  process.exit(1);
});
