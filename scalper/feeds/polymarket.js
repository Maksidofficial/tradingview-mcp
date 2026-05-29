import { WebSocket } from 'ws';
import { createRequire } from 'module';
import { CONFIG } from '../config.js';

// In-memory CLOB book state for UP and DOWN tokens
const state = {
  up:   { tokenId: null, bestBid: null, bestAsk: null, askDepth: 0, bidDepth: 0, mid: null },
  down: { tokenId: null, bestBid: null, bestAsk: null, askDepth: 0, bidDepth: 0, mid: null },
  connected: false,
};

const _listeners = new Set();
let _ws = null;

// ── Market discovery ──────────────────────────────────────────────────────────

async function discoverMarkets() {
  const url = `${CONFIG.POLYMARKET_REST}/markets?active=true&closed=false&tag=crypto&limit=50`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Polymarket markets fetch failed: ${res.status}`);
  const body = await res.json();
  const markets = body.data ?? body;

  for (const market of markets) {
    const desc = (market.question ?? market.description ?? '').toLowerCase();
    // Match "will btc be higher/lower in 5 minutes" style markets
    if (!desc.includes('btc') && !desc.includes('bitcoin')) continue;
    if (!desc.includes('5') && !desc.includes('five')) continue;

    const tokens = market.tokens ?? market.clob_token_ids ?? [];
    for (const token of tokens) {
      const outcome = (token.outcome ?? '').toLowerCase();
      if (outcome === 'yes' || outcome === 'up' || outcome === 'higher') {
        state.up.tokenId = token.token_id ?? token;
      }
      if (outcome === 'no' || outcome === 'down' || outcome === 'lower') {
        state.down.tokenId = token.token_id ?? token;
      }
    }
    if (state.up.tokenId && state.down.tokenId) break;
  }

  // Fallback: try the gamma markets API
  if (!state.up.tokenId) {
    await discoverViaGamma();
  }
}

async function discoverViaGamma() {
  const url = 'https://gamma-api.polymarket.com/markets?active=true&limit=100&tag=Crypto';
  try {
    const res = await fetch(url);
    const markets = await res.json();
    for (const m of markets) {
      const desc = (m.question ?? '').toLowerCase();
      if (!desc.includes('btc') && !desc.includes('bitcoin')) continue;
      if (!desc.includes('5 min') && !desc.includes('5-min') && !desc.includes('five')) continue;
      const tokens = m.clobTokenIds ?? [];
      if (tokens.length >= 2) {
        state.up.tokenId   = tokens[0];
        state.down.tokenId = tokens[1];
        break;
      }
    }
  } catch { /* best-effort */ }
}

// ── Book fetch (REST snapshot) ─────────────────────────────────────────────────

async function fetchBook(tokenId) {
  const res = await fetch(`${CONFIG.POLYMARKET_REST}/book?token_id=${tokenId}`);
  if (!res.ok) return null;
  const book = await res.json();
  return parseBook(book);
}

function parseBook(book) {
  const bids = (book.bids ?? []).sort((a, b) => b.price - a.price);
  const asks = (book.asks ?? []).sort((a, b) => a.price - b.price);
  const bestBid = bids[0] ? parseFloat(bids[0].price) : null;
  const bestAsk = asks[0] ? parseFloat(asks[0].price) : null;
  const askDepth = asks.slice(0, 5).reduce((s, o) => s + parseFloat(o.size ?? 0), 0);
  const bidDepth = bids.slice(0, 5).reduce((s, o) => s + parseFloat(o.size ?? 0), 0);
  return { bestBid, bestAsk, askDepth, bidDepth, mid: bestBid && bestAsk ? (bestBid + bestAsk) / 2 : null };
}

async function snapshotBooks() {
  if (state.up.tokenId) {
    const b = await fetchBook(state.up.tokenId);
    if (b) Object.assign(state.up, b);
  }
  if (state.down.tokenId) {
    const b = await fetchBook(state.down.tokenId);
    if (b) Object.assign(state.down, b);
  }
}

// ── WebSocket subscription ────────────────────────────────────────────────────

function subscribeWS(attempt = 0) {
  const ws = new WebSocket(CONFIG.POLYMARKET_WS);
  _ws = ws;

  ws.on('open', () => {
    state.connected = true;
    const tokens = [state.up.tokenId, state.down.tokenId].filter(Boolean);
    if (tokens.length) {
      ws.send(JSON.stringify({
        auth: {},
        type: 'subscribe',
        channel: 'book',
        assets_ids: tokens,
      }));
    }
  });

  ws.on('message', (raw) => {
    let events;
    try { events = JSON.parse(raw); } catch { return; }
    if (!Array.isArray(events)) events = [events];
    for (const ev of events) {
      if (ev.event_type === 'book' || ev.type === 'book') handleBook(ev);
      if (ev.event_type === 'price_change' || ev.type === 'price_change') handlePriceChange(ev);
    }
  });

  ws.on('error', () => {});
  ws.on('close', () => {
    state.connected = false;
    _ws = null;
    const delay = Math.min(1000 * 2 ** attempt, 30_000);
    if (attempt < 5) setTimeout(() => subscribeWS(attempt + 1), delay);
  });
}

function handleBook(ev) {
  const tokenId = ev.asset_id ?? ev.token_id;
  const side = tokenId === state.up.tokenId ? 'up' : tokenId === state.down.tokenId ? 'down' : null;
  if (!side) return;
  const parsed = parseBook({ bids: ev.bids ?? [], asks: ev.asks ?? [] });
  Object.assign(state[side], parsed);
  emit('book_update', { side, ...state[side] });
}

function handlePriceChange(ev) {
  const tokenId = ev.asset_id ?? ev.token_id;
  const side = tokenId === state.up.tokenId ? 'up' : tokenId === state.down.tokenId ? 'down' : null;
  if (!side) return;
  const price = parseFloat(ev.price ?? 0);
  const changes = ev.changes ?? [];
  for (const c of changes) {
    if (c.side === 'BUY' || c.side === 'bid') {
      state[side].bestBid = parseFloat(c.price ?? price);
    } else {
      state[side].bestAsk = parseFloat(c.price ?? price);
    }
  }
  if (state[side].bestBid && state[side].bestAsk) {
    state[side].mid = (state[side].bestBid + state[side].bestAsk) / 2;
  }
  emit('book_update', { side, ...state[side] });
}

// ── Event emitter (minimal) ───────────────────────────────────────────────────

function on(event, fn) {
  _listeners.add({ event, fn });
}

function off(event, fn) {
  for (const l of _listeners) {
    if (l.event === event && l.fn === fn) { _listeners.delete(l); break; }
  }
}

function emit(event, data) {
  for (const l of _listeners) {
    if (l.event === event) l.fn(data);
  }
}

// ── Order submission (live mode) ──────────────────────────────────────────────

async function submitOrder({ direction, sizeUsdc, price }) {
  if (CONFIG.PAPER_TRADE) throw new Error('submitOrder called in paper mode');
  const tokenId = direction === 'UP' ? state.up.tokenId : state.down.tokenId;
  const body = JSON.stringify({
    order_type: 'FOK',
    side: 'BUY',
    token_id: tokenId,
    price: price.toFixed(4),
    size: sizeUsdc.toFixed(2),
  });
  const ts = Date.now().toString();
  const res = await fetch(`${CONFIG.POLYMARKET_REST}/order`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'POLY-API-KEY':    CONFIG.PM_API_KEY ?? '',
      'POLY-TIMESTAMP':  ts,
      'POLY-SIGNATURE':  '',  // caller signs externally
    },
    body,
  });
  return res.json();
}

function getState() { return { ...state }; }

async function start() {
  await discoverMarkets();
  await snapshotBooks();
  if (state.up.tokenId || state.down.tokenId) subscribeWS();
  return { upTokenId: state.up.tokenId, downTokenId: state.down.tokenId };
}

function stop() { _ws?.close(); _ws = null; }

export { start, stop, on, off, emit, getState, discoverMarkets, snapshotBooks, parseBook, submitOrder };
