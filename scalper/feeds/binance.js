import { WebSocket } from 'ws';
import { CONFIG } from '../config.js';

const STREAMS = 'btcusdt@aggTrade/btcusdt@kline_5m';
const RING_SIZE = 100;

// Ring buffer: last N items, oldest overwritten first
class RingBuffer {
  constructor(size) {
    this._buf = new Array(size).fill(null);
    this._pos = 0;
    this._size = size;
  }
  push(item) {
    this._buf[this._pos % this._size] = item;
    this._pos++;
  }
  toArray() {
    const out = [];
    for (let i = 0; i < this._size; i++) {
      const v = this._buf[(this._pos - this._size + i + this._size * 2) % this._size];
      if (v !== null) out.push(v);
    }
    return out;
  }
  last() { return this._buf[(this._pos - 1 + this._size) % this._size]; }
}

const state = {
  price:    null,
  qty:      null,
  time:     null,
  kline:    null,
  ticks:    new RingBuffer(RING_SIZE),
  klines:   new RingBuffer(20),
  connected: false,
};

let _ws = null;
let _callbacks = { onTick: null, onKline: null };

function priceAt(secondsAgo) {
  const cutoff = Date.now() - secondsAgo * 1000;
  const arr = state.ticks.toArray();
  for (let i = arr.length - 1; i >= 0; i--) {
    if (arr[i].time <= cutoff) return arr[i].price;
  }
  return arr[0]?.price ?? null;
}

function connect(onTick, onKline, attempt = 0) {
  _callbacks = { onTick, onKline };
  const url = `${CONFIG.BINANCE_WS}?streams=${STREAMS}`;
  const ws = new WebSocket(url);
  _ws = ws;

  ws.on('open', () => {
    state.connected = true;
  });

  ws.on('message', (raw) => {
    const msg = JSON.parse(raw);
    const { stream, data } = msg;

    if (stream === 'btcusdt@aggTrade') {
      const tick = {
        price: parseFloat(data.p),
        qty:   parseFloat(data.q),
        time:  data.T,
      };
      state.price = tick.price;
      state.qty   = tick.qty;
      state.time  = tick.time;
      state.ticks.push(tick);
      onTick?.(tick);
    }

    if (stream === 'btcusdt@kline_5m') {
      const k = data.k;
      const kline = {
        open:    parseFloat(k.o),
        high:    parseFloat(k.h),
        low:     parseFloat(k.l),
        close:   parseFloat(k.c),
        volume:  parseFloat(k.v),
        time:    k.t,
        isFinal: k.x,
      };
      state.kline = kline;
      if (kline.isFinal) state.klines.push(kline);
      onKline?.(kline);
    }
  });

  ws.on('error', () => {});

  ws.on('close', () => {
    state.connected = false;
    _ws = null;
    const delay = Math.min(1000 * 2 ** attempt, 30_000);
    if (attempt < 5) setTimeout(() => connect(onTick, onKline, attempt + 1), delay);
  });
}

function disconnect() {
  _ws?.close();
  _ws = null;
}

function getState() {
  return {
    price:       state.price,
    qty:         state.qty,
    time:        state.time,
    kline:       state.kline,
    connected:   state.connected,
    price_60s:   priceAt(60),
    price_30s:   priceAt(30),
    price_10s:   priceAt(10),
    price_5s:    priceAt(5),
    price_1s:    priceAt(1),
    recentTicks: state.ticks.toArray().slice(-20),
    recentKlines: state.klines.toArray(),
  };
}

export { connect, disconnect, getState, RingBuffer };
