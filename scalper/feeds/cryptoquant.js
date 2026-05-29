import { CONFIG } from '../config.js';

const state = {
  inflow:   null,
  outflow:  null,
  netFlow:  null,
  stablecoinInflow: null,
  fundingRate: null,
  ts: null,
  available: false,
};

let _warned = false;
let _timer = null;

async function poll() {
  if (!CONFIG.CQ_API_KEY) {
    if (!_warned) {
      _warned = true;
      process.stderr.write('[cq] CQ_API_KEY not set — exchange flow signals disabled\n');
    }
    return;
  }

  try {
    const headers = { Authorization: `Bearer ${CONFIG.CQ_API_KEY}` };

    const [inflowRes, stableRes] = await Promise.all([
      fetch(`${CONFIG.CQ_BASE}/btc/exchange-flows/inflow?window=min&limit=3`, { headers }),
      fetch(`${CONFIG.CQ_BASE}/stablecoins/exchange-flows/inflow?window=min&limit=1`, { headers }),
    ]);

    if (inflowRes.ok) {
      const body = await inflowRes.json();
      const rows = body.data?.result ?? [];
      if (rows.length > 0) {
        const latest = rows[rows.length - 1];
        state.inflow  = latest.inflow_total ?? null;
        state.outflow = latest.outflow_total ?? null;
        state.netFlow = state.inflow != null && state.outflow != null
          ? state.outflow - state.inflow   // positive = net outflow = bullish
          : null;
        state.ts = Date.now();
        state.available = true;
      }
    }

    if (stableRes.ok) {
      const body = await stableRes.json();
      const rows = body.data?.result ?? [];
      state.stablecoinInflow = rows[0]?.inflow_total ?? null;
    }
  } catch { /* network errors are non-fatal */ }
}

function start() {
  poll();
  _timer = setInterval(poll, CONFIG.CQ_POLL_INTERVAL_MS);
}

function stop() {
  if (_timer) clearInterval(_timer);
  _timer = null;
}

function getState() { return { ...state }; }

export { start, stop, getState, poll };
