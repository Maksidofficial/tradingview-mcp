// Thin bridge to src/core/data.js — skips silently if CDP unavailable.
let _warned = false;

async function _tryImport() {
  try {
    return await import('../../src/core/data.js');
  } catch {
    return null;
  }
}

let _core = null;
let _available = null;

async function _getCore() {
  if (_core) return _core;
  _core = await _tryImport();
  return _core;
}

async function getTVSignals() {
  const core = await _getCore();
  if (!core) {
    if (!_warned) { _warned = true; process.stderr.write('[tv] TradingView core unavailable — skipping TV signals\n'); }
    return null;
  }

  try {
    const [studyRaw, quoteRaw] = await Promise.all([
      core.getStudyValues().catch(() => null),
      core.getQuote().catch(() => null),
    ]);

    const signals = { rsi: null, macdHist: null, bbPct: null, ema9: null, ema21: null, available: true };

    if (studyRaw?.studies) {
      for (const study of studyRaw.studies) {
        const name = (study.name ?? '').toLowerCase();
        const vals = study.values ?? {};

        if (name.includes('rsi')) {
          signals.rsi = vals.RSI ?? vals['RSI[1]'] ?? Object.values(vals)[0] ?? null;
        }
        if (name.includes('macd')) {
          signals.macdHist = vals.Histogram ?? vals.MACD_Histogram ?? vals['Hist.'] ?? null;
        }
        if (name.includes('bollinger') || name.includes('bb')) {
          const upper = vals.Upper ?? vals['Upper Band'];
          const lower = vals.Lower ?? vals['Lower Band'];
          const mid   = vals.Basis ?? vals.Mid;
          const price = quoteRaw?.close ?? quoteRaw?.last;
          if (upper && lower && price) {
            signals.bbPct = (price - lower) / (upper - lower);
          }
        }
        if (name.includes('ema') || name.includes('moving average exp')) {
          const val = Object.values(vals)[0];
          if (!signals.ema9)  { signals.ema9  = val; continue; }
          if (!signals.ema21) { signals.ema21 = val; continue; }
        }
      }
    }

    if (quoteRaw) {
      signals.price  = quoteRaw.close ?? quoteRaw.last;
      signals.volume = quoteRaw.volume;
    }

    return signals;
  } catch {
    return null;
  }
}

async function isAvailable() {
  if (_available !== null) return _available;
  const core = await _getCore();
  if (!core) { _available = false; return false; }
  try {
    await core.getQuote();
    _available = true;
  } catch {
    _available = false;
  }
  return _available;
}

export { getTVSignals, isAvailable };
