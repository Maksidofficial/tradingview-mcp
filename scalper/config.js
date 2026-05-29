export const CONFIG = {
  // Risk controls
  PER_TRADE_RISK_PCT: 0.005,   // 0.5% of capital per trade
  DAILY_CAP_PCT:      0.02,    // 2% max daily exposure
  HARD_STOP_PCT:      0.004,   // 0.4% hard stop per position
  CAPITAL_USDC: Number(process.env.CAPITAL_USDC ?? 1000),

  // Edge detection
  LAG_THRESHOLD_PCT:  0.003,   // 0.3% minimum Polymarket lag to enter
  MIN_LIQUIDITY_USDC: 1000,    // minimum CLOB depth on entry side
  SIGNAL_CONFLICT_MAX: 0.4,    // conflict score above this → skip
  MIN_CONFIDENCE:     0.5,     // minimum aggregated signal confidence

  // Timing
  EXEC_DEADLINE_MS:   100,     // warn if execution exceeds this
  DISPLAY_INTERVAL_MS: 200,
  FORCE_GRAPH_TICK_MS: 50,
  CQ_POLL_INTERVAL_MS: 60_000,

  // Feeds
  BINANCE_WS:     'wss://stream.binance.com:9443/stream',
  POLYMARKET_WS:  'wss://ws-subscriptions-clob.polymarket.com/ws/',
  POLYMARKET_REST: 'https://clob.polymarket.com',
  CQ_BASE:        'https://api.cryptoquant.com/v1',

  // Mode
  PAPER_TRADE: process.env.PAPER_TRADE !== 'false',

  // API keys (all optional)
  CQ_API_KEY:     process.env.CQ_API_KEY    ?? null,
  PM_API_KEY:     process.env.PM_API_KEY    ?? null,
  PM_API_SECRET:  process.env.PM_API_SECRET ?? null,
  PM_WALLET_KEY:  process.env.PM_WALLET_KEY ?? null,

  // Mirofish weight persistence
  WEIGHTS_FILE:   new URL('./weights.json', import.meta.url).pathname,
  WEIGHT_SAVE_INTERVAL: 100,    // trades between weight saves
  WEIGHT_MIN: 0.01,
  WEIGHT_MAX: 2.0,
  WEIGHT_REINFORCE: 0.05,       // winning trade: +5% on active edges
  WEIGHT_DAMPEN:    0.05,       // losing trade:  -5% on active edges
};
