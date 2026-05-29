import { readFileSync, writeFileSync, existsSync } from 'fs';
import { CONFIG } from '../config.js';

// ── Node definitions (100 nodes) ──────────────────────────────────────────────

const NODE_DEFS = [
  // Price momentum (20 nodes) — Δprice at multiple lookback windows
  { id: 'pm_1s',   cat: 'momentum', weight: 0.8, desc: 'price Δ 1s' },
  { id: 'pm_3s',   cat: 'momentum', weight: 0.8, desc: 'price Δ 3s' },
  { id: 'pm_5s',   cat: 'momentum', weight: 0.9, desc: 'price Δ 5s' },
  { id: 'pm_10s',  cat: 'momentum', weight: 1.0, desc: 'price Δ 10s' },
  { id: 'pm_15s',  cat: 'momentum', weight: 1.0, desc: 'price Δ 15s' },
  { id: 'pm_20s',  cat: 'momentum', weight: 0.9, desc: 'price Δ 20s' },
  { id: 'pm_30s',  cat: 'momentum', weight: 1.1, desc: 'price Δ 30s' },
  { id: 'pm_45s',  cat: 'momentum', weight: 1.0, desc: 'price Δ 45s' },
  { id: 'pm_60s',  cat: 'momentum', weight: 1.2, desc: 'price Δ 60s' },
  { id: 'pm_90s',  cat: 'momentum', weight: 1.1, desc: 'price Δ 90s' },
  { id: 'pm_2m',   cat: 'momentum', weight: 1.0, desc: 'price Δ 2m' },
  { id: 'pm_3m',   cat: 'momentum', weight: 0.9, desc: 'price Δ 3m' },
  { id: 'pm_5m',   cat: 'momentum', weight: 1.3, desc: 'price Δ 5m (kline)' },
  { id: 'pm_acc',  cat: 'momentum', weight: 1.0, desc: 'price acceleration' },
  { id: 'pm_tick_vel', cat: 'momentum', weight: 0.7, desc: 'tick velocity' },
  { id: 'pm_buy_ratio', cat: 'momentum', weight: 0.8, desc: 'buy-side aggressor ratio' },
  { id: 'pm_vol_surge', cat: 'momentum', weight: 0.9, desc: 'volume surge vs 5m avg' },
  { id: 'pm_high_break', cat: 'momentum', weight: 1.0, desc: 'kline high breakout' },
  { id: 'pm_low_break',  cat: 'momentum', weight: 1.0, desc: 'kline low breakdown' },
  { id: 'pm_close_pos',  cat: 'momentum', weight: 0.8, desc: 'close position in range' },

  // Volume profile (15 nodes)
  { id: 'vp_ask_d1', cat: 'volume', weight: 0.9, desc: 'PM ask depth tier 1' },
  { id: 'vp_ask_d2', cat: 'volume', weight: 0.8, desc: 'PM ask depth tier 2' },
  { id: 'vp_bid_d1', cat: 'volume', weight: 0.9, desc: 'PM bid depth tier 1' },
  { id: 'vp_bid_d2', cat: 'volume', weight: 0.8, desc: 'PM bid depth tier 2' },
  { id: 'vp_imbalance', cat: 'volume', weight: 1.1, desc: 'order book imbalance' },
  { id: 'vp_spread',    cat: 'volume', weight: 0.7, desc: 'bid-ask spread tightness' },
  { id: 'vp_bn_vol_1m', cat: 'volume', weight: 1.0, desc: 'Binance volume 1m' },
  { id: 'vp_bn_vol_5m', cat: 'volume', weight: 1.1, desc: 'Binance volume 5m' },
  { id: 'vp_trade_sz_sm', cat: 'volume', weight: 0.6, desc: 'small trade fraction' },
  { id: 'vp_trade_sz_lg', cat: 'volume', weight: 1.0, desc: 'large trade fraction' },
  { id: 'vp_vwap_dist',  cat: 'volume', weight: 0.9, desc: 'VWAP distance' },
  { id: 'vp_tick_buy_vol', cat: 'volume', weight: 0.9, desc: 'buy-side volume 10s' },
  { id: 'vp_tick_sell_vol', cat: 'volume', weight: 0.9, desc: 'sell-side volume 10s' },
  { id: 'vp_delta', cat: 'volume', weight: 1.0, desc: 'cumulative volume delta' },
  { id: 'vp_cvd_slope', cat: 'volume', weight: 1.0, desc: 'CVD slope 30s' },

  // Technical indicators (25 nodes)
  { id: 'ti_rsi',       cat: 'indicator', weight: 1.2, desc: 'RSI-14' },
  { id: 'ti_rsi_slope', cat: 'indicator', weight: 0.9, desc: 'RSI slope' },
  { id: 'ti_macd_hist', cat: 'indicator', weight: 1.1, desc: 'MACD histogram' },
  { id: 'ti_macd_cross', cat: 'indicator', weight: 1.0, desc: 'MACD zero-cross' },
  { id: 'ti_bb_pct',    cat: 'indicator', weight: 1.0, desc: 'BBands %B' },
  { id: 'ti_bb_squeeze', cat: 'indicator', weight: 0.8, desc: 'BB squeeze' },
  { id: 'ti_ema9',      cat: 'indicator', weight: 0.9, desc: 'EMA-9 vs price' },
  { id: 'ti_ema21',     cat: 'indicator', weight: 1.0, desc: 'EMA-21 vs price' },
  { id: 'ti_ema55',     cat: 'indicator', weight: 0.8, desc: 'EMA-55 vs price' },
  { id: 'ti_ema_cross9_21', cat: 'indicator', weight: 1.1, desc: 'EMA9/21 cross' },
  { id: 'ti_adx',       cat: 'indicator', weight: 0.8, desc: 'ADX-14 trend strength' },
  { id: 'ti_cci',       cat: 'indicator', weight: 0.9, desc: 'CCI-20' },
  { id: 'ti_stoch_k',   cat: 'indicator', weight: 0.9, desc: 'Stoch %K' },
  { id: 'ti_stoch_d',   cat: 'indicator', weight: 0.8, desc: 'Stoch %D' },
  { id: 'ti_mfi',       cat: 'indicator', weight: 1.0, desc: 'MFI-14' },
  { id: 'ti_obv_slope', cat: 'indicator', weight: 0.9, desc: 'OBV slope' },
  { id: 'ti_kline_body', cat: 'indicator', weight: 0.8, desc: 'kline body direction' },
  { id: 'ti_kline_wick', cat: 'indicator', weight: 0.7, desc: 'wick rejection' },
  { id: 'ti_kline_vol_trend', cat: 'indicator', weight: 0.9, desc: 'kline volume trend' },
  { id: 'ti_atr_norm',  cat: 'indicator', weight: 0.6, desc: 'ATR normalised' },
  { id: 'ti_roc_1',     cat: 'indicator', weight: 0.9, desc: 'rate-of-change 1-bar' },
  { id: 'ti_roc_3',     cat: 'indicator', weight: 0.9, desc: 'rate-of-change 3-bar' },
  { id: 'ti_willr',     cat: 'indicator', weight: 0.8, desc: "Williams %R" },
  { id: 'ti_ema9_slope', cat: 'indicator', weight: 0.9, desc: 'EMA-9 slope' },
  { id: 'ti_tv_signal', cat: 'indicator', weight: 1.2, desc: 'TradingView composite' },

  // Exchange flows (15 nodes)
  { id: 'ef_inflow_1m',   cat: 'flow', weight: 1.0, desc: 'CQ exchange inflow 1m' },
  { id: 'ef_outflow_1m',  cat: 'flow', weight: 1.0, desc: 'CQ exchange outflow 1m' },
  { id: 'ef_netflow',     cat: 'flow', weight: 1.2, desc: 'CQ net flow' },
  { id: 'ef_stable_in',   cat: 'flow', weight: 0.9, desc: 'stablecoin inflow' },
  { id: 'ef_funding',     cat: 'flow', weight: 0.8, desc: 'funding rate' },
  { id: 'ef_oi_change',   cat: 'flow', weight: 0.9, desc: 'OI change' },
  { id: 'ef_inflow_5m',   cat: 'flow', weight: 1.0, desc: 'CQ exchange inflow 5m' },
  { id: 'ef_outflow_5m',  cat: 'flow', weight: 1.0, desc: 'CQ exchange outflow 5m' },
  { id: 'ef_netflow_5m',  cat: 'flow', weight: 1.1, desc: 'CQ net flow 5m' },
  { id: 'ef_whale_alert', cat: 'flow', weight: 1.0, desc: 'large transfer signal' },
  { id: 'ef_miner_flow',  cat: 'flow', weight: 0.7, desc: 'miner outflow' },
  { id: 'ef_hot_wallet',  cat: 'flow', weight: 0.8, desc: 'hot wallet balance' },
  { id: 'ef_nupl',        cat: 'flow', weight: 0.7, desc: 'NUPL signal' },
  { id: 'ef_sopr',        cat: 'flow', weight: 0.7, desc: 'SOPR signal' },
  { id: 'ef_reserved_1',  cat: 'flow', weight: 0.5, desc: 'reserved flow node' },

  // Market microstructure (15 nodes)
  { id: 'ms_spread',       cat: 'micro', weight: 0.8, desc: 'Binance spread' },
  { id: 'ms_trade_rate',   cat: 'micro', weight: 0.9, desc: 'trades per second' },
  { id: 'ms_buy_ratio',    cat: 'micro', weight: 1.1, desc: 'buy order ratio' },
  { id: 'ms_size_sm',      cat: 'micro', weight: 0.6, desc: 'small trade fraction' },
  { id: 'ms_size_md',      cat: 'micro', weight: 0.8, desc: 'medium trade fraction' },
  { id: 'ms_size_lg',      cat: 'micro', weight: 1.0, desc: 'large trade fraction' },
  { id: 'ms_aggressor',    cat: 'micro', weight: 1.0, desc: 'aggressive order ratio' },
  { id: 'ms_imbalance',    cat: 'micro', weight: 1.1, desc: 'order flow imbalance' },
  { id: 'ms_tick_dir',     cat: 'micro', weight: 0.9, desc: 'tick direction streak' },
  { id: 'ms_reversal',     cat: 'micro', weight: 0.8, desc: 'reversal signal' },
  { id: 'ms_latency',      cat: 'micro', weight: 0.5, desc: 'feed latency health' },
  { id: 'ms_print_speed',  cat: 'micro', weight: 0.7, desc: 'print speed vs avg' },
  { id: 'ms_depth_pull',   cat: 'micro', weight: 0.9, desc: 'depth pull (spoofing)' },
  { id: 'ms_sweep',        cat: 'micro', weight: 1.0, desc: 'book sweep signal' },
  { id: 'ms_iceberg',      cat: 'micro', weight: 0.7, desc: 'iceberg order signal' },

  // Sentiment / Polymarket probability (10 nodes)
  { id: 'sp_up_prob',      cat: 'sentiment', weight: 1.3, desc: 'PM UP mid-price' },
  { id: 'sp_down_prob',    cat: 'sentiment', weight: 1.3, desc: 'PM DOWN mid-price' },
  { id: 'sp_up_liq',       cat: 'sentiment', weight: 0.9, desc: 'PM UP ask liquidity' },
  { id: 'sp_down_liq',     cat: 'sentiment', weight: 0.9, desc: 'PM DOWN ask liquidity' },
  { id: 'sp_imbalance',    cat: 'sentiment', weight: 1.1, desc: 'PM UP/DOWN imbalance' },
  { id: 'sp_lag',          cat: 'sentiment', weight: 1.5, desc: 'detected PM lag' },
  { id: 'sp_funding',      cat: 'sentiment', weight: 0.8, desc: 'perp funding (sentiment)' },
  { id: 'sp_fear_greed',   cat: 'sentiment', weight: 0.6, desc: 'fear & greed proxy' },
  { id: 'sp_spread_ratio', cat: 'sentiment', weight: 0.8, desc: 'PM spread ratio' },
  { id: 'sp_momentum_prob', cat: 'sentiment', weight: 1.2, desc: 'momentum-implied prob' },
];

if (NODE_DEFS.length !== 100) throw new Error(`Expected 100 nodes, got ${NODE_DEFS.length}`);

// ── Edge definitions (180 edges) ──────────────────────────────────────────────
// type: 'C' = correlated (attraction), 'I' = inverse (repulsion), 'A' = causal

const EDGE_DEFS = [
  // Momentum ↔ momentum correlations (9 edges)
  { u: 'pm_1s',   v: 'pm_5s',   type: 'C', w: 1.0 },
  { u: 'pm_5s',   v: 'pm_30s',  type: 'C', w: 1.0 },
  { u: 'pm_30s',  v: 'pm_60s',  type: 'C', w: 1.0 },
  { u: 'pm_60s',  v: 'pm_5m',   type: 'C', w: 1.0 },
  { u: 'pm_acc',  v: 'pm_1s',   type: 'C', w: 0.8 },
  { u: 'pm_tick_vel', v: 'pm_1s', type: 'C', w: 0.7 },
  { u: 'pm_buy_ratio', v: 'pm_5s', type: 'C', w: 0.8 },
  { u: 'pm_vol_surge', v: 'pm_30s', type: 'C', w: 0.9 },
  { u: 'pm_close_pos', v: 'pm_5m', type: 'C', w: 0.8 },

  // Momentum ↔ microstructure (10 edges)
  { u: 'ms_buy_ratio',  v: 'pm_5s',  type: 'C', w: 1.0 },
  { u: 'ms_imbalance',  v: 'pm_10s', type: 'C', w: 1.1 },
  { u: 'ms_aggressor',  v: 'pm_1s',  type: 'C', w: 0.9 },
  { u: 'ms_sweep',      v: 'pm_5s',  type: 'C', w: 1.2 },
  { u: 'ms_tick_dir',   v: 'pm_3s',  type: 'C', w: 0.9 },
  { u: 'ms_trade_rate', v: 'pm_tick_vel', type: 'C', w: 0.8 },
  { u: 'ms_size_lg',    v: 'pm_vol_surge', type: 'C', w: 0.9 },
  { u: 'ms_depth_pull', v: 'pm_5s',  type: 'I', w: 0.7 },
  { u: 'ms_reversal',   v: 'pm_5s',  type: 'I', w: 0.8 },
  { u: 'ms_spread',     v: 'pm_1s',  type: 'I', w: 0.5 },

  // Technical indicators ↔ momentum (15 edges)
  { u: 'ti_rsi',       v: 'pm_60s', type: 'C', w: 1.0 },
  { u: 'ti_rsi_slope', v: 'pm_10s', type: 'C', w: 0.9 },
  { u: 'ti_macd_hist', v: 'pm_5m',  type: 'C', w: 1.1 },
  { u: 'ti_macd_cross', v: 'pm_5m', type: 'C', w: 1.2 },
  { u: 'ti_bb_pct',    v: 'pm_30s', type: 'C', w: 0.9 },
  { u: 'ti_ema9',      v: 'pm_5s',  type: 'C', w: 0.8 },
  { u: 'ti_ema21',     v: 'pm_60s', type: 'C', w: 1.0 },
  { u: 'ti_ema_cross9_21', v: 'pm_5m', type: 'C', w: 1.1 },
  { u: 'ti_obv_slope', v: 'pm_30s', type: 'C', w: 0.9 },
  { u: 'ti_mfi',       v: 'pm_30s', type: 'C', w: 0.9 },
  { u: 'ti_kline_body', v: 'pm_5m', type: 'C', w: 1.0 },
  { u: 'ti_cci',       v: 'pm_15s', type: 'C', w: 0.8 },
  { u: 'ti_stoch_k',   v: 'pm_30s', type: 'C', w: 0.8 },
  { u: 'ti_roc_1',     v: 'pm_60s', type: 'C', w: 0.9 },
  { u: 'ti_roc_3',     v: 'pm_5m',  type: 'C', w: 0.9 },

  // RSI inverse at extremes (3 edges — overbought/oversold repulsion)
  { u: 'ti_rsi',   v: 'pm_buy_ratio', type: 'I', w: 0.8 },
  { u: 'ti_willr', v: 'pm_buy_ratio', type: 'I', w: 0.7 },
  { u: 'ti_bb_pct', v: 'ms_reversal', type: 'C', w: 0.6 },

  // Volume profile ↔ momentum (10 edges)
  { u: 'vp_imbalance',   v: 'pm_5s',   type: 'C', w: 1.1 },
  { u: 'vp_delta',       v: 'pm_30s',  type: 'C', w: 1.0 },
  { u: 'vp_cvd_slope',   v: 'pm_60s',  type: 'C', w: 1.0 },
  { u: 'vp_bn_vol_5m',   v: 'pm_vol_surge', type: 'C', w: 0.9 },
  { u: 'vp_tick_buy_vol', v: 'pm_buy_ratio', type: 'C', w: 0.9 },
  { u: 'vp_tick_sell_vol', v: 'pm_buy_ratio', type: 'I', w: 0.9 },
  { u: 'vp_ask_d1',      v: 'pm_high_break', type: 'I', w: 0.8 },
  { u: 'vp_bid_d1',      v: 'pm_low_break',  type: 'I', w: 0.8 },
  { u: 'vp_trade_sz_lg', v: 'ms_size_lg',    type: 'C', w: 0.8 },
  { u: 'vp_vwap_dist',   v: 'pm_60s',        type: 'C', w: 0.7 },

  // Volume profile ↔ volume profile (6 edges)
  { u: 'vp_ask_d1',  v: 'vp_ask_d2',  type: 'C', w: 0.7 },
  { u: 'vp_bid_d1',  v: 'vp_bid_d2',  type: 'C', w: 0.7 },
  { u: 'vp_delta',   v: 'vp_cvd_slope', type: 'C', w: 0.9 },
  { u: 'vp_imbalance', v: 'vp_delta',  type: 'C', w: 0.8 },
  { u: 'vp_bn_vol_1m', v: 'vp_bn_vol_5m', type: 'C', w: 0.8 },
  { u: 'vp_spread',  v: 'ms_spread',   type: 'C', w: 0.7 },

  // Exchange flows → momentum (causal, lagged) (10 edges)
  { u: 'ef_inflow_1m',  v: 'pm_60s',   type: 'A', w: 0.9 },
  { u: 'ef_outflow_1m', v: 'pm_60s',   type: 'A', w: 0.9 },
  { u: 'ef_netflow',    v: 'pm_5m',    type: 'A', w: 1.2 },
  { u: 'ef_stable_in',  v: 'pm_5m',   type: 'A', w: 0.9 },
  { u: 'ef_funding',    v: 'pm_60s',   type: 'A', w: 0.7 },
  { u: 'ef_oi_change',  v: 'pm_5m',   type: 'A', w: 0.9 },
  { u: 'ef_netflow_5m', v: 'pm_5m',   type: 'A', w: 1.1 },
  { u: 'ef_whale_alert', v: 'pm_5s',  type: 'A', w: 1.0 },
  { u: 'ef_inflow_1m',  v: 'ms_imbalance', type: 'A', w: 0.7 },
  { u: 'ef_netflow',    v: 'ti_macd_hist',  type: 'A', w: 0.6 },

  // Exchange flows inverse to bullish nodes when inflow high (5 edges)
  { u: 'ef_inflow_1m',  v: 'pm_buy_ratio', type: 'I', w: 0.8 },
  { u: 'ef_inflow_5m',  v: 'ti_rsi',       type: 'I', w: 0.7 },
  { u: 'ef_inflow_1m',  v: 'vp_imbalance', type: 'I', w: 0.7 },
  { u: 'ef_inflow_5m',  v: 'pm_5m',        type: 'I', w: 0.8 },
  { u: 'ef_miner_flow', v: 'pm_60s',        type: 'I', w: 0.6 },

  // Sentiment ↔ momentum (15 edges)
  { u: 'sp_up_prob',    v: 'pm_60s',   type: 'C', w: 1.3 },
  { u: 'sp_down_prob',  v: 'pm_60s',   type: 'I', w: 1.3 },
  { u: 'sp_imbalance',  v: 'pm_30s',   type: 'C', w: 1.1 },
  { u: 'sp_lag',        v: 'pm_5s',    type: 'C', w: 1.5 },
  { u: 'sp_momentum_prob', v: 'sp_up_prob', type: 'C', w: 1.2 },
  { u: 'sp_momentum_prob', v: 'pm_30s',    type: 'C', w: 1.0 },
  { u: 'sp_funding',    v: 'pm_60s',   type: 'C', w: 0.7 },
  { u: 'sp_up_liq',     v: 'vp_ask_d1', type: 'C', w: 0.8 },
  { u: 'sp_down_liq',   v: 'vp_bid_d1', type: 'C', w: 0.8 },
  { u: 'sp_spread_ratio', v: 'vp_spread', type: 'C', w: 0.7 },
  { u: 'sp_up_prob',    v: 'ti_tv_signal', type: 'C', w: 1.0 },
  { u: 'sp_down_prob',  v: 'ti_tv_signal', type: 'I', w: 1.0 },
  { u: 'sp_imbalance',  v: 'ms_imbalance', type: 'C', w: 0.9 },
  { u: 'sp_lag',        v: 'sp_up_prob', type: 'C', w: 1.2 },
  { u: 'sp_lag',        v: 'ms_sweep',   type: 'C', w: 1.0 },

  // Microstructure inter-edges (8 edges)
  { u: 'ms_buy_ratio',  v: 'ms_aggressor',  type: 'C', w: 0.9 },
  { u: 'ms_imbalance',  v: 'ms_buy_ratio',  type: 'C', w: 0.9 },
  { u: 'ms_sweep',      v: 'ms_aggressor',  type: 'C', w: 0.8 },
  { u: 'ms_tick_dir',   v: 'ms_buy_ratio',  type: 'C', w: 0.8 },
  { u: 'ms_iceberg',    v: 'ms_depth_pull', type: 'C', w: 0.7 },
  { u: 'ms_print_speed', v: 'ms_trade_rate', type: 'C', w: 0.8 },
  { u: 'ms_size_lg',    v: 'ms_aggressor',  type: 'C', w: 0.8 },
  { u: 'ms_reversal',   v: 'ms_tick_dir',   type: 'I', w: 0.7 },

  // Indicator inter-edges (15 edges)
  { u: 'ti_rsi',       v: 'ti_mfi',       type: 'C', w: 0.8 },
  { u: 'ti_macd_hist', v: 'ti_macd_cross', type: 'C', w: 0.9 },
  { u: 'ti_ema9',      v: 'ti_ema21',     type: 'C', w: 0.8 },
  { u: 'ti_ema21',     v: 'ti_ema55',     type: 'C', w: 0.8 },
  { u: 'ti_ema_cross9_21', v: 'ti_macd_cross', type: 'C', w: 0.9 },
  { u: 'ti_bb_pct',    v: 'ti_bb_squeeze', type: 'I', w: 0.7 },
  { u: 'ti_stoch_k',   v: 'ti_stoch_d',   type: 'C', w: 0.8 },
  { u: 'ti_stoch_k',   v: 'ti_rsi',       type: 'C', w: 0.7 },
  { u: 'ti_cci',       v: 'ti_rsi',       type: 'C', w: 0.7 },
  { u: 'ti_willr',     v: 'ti_stoch_k',   type: 'C', w: 0.8 },
  { u: 'ti_obv_slope', v: 'ti_mfi',       type: 'C', w: 0.8 },
  { u: 'ti_kline_body', v: 'ti_kline_vol_trend', type: 'C', w: 0.8 },
  { u: 'ti_roc_1',     v: 'ti_roc_3',    type: 'C', w: 0.9 },
  { u: 'ti_ema9_slope', v: 'ti_ema9',    type: 'C', w: 0.9 },
  { u: 'ti_tv_signal', v: 'ti_rsi',      type: 'C', w: 1.0 },

  // Flow inter-edges (6 edges)
  { u: 'ef_inflow_1m',  v: 'ef_inflow_5m',  type: 'C', w: 0.8 },
  { u: 'ef_outflow_1m', v: 'ef_outflow_5m', type: 'C', w: 0.8 },
  { u: 'ef_netflow',    v: 'ef_netflow_5m', type: 'C', w: 0.9 },
  { u: 'ef_funding',    v: 'ef_oi_change',  type: 'C', w: 0.7 },
  { u: 'ef_stable_in',  v: 'ef_inflow_1m',  type: 'I', w: 0.6 },
  { u: 'ef_nupl',       v: 'ef_sopr',       type: 'C', w: 0.7 },

  // Sentiment ↔ flow (8 edges)
  { u: 'ef_funding',   v: 'sp_funding',    type: 'C', w: 0.9 },
  { u: 'ef_netflow',   v: 'sp_imbalance',  type: 'C', w: 0.8 },
  { u: 'ef_stable_in', v: 'sp_up_prob',    type: 'C', w: 0.7 },
  { u: 'ef_inflow_1m', v: 'sp_down_prob',  type: 'C', w: 0.7 },
  { u: 'sp_fear_greed', v: 'ef_funding',   type: 'C', w: 0.6 },
  { u: 'ef_oi_change', v: 'sp_funding',    type: 'C', w: 0.7 },
  { u: 'ef_whale_alert', v: 'sp_imbalance', type: 'C', w: 0.8 },
  { u: 'ef_miner_flow', v: 'sp_fear_greed', type: 'I', w: 0.6 },

  // Breakout / level nodes (8 edges)
  { u: 'pm_high_break', v: 'ms_sweep',      type: 'C', w: 1.0 },
  { u: 'pm_low_break',  v: 'ms_sweep',      type: 'C', w: 1.0 },
  { u: 'pm_high_break', v: 'vp_ask_d1',     type: 'I', w: 0.8 },
  { u: 'pm_low_break',  v: 'vp_bid_d1',     type: 'I', w: 0.8 },
  { u: 'pm_high_break', v: 'ti_bb_pct',     type: 'C', w: 0.8 },
  { u: 'pm_low_break',  v: 'ti_bb_pct',     type: 'I', w: 0.8 },
  { u: 'pm_close_pos',  v: 'ti_kline_body', type: 'C', w: 0.8 },
  { u: 'pm_vol_surge',  v: 'ms_print_speed', type: 'C', w: 0.7 },

  // Cross-category long-range (25 edges)
  { u: 'ti_rsi',       v: 'sp_up_prob',     type: 'C', w: 0.8 },
  { u: 'ti_macd_hist', v: 'sp_momentum_prob', type: 'C', w: 0.9 },
  { u: 'vp_delta',     v: 'sp_imbalance',   type: 'C', w: 0.9 },
  { u: 'ms_imbalance', v: 'sp_imbalance',   type: 'C', w: 0.9 },
  { u: 'vp_cvd_slope', v: 'ti_obv_slope',   type: 'C', w: 0.8 },
  { u: 'ti_adx',       v: 'pm_acc',         type: 'C', w: 0.7 },
  { u: 'ms_sweep',     v: 'vp_delta',       type: 'C', w: 0.9 },
  { u: 'ef_netflow',   v: 'ti_tv_signal',   type: 'A', w: 0.7 },
  { u: 'sp_lag',       v: 'vp_imbalance',   type: 'C', w: 1.0 },
  { u: 'sp_lag',       v: 'ti_macd_hist',   type: 'C', w: 0.8 },
  { u: 'pm_buy_ratio', v: 'vp_tick_buy_vol', type: 'C', w: 0.8 },
  { u: 'ti_bb_squeeze', v: 'pm_acc',        type: 'A', w: 0.7 },
  { u: 'ms_size_lg',   v: 'ef_whale_alert', type: 'C', w: 0.8 },
  { u: 'vp_spread',    v: 'sp_spread_ratio', type: 'C', w: 0.8 },
  { u: 'ti_atr_norm',  v: 'pm_acc',         type: 'C', w: 0.7 },
  { u: 'ef_oi_change', v: 'ms_aggressor',   type: 'C', w: 0.7 },
  { u: 'ti_kline_wick', v: 'ms_reversal',   type: 'C', w: 0.8 },
  { u: 'vp_vwap_dist', v: 'ti_rsi',         type: 'C', w: 0.7 },
  { u: 'ms_iceberg',   v: 'vp_ask_d2',      type: 'C', w: 0.7 },
  { u: 'sp_fear_greed', v: 'ti_rsi',        type: 'C', w: 0.6 },
  { u: 'ef_sopr',      v: 'pm_5m',          type: 'A', w: 0.6 },
  { u: 'ti_ema55',     v: 'pm_5m',          type: 'C', w: 0.7 },
  { u: 'pm_2m',        v: 'pm_3m',          type: 'C', w: 0.9 },
  { u: 'pm_3m',        v: 'pm_5m',          type: 'C', w: 0.9 },
  { u: 'pm_90s',       v: 'pm_2m',          type: 'C', w: 0.9 },

  // Final padding to reach exactly 180 (27 edges)
  { u: 'pm_10s',  v: 'pm_15s',   type: 'C', w: 0.9 },
  { u: 'pm_15s',  v: 'pm_20s',   type: 'C', w: 0.9 },
  { u: 'pm_20s',  v: 'pm_30s',   type: 'C', w: 0.9 },
  { u: 'pm_45s',  v: 'pm_60s',   type: 'C', w: 0.9 },
  { u: 'ms_size_sm', v: 'ms_size_md', type: 'C', w: 0.7 },
  { u: 'ms_size_md', v: 'ms_size_lg', type: 'C', w: 0.7 },
  { u: 'vp_bn_vol_1m', v: 'vp_tick_buy_vol', type: 'C', w: 0.8 },
  { u: 'vp_bn_vol_1m', v: 'vp_tick_sell_vol', type: 'C', w: 0.8 },
  { u: 'ti_stoch_d', v: 'ti_rsi',   type: 'C', w: 0.7 },
  { u: 'ef_hot_wallet', v: 'ef_outflow_1m', type: 'I', w: 0.6 },
  { u: 'sp_up_prob', v: 'sp_down_prob', type: 'I', w: 1.4 },
  { u: 'ef_inflow_5m', v: 'ef_inflow_1m', type: 'C', w: 0.7 },
  { u: 'ef_outflow_5m', v: 'ef_outflow_1m', type: 'C', w: 0.7 },
  { u: 'pm_3s',   v: 'pm_5s',    type: 'C', w: 0.9 },
  { u: 'pm_1s',   v: 'pm_3s',    type: 'C', w: 0.9 },
  { u: 'ti_adx',  v: 'ti_macd_hist', type: 'C', w: 0.7 },
  { u: 'vp_delta', v: 'vp_tick_buy_vol', type: 'C', w: 0.8 },
  { u: 'ef_nupl',  v: 'pm_5m',    type: 'A', w: 0.5 },
  { u: 'ms_latency', v: 'ms_spread', type: 'I', w: 0.5 },
  { u: 'sp_fear_greed', v: 'sp_imbalance', type: 'C', w: 0.6 },
  { u: 'ti_willr', v: 'ti_cci',   type: 'C', w: 0.7 },
  { u: 'ef_reserved_1', v: 'ef_netflow', type: 'C', w: 0.4 },
  { u: 'ti_kline_wick', v: 'pm_high_break', type: 'C', w: 0.7 },
  { u: 'vp_cvd_slope', v: 'ms_buy_ratio',  type: 'C', w: 0.7 },
  { u: 'ms_print_speed', v: 'pm_tick_vel', type: 'C', w: 0.7 },
  { u: 'ti_kline_vol_trend', v: 'vp_bn_vol_5m', type: 'C', w: 0.7 },
  { u: 'ef_miner_flow', v: 'ef_netflow',   type: 'A', w: 0.5 },
];

if (EDGE_DEFS.length !== 180) throw new Error(`Expected 180 edges, got ${EDGE_DEFS.length}`);

// ── Physics engine ─────────────────────────────────────────────────────────────

const DAMPING  = 0.82;
const RESTORE  = 0.10;   // self-restoring force: pull position toward external value
const GAIN_C   = 0.06;   // correlated inter-node force gain (position-based)
const GAIN_I   = 0.06;   // inverse inter-node force gain
const GAIN_A   = 0.03;   // causal inter-node force gain
const POS_MAX  = 2.0;

export class MirofishGraph {
  constructor(weightOverrides = {}) {
    // Build node map
    this.nodes = new Map();
    for (const def of NODE_DEFS) {
      this.nodes.set(def.id, {
        ...def,
        value:    0,
        position: 0,
        velocity: 0,
      });
    }

    // Build edge list with mutable weights (loaded from file if available)
    this.edges = EDGE_DEFS.map((e, i) => ({
      ...e,
      w: weightOverrides[`${e.u}:${e.v}`] ?? e.w,
      idx: i,
      lastForce: 0,
    }));

    this._tradeCount = 0;
    this._activeEdgeForces = new Map();
  }

  // Update node input values from current market signals
  setSignals(signals) {
    const { binance, tradingview: tv, cryptoquant: cq, polymarket: pm } = signals;
    const now = Date.now();

    const b = binance ?? {};
    const price = b.price ?? 0;

    // Helper: pct change clipped to [-1,1]
    const pct = (cur, ref) => ref && cur ? Math.max(-1, Math.min(1, (cur - ref) / ref / 0.005)) : 0;

    // Price momentum nodes
    this._setNode('pm_1s',  pct(price, b.price_1s));
    this._setNode('pm_3s',  pct(price, b.price_5s) * 0.7);
    this._setNode('pm_5s',  pct(price, b.price_5s));
    this._setNode('pm_10s', pct(price, b.price_10s));
    this._setNode('pm_15s', pct(price, b.price_10s) * 0.9);
    this._setNode('pm_20s', pct(price, b.price_30s) * 0.7);
    this._setNode('pm_30s', pct(price, b.price_30s));
    this._setNode('pm_45s', pct(price, b.price_60s) * 0.8);
    this._setNode('pm_60s', pct(price, b.price_60s));
    this._setNode('pm_90s', pct(price, b.price_60s) * 0.9);
    this._setNode('pm_2m',  pct(price, b.price_60s) * 0.85);
    this._setNode('pm_3m',  pct(price, b.price_60s) * 0.8);

    // 5m kline momentum
    const kline = b.kline;
    const klineDir = kline ? Math.sign(kline.close - kline.open) * Math.min(1, Math.abs(kline.close - kline.open) / kline.open / 0.003) : 0;
    this._setNode('pm_5m', klineDir);

    // Acceleration: rate of change of 5s momentum
    const acc5 = pct(price, b.price_5s);
    const acc10 = pct(price, b.price_10s);
    this._setNode('pm_acc', acc5 - acc10);

    // Tick velocity
    const ticks = b.recentTicks ?? [];
    this._setNode('pm_tick_vel', Math.min(1, ticks.length / 20));

    // Buy ratio from recent ticks
    const buys = ticks.filter(t => t.isBuyer !== false).length;
    this._setNode('pm_buy_ratio', (buys / Math.max(1, ticks.length)) * 2 - 1);

    // Volume surge
    const klines5 = (b.recentKlines ?? []).slice(-5);
    const avgVol = klines5.length ? klines5.reduce((s, k) => s + k.volume, 0) / klines5.length : 0;
    const curVol = kline?.volume ?? 0;
    this._setNode('pm_vol_surge', avgVol > 0 ? Math.min(1, (curVol / avgVol - 1)) : 0);

    this._setNode('pm_high_break', kline && price > kline.high ? 1 : 0);
    this._setNode('pm_low_break',  kline && price < kline.low  ? -1 : 0);
    this._setNode('pm_close_pos',  kline ? (price - kline.low) / Math.max(kline.high - kline.low, 1) * 2 - 1 : 0);

    // Volume profile from Polymarket CLOB book
    const pmUp   = pm?.up   ?? {};
    const pmDown = pm?.down ?? {};
    const askD1 = pmUp.askDepth ?? 0;
    const bidD1 = pmUp.bidDepth ?? 0;
    this._setNode('vp_ask_d1', Math.min(1, askD1 / 5000));
    this._setNode('vp_bid_d1', Math.min(1, bidD1 / 5000));
    this._setNode('vp_ask_d2', Math.min(1, (pmDown.askDepth ?? 0) / 5000));
    this._setNode('vp_bid_d2', Math.min(1, (pmDown.bidDepth ?? 0) / 5000));
    const imbalance = askD1 + bidD1 > 0 ? (bidD1 - askD1) / (bidD1 + askD1) : 0;
    this._setNode('vp_imbalance', imbalance);
    this._setNode('vp_spread', pmUp.bestAsk != null && pmUp.bestBid != null ? 1 - (pmUp.bestAsk - pmUp.bestBid) * 20 : 0);

    // Binance volume
    this._setNode('vp_bn_vol_1m', Math.min(1, (kline?.volume ?? 0) / 5000));
    this._setNode('vp_bn_vol_5m', Math.min(1, avgVol / 5000));

    // Trade size distribution
    const small = ticks.filter(t => t.qty < 0.01).length / Math.max(1, ticks.length);
    const large = ticks.filter(t => t.qty > 1).length / Math.max(1, ticks.length);
    this._setNode('vp_trade_sz_sm', small * 2 - 1);
    this._setNode('vp_trade_sz_lg', large * 2 - 1);
    this._setNode('vp_vwap_dist', 0);   // would need VWAP calculation

    // Volume delta
    const buyVol  = ticks.filter(t => t.isBuyer !== false).reduce((s, t) => s + t.qty, 0);
    const sellVol = ticks.filter(t => t.isBuyer === false).reduce((s, t) => s + t.qty, 0);
    const totalVol = buyVol + sellVol;
    this._setNode('vp_tick_buy_vol',  totalVol > 0 ? buyVol / totalVol * 2 - 1 : 0);
    this._setNode('vp_tick_sell_vol', totalVol > 0 ? sellVol / totalVol * 2 - 1 : 0);
    this._setNode('vp_delta', totalVol > 0 ? (buyVol - sellVol) / totalVol : 0);
    this._setNode('vp_cvd_slope', 0);  // requires historical delta

    // Technical indicators from TradingView
    if (tv) {
      const rsi = tv.rsi ?? null;
      this._setNode('ti_rsi', rsi != null ? (rsi - 50) / 50 : 0);
      this._setNode('ti_rsi_slope', 0);  // would need prev RSI

      const macd = tv.macdHist ?? null;
      this._setNode('ti_macd_hist', macd != null ? Math.max(-1, Math.min(1, macd / 100)) : 0);
      this._setNode('ti_macd_cross', macd != null ? Math.sign(macd) : 0);

      const bbPct = tv.bbPct ?? null;
      this._setNode('ti_bb_pct', bbPct != null ? bbPct * 2 - 1 : 0);
      this._setNode('ti_bb_squeeze', bbPct != null && Math.abs(bbPct - 0.5) < 0.1 ? -0.5 : 0);

      this._setNode('ti_ema9',  tv.ema9  ? (price - tv.ema9)  / tv.ema9  / 0.001 : 0);
      this._setNode('ti_ema21', tv.ema21 ? (price - tv.ema21) / tv.ema21 / 0.001 : 0);
      this._setNode('ti_ema55', tv.ema55 ? (price - tv.ema55) / tv.ema55 / 0.001 : 0);

      const emaCross = tv.ema9 && tv.ema21 ? Math.sign(tv.ema9 - tv.ema21) : 0;
      this._setNode('ti_ema_cross9_21', emaCross);
      this._setNode('ti_ema9_slope', 0);
      this._setNode('ti_tv_signal', tv.available ? (rsi != null ? (rsi - 50) / 50 * 0.5 + (macd ?? 0) / 200 : 0) : 0);
    }

    // Microstructure
    this._setNode('ms_spread', 0);
    this._setNode('ms_trade_rate', Math.min(1, ticks.length / 20));
    this._setNode('ms_buy_ratio',  (buys / Math.max(1, ticks.length)) * 2 - 1);
    this._setNode('ms_size_sm', small);
    this._setNode('ms_size_md', 1 - small - large);
    this._setNode('ms_size_lg', large);
    this._setNode('ms_aggressor', (buys / Math.max(1, ticks.length)) * 2 - 1);
    this._setNode('ms_imbalance', imbalance);
    this._setNode('ms_tick_dir', acc5 > 0.3 ? 1 : acc5 < -0.3 ? -1 : 0);
    this._setNode('ms_reversal', 0);
    this._setNode('ms_latency', 1);
    this._setNode('ms_print_speed', Math.min(1, ticks.length / 10));
    this._setNode('ms_depth_pull', 0);
    this._setNode('ms_sweep', Math.abs(acc5) > 0.8 && large > 0.1 ? Math.sign(acc5) : 0);
    this._setNode('ms_iceberg', 0);

    // Exchange flows
    if (cq) {
      const netNorm = cq.netFlow != null ? Math.max(-1, Math.min(1, cq.netFlow / 1000)) : 0;
      this._setNode('ef_inflow_1m',  cq.inflow  != null ? -Math.min(1, cq.inflow  / 1000) : 0);
      this._setNode('ef_outflow_1m', cq.outflow != null ?  Math.min(1, cq.outflow / 1000) : 0);
      this._setNode('ef_netflow', netNorm);
      this._setNode('ef_stable_in', cq.stablecoinInflow != null ? Math.min(1, cq.stablecoinInflow / 500) : 0);
      this._setNode('ef_funding', cq.fundingRate != null ? Math.max(-1, Math.min(1, cq.fundingRate * 1000)) : 0);
      this._setNode('ef_inflow_5m',  cq.inflow  != null ? -Math.min(1, cq.inflow  / 2000) : 0);
      this._setNode('ef_outflow_5m', cq.outflow != null ?  Math.min(1, cq.outflow / 2000) : 0);
      this._setNode('ef_netflow_5m', netNorm * 0.9);
    }

    // Sentiment / Polymarket
    const upMid   = pmUp.mid   ?? 0.5;
    const downMid = pmDown.mid ?? 0.5;
    this._setNode('sp_up_prob',    upMid * 2 - 1);
    this._setNode('sp_down_prob',  downMid * 2 - 1);
    this._setNode('sp_up_liq',     Math.min(1, (pmUp.askDepth ?? 0) / 5000));
    this._setNode('sp_down_liq',   Math.min(1, (pmDown.askDepth ?? 0) / 5000));
    this._setNode('sp_imbalance',  upMid - downMid);
    this._setNode('sp_funding',    0);
    this._setNode('sp_fear_greed', 0);
    this._setNode('sp_spread_ratio', 0);

    // sp_lag and sp_momentum_prob updated by edge_detector after each detection
  }

  _setNode(id, value) {
    const n = this.nodes.get(id);
    if (!n) return;
    n.value = isFinite(value) ? Math.max(-1, Math.min(1, value)) : 0;
  }

  // One physics iteration
  tick() {
    this._activeEdgeForces.clear();

    // Step 1: self-restoring force — pull each node's position toward its external value
    for (const n of this.nodes.values()) {
      n.velocity += RESTORE * (n.value - n.position);
    }

    // Step 2: inter-node forces based on POSITION differences (not values)
    for (const edge of this.edges) {
      const u = this.nodes.get(edge.u);
      const v = this.nodes.get(edge.v);
      if (!u || !v) continue;

      const diff = u.position - v.position;
      let gain;

      if (edge.type === 'C')      gain =  GAIN_C;
      else if (edge.type === 'I') gain = -GAIN_I;
      else                        gain =  GAIN_A;

      const applied = edge.w * diff * gain;
      v.velocity += applied;
      edge.lastForce = Math.abs(applied);
      this._activeEdgeForces.set(`${edge.u}:${edge.v}`, edge.lastForce);
    }

    // Step 3: integrate positions
    let bullScore = 0, bearScore = 0, bullW = 0, bearW = 0;

    for (const n of this.nodes.values()) {
      n.velocity *= DAMPING;
      n.position += n.velocity;
      n.position  = Math.max(-POS_MAX, Math.min(POS_MAX, n.position));

      if (n.position > 0) { bullScore += n.position * n.weight; bullW += n.weight; }
      else                { bearScore -= n.position * n.weight; bearW += n.weight; }
    }

    const bAvg = bullW > 0 ? bullScore / bullW : 0;
    const rAvg = bearW > 0 ? bearScore / bearW : 0;
    const total = bAvg + rAvg + 1e-9;
    const convergence = Math.abs(bAvg - rAvg) / total;

    return {
      bias:        bAvg >= rAvg ? 'BULL' : 'BEAR',
      bull_score:  bAvg,
      bear_score:  rAvg,
      convergence: Math.min(1, convergence),
    };
  }

  // Called after trade outcome to adjust edge weights
  updateWeights(outcome) {
    const won = outcome.pnl > 0;
    for (const edge of this.edges) {
      const key = `${edge.u}:${edge.v}`;
      const activity = this._activeEdgeForces.get(key) ?? 0;
      if (activity < 0.01) continue;
      const delta = activity * CONFIG.WEIGHT_REINFORCE * (won ? 1 : -1);
      edge.w = Math.max(CONFIG.WEIGHT_MIN, Math.min(CONFIG.WEIGHT_MAX, edge.w + delta));
    }

    this._tradeCount++;
    if (this._tradeCount % CONFIG.WEIGHT_SAVE_INTERVAL === 0) this.saveWeights();
  }

  saveWeights() {
    const weights = {};
    for (const edge of this.edges) {
      weights[`${edge.u}:${edge.v}`] = edge.w;
    }
    try { writeFileSync(CONFIG.WEIGHTS_FILE, JSON.stringify(weights, null, 2)); } catch {}
  }

  // Snapshot of all node positions for display
  nodeSnapshot() {
    const out = {};
    for (const [id, n] of this.nodes) out[id] = { pos: n.position, val: n.value, cat: n.cat };
    return out;
  }

  static loadWeights() {
    if (!existsSync(CONFIG.WEIGHTS_FILE)) return {};
    try { return JSON.parse(readFileSync(CONFIG.WEIGHTS_FILE, 'utf8')); } catch { return {}; }
  }
}

export { NODE_DEFS, EDGE_DEFS };
