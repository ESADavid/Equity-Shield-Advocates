import { Router } from 'express';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

const {
  run_full_analysis,
  summarize_sector_performance,
  summarize_company_distribution,
  summarize_key_metrics
} = require('../../ai_analysis.py');

const { predict } = require('../../ai_predictive.py');
const { handle_query } = require('../../ai_nl_query.py');
const { generate_full_report_bundle } = require('../../ai_report.py');

const router = Router();

router.post('/analysis/full', (req, res, next) => {
  try {
    const result = run_full_analysis(req.body);
    return res.json({ ok: true, result, requestId: req.requestId });
  } catch (err) {
    return next(err);
  }
});

router.post('/analysis/sector', (req, res, next) => {
  try {
    const result = summarize_sector_performance(req.body);
    return res.json({ ok: true, result, requestId: req.requestId });
  } catch (err) {
    return next(err);
  }
});

router.post('/analysis/distribution', (req, res, next) => {
  try {
    const result = summarize_company_distribution(req.body);
    return res.json({ ok: true, result, requestId: req.requestId });
  } catch (err) {
    return next(err);
  }
});

router.post('/analysis/metrics', (req, res, next) => {
  try {
    const result = summarize_key_metrics(req.body);
    return res.json({ ok: true, result, requestId: req.requestId });
  } catch (err) {
    return next(err);
  }
});

router.post('/predict', (req, res, next) => {
  try {
    const records = Array.isArray(req.body?.records) ? req.body.records : [];
    const valueKey = typeof req.body?.valueKey === 'string' ? req.body.valueKey : 'value';
    const horizon = Number.isInteger(req.body?.horizon) ? req.body.horizon : 3;
    const result = predict(records, valueKey, horizon);
    return res.json({ ok: true, result, requestId: req.requestId });
  } catch (err) {
    return next(err);
  }
});

router.post('/nl-query', (req, res, next) => {
  try {
    const query = typeof req.body?.query === 'string' ? req.body.query : '';
    const result = handle_query(query);
    return res.json({ ok: true, result, requestId: req.requestId });
  } catch (err) {
    return next(err);
  }
});

router.post('/report', (req, res, next) => {
  try {
    const analysis = req.body?.analysis || {};
    const predictive = req.body?.predictive || {};
    const risk = req.body?.risk || {};
    const result = generate_full_report_bundle(analysis, predictive, risk);
    return res.json({ ok: true, result, requestId: req.requestId });
  } catch (err) {
    return next(err);
  }
});

export default router;
