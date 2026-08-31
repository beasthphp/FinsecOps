# Monitoring dashboard

The Streamlit dashboard is the presentation layer for the FinSecOps prototype. It reads the local SQLite event store and surfaces:

- recent security alerts and explanations
- rule, ML, and final risk scores
- high/critical alert counts
- anomaly counts from the Isolation Forest detector
- suspicious-user summaries
- a searchable security-event view

Run it from the repository root with:

```bash
streamlit run dashboard/dashboard.py
```

The dashboard is intentionally local and lightweight; production SOC integrations are outside the current prototype scope.
