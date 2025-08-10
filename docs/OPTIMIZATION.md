
# OPTIMIZATION

Phase-4-Optimierung: Strategien (Bolus/kurz/verlängert/kontinuierlich), Constraints, Pareto (PTA vs Risiko), Heatmaps, Auto-Empfehlung.

## Funktionen
- `generate_candidates`, `apply_constraints`
- `compute_pta_risk` (PTA + Risiko: `Cmax>limit` / `AUC24>limit` / `Vanco_AKI` Platzhalter)
- `pareto_front_idx`, `optimize_regimen`
- `pta_heatmap_data[_tau]`

## UI/Server
- Tab **„Optimierung“** mit Empfehlung, Pareto-Plot, Heatmaps, Grid.
- Sidebar-Block für Strategien, Bounds, Constraints, Risiko-Metrik, PTA-Schwelle.
