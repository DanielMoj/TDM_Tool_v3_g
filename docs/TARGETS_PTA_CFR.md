# TARGETS · PTA · CFR

## Zielmetriken
- **fT>MIC** (β-Laktame): Anteil der Zeit innerhalb **τ**, in der C(t) > MIC.  
- **AUC24/MIC** (Vancomycin): AUC über τ → auf **24h** skaliert, dann / MIC.  
- **Cmax/MIC** (Aminoglykoside).

**Hinweis:** Default-Targets in `config/targets.json` sind **Platzhalter**.

## PTA (Probability of Target Attainment)
- Ziehe **Posterior-Draws**.  
- Simuliere **steady state** (20·τ), nimm letzte **τ**.  
- Berechne Metrik je Draw → **PTA = Anteil Draws, die Ziel erfüllen**.

## CFR (Cumulative Fraction of Response)
- Diskrete **MIC-Verteilung** `MIC_i : P_i`.  
- **CFR = Σ PTA(MIC_i)·P_i**.

## Site-of-Infection
- Konzentrationen werden per **Faktor** skaliert (`config/tissue.json`), z. B. ELF 0.6–0.7.

## UI
- Sidebar: **MIC** (einzeln) & **MIC-Verteilung** (Textformat `mic:prob, ...`).  
- Ziele: **Auto (per Drug)** oder **Manuell**.

## Beispiele
- Meropenem: fT>MIC ≥ 50% (Demo).  
- Vancomycin: AUC24/MIC 400–600 (Demo).

## Grenzen
- AUC24 aus AUCτ skaliert (vereinfachend).  
- MIC-Verteilungen klinikspezifisch → bitte **lokal** befüllen.

## Verbindung zur Optimierung
PTA gegen das gewählte Target bildet die Zielfunktion in der Phase-4-Optimierung. Sie variiert Dosis/τ/tinf unter Constraints und bewertet zusätzlich eine Risiko-Metrik.
