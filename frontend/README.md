# Frontend Application Structure

The React + TypeScript + Vite + Tailwind CSS + Recharts frontend is rooted at the repository root (`/src`, `/index.html`, `/vite.config.ts`) so `npm run dev` and `npm run build` execute directly.

- `src/types.ts` — Authoritative TypeScript interfaces matching the REST API contract.
- `src/api.ts` — Typed REST client for `/api/*` endpoints (zero mock or hardcoded data).
- `src/components/Layout.tsx` — Light-theme sidebar navigation + live `/api/health` engine status dots.
- `src/components/AlertDetailContent.tsx` — 4-component risk score breakdown (`severity`, `confidence`, `behavior`, `context`), formula, detection info, 5-tuple, and evidence table.
- `src/pages/DashboardPage.tsx` — 4 summary stat cards, category donut chart, method bar chart, timeline line chart, top source IPs, and recent alerts.
- `src/pages/UploadPage.tsx` — Drag-and-drop `.pcap`/`.pcapng` upload (100 MB limit), live polling job card, Scenario A/B/C/D verification controls, CSV/JSON export, and previous jobs table.
- `src/pages/AlertsPage.tsx` — URL-synced filter bar, paginated alerts table (sorted by `risk_score desc`), and right-side detail drawer.
- `src/pages/AlertDetailPage.tsx` — Standalone `/alerts/:id` view.
- `src/pages/EvaluationPage.tsx` — Held-out CICIDS2017 metrics, 2x2 confusion matrix, and limitations note.
