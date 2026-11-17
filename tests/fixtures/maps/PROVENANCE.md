# Map provider fixtures: provenance

Every file under a `run-<id>/` folder is a raw provider answer recorded by
the opt-in `maps-live-smoke` workflow and copied unmodified from that run's
artifact (`maps-live-<id>`). No fixture here is hand-written. Each run's
`MANIFEST` is the workflow's own record: per request, the file name, UTC
time, HTTP status, content type and the exact URL sent.

## run-44178019895

- Workflow run: https://github.com/MikkoParkkola/mcp-gateway/actions/runs/44178019895
- Recording branch head: 06d38ac017e371f3d846c8bead38507df20e4168 (draft PR #5048,
  opened only for recording, never merged)
- Recorded: 2026-11-17, 21:16:22Z to 21:16:31Z (times per file in `MANIFEST`)

| File | Status | Content type | Request |
|---|---|---|---|
| geocode.json | 200 | application/json; charset=utf-8 | geocoding-api.open-meteo.com/v1/search?name=Helsinki&count=5 |
| geocode_none.json | 200 | application/json; charset=utf-8 | geocoding-api.open-meteo.com/v1/search?name=Qxzvqzzyx&count=5 |
| weather.json | 200 | application/json; charset=utf-8 | api.open-meteo.com/v1/forecast (coordinates 60.1699, 24.9384; no forecast_days) |
| nominatim_search.json | 200 | application/json; charset=utf-8 | nominatim.openstreetmap.org/search?q=Helsinki+Cathedral&format=jsonv2&limit=5 |
| nominatim_reverse.json | 200 | application/json; charset=utf-8 | nominatim.openstreetmap.org/reverse?lat=60.1699&lon=24.9384&format=jsonv2&zoom=18 |
| photon_search.json | 200 | application/json | photon.komoot.io/api/?q=Helsinki+Cathedral&limit=5 |
| overpass_nearby.json | 502 | text/plain | overpass-api.de/api/interpreter (QL in `MANIFEST`); the server's at-capacity answer, not JSON despite the name |
| osrm_route.json | 200 | application/json; charset=UTF-8 | router.project-osrm.org/route/v1/driving/24.9384,60.1699;22.2666,60.4518?overview=false |

The full URLs are in `run-44178019895/MANIFEST`.

## Licences of the recorded data

- Open-Meteo answers (geocode, weather): Open-Meteo.com, CC BY 4.0.
- Nominatim, Photon and Overpass answers, and OSRM routes: data
  © OpenStreetMap contributors, ODbL 1.0.
