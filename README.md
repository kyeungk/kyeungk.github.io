# Keith Yeung - Personal Website

Interactive travel map showing 14,000+ places visited from 2009-2025.

**Live at**: [keithyeung.com](https://www.keithyeung.com)

## Privacy

Home and work locations (5 mile radius) have been filtered out for privacy.

## CI

Every PR and push runs `.github/workflows/checks.yml`: a public-site guard (personal/financial data, GPS, coordinates near a home) and a secret scan. Main is protected, so the page cannot publish until both pass.

## Tech Stack

- Pure HTML/CSS/JavaScript
- Leaflet.js for maps
- CARTO dark basemap
- Hosted on GitHub Pages

## Data Source

Google Maps Timeline export, processed with Claude Code.

---

Built with 🤖 [Claude Code](https://claude.ai/claude-code)
