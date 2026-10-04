# Third-party notices

Uninvited's own code is under the license in `LICENSE`. The dashboard also serves a few files made by other people. They
are kept in `static/vendor` so the page loads nothing from a third party. Each one keeps its own license, and the license
texts ship with it in `static/vendor/licenses`.

| What | Files | From | License |
|---|---|---|---|
| JetBrains Mono, the font | `static/vendor/fonts/*.woff2` | [JetBrains/JetBrainsMono](https://github.com/JetBrains/JetBrainsMono). The latin and latin-ext subsets, as downloaded from Google Fonts. | SIL Open Font License 1.1: [JetBrainsMono-OFL.txt](static/vendor/licenses/JetBrainsMono-OFL.txt) |
| topojson-client 3.1.0, which reads the map data | `static/vendor/topojson-client.min.js` | [topojson/topojson-client](https://github.com/topojson/topojson-client) | ISC: [topojson-client-LICENSE.txt](static/vendor/licenses/topojson-client-LICENSE.txt) |
| world-atlas 2, the coastline on the globe | `static/vendor/land-110m.json`, `static/vendor/land-50m.json` | [topojson/world-atlas](https://github.com/topojson/world-atlas), a redistribution of [Natural Earth](https://www.naturalearthdata.com/) vector data | ISC: [world-atlas-LICENSE.txt](static/vendor/licenses/world-atlas-LICENSE.txt) |
| Country flags, 32 by 24 pixels | `static/vendor/flags/*.png` | [flagcdn.com](https://flagcdn.com), made by [Flagpedia](https://flagpedia.net) | Public domain, as Flagpedia's About page states. There is no license text to ship. |

Not bundled, but used when you run an instance: the MaxMind GeoLite2 databases, which you download yourself under MaxMind's
terms, and the Python packages in `requirements.txt`, each under its own license.
