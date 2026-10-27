package apigateway

import (
	_ "embed"
	"net/http"
	"strings"
)

//go:embed openapi.yaml
var embeddedOpenAPIYAML []byte

const scalarHTML = `<!doctype html>
<html lang="en">
  <head>
    <title>Aeitron Global Infrastructure — Developer API Reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="description" content="Interactive developer documentation and API reference for the Aeitron Intelligent Global Edge & Cloud Infrastructure Platform." />
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='%236366f1'/><path d='M30 70 L50 30 L70 70 Z' fill='none' stroke='white' stroke-width='8'/></svg>" />
    <style>
      body {
        margin: 0;
        padding: 0;
        background-color: #0b0f19;
      }
      /* Custom header bar styling */
      .aeitron-top-nav {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 10px 24px;
        background: rgba(15, 23, 42, 0.95);
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        color: #f8fafc;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 14px;
        backdrop-filter: blur(12px);
      }
      .aeitron-brand {
        display: flex;
        align-items: center;
        gap: 10px;
        font-weight: 700;
        letter-spacing: -0.02em;
        text-decoration: none;
        color: #fff;
      }
      .aeitron-badge {
        font-size: 11px;
        padding: 2px 8px;
        border-radius: 9999px;
        background: rgba(99, 102, 241, 0.2);
        color: #818cf8;
        border: 1px solid rgba(99, 102, 241, 0.4);
        font-weight: 600;
      }
      .aeitron-links {
        display: flex;
        align-items: center;
        gap: 16px;
      }
      .aeitron-link {
        color: #94a3b8;
        text-decoration: none;
        transition: color 0.15s ease;
      }
      .aeitron-link:hover {
        color: #f1f5f9;
      }
    </style>
  </head>
  <body>
    <div class="aeitron-top-nav">
      <a href="https://aeitron.com" class="aeitron-brand">
        <svg width="24" height="24" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect width="100" height="100" rx="20" fill="#6366f1"/>
          <path d="M30 70 L50 30 L70 70 Z" stroke="white" stroke-width="8" stroke-linejoin="round"/>
        </svg>
        Aeitron Global Infrastructure
        <span class="aeitron-badge">OpenAPI 3.1.0</span>
      </a>
      <div class="aeitron-links">
        <a href="/swagger" class="aeitron-link">Swagger UI</a>
        <a href="/openapi.yaml" download="openapi.yaml" class="aeitron-link">Download Spec (.yaml)</a>
        <a href="/ready" class="aeitron-link" target="_blank">Health (/ready)</a>
        <a href="https://github.com/aeitron/api" target="_blank" class="aeitron-link">GitHub Repo ↗</a>
      </div>
    </div>
    <script
      id="api-reference"
      data-url="/openapi.yaml"
      data-configuration='{"theme":"purple","darkMode":true,"layout":"modern","hideModels":false,"showSidebar":true,"searchHotKey":"k"}'>
    </script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>
`

const swaggerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Aeitron API — Swagger UI</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='%236366f1'/><path d='M30 70 L50 30 L70 70 Z' fill='none' stroke='white' stroke-width='8'/></svg>" />
  <style>
    html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
    *, *:before, *:after { box-sizing: inherit; }
    body { margin:0; background: #0b0f19; }
    .swagger-ui .topbar { background-color: #0f172a; border-bottom: 1px solid rgba(255,255,255,0.08); }
    .swagger-ui { filter: invert(88%) hue-rotate(180deg); }
    .swagger-ui img, .swagger-ui .download-contents { filter: invert(100%) hue-rotate(180deg); }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: "/openapi.yaml",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout"
      });
    };
  </script>
</body>
</html>
`

// ServeDocs handles requests for interactive documentation and OpenAPI specifications.
// Returns true if the request was handled, false otherwise.
func ServeDocs(w http.ResponseWriter, r *http.Request) bool {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "" {
		path = "/"
	}

	switch path {
	case "/docs", "/scalar":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(scalarHTML))
		return true

	case "/swagger":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(swaggerHTML))
		return true

	case "/openapi.yaml":
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(embeddedOpenAPIYAML)
		return true

	default:
		return false
	}
}
