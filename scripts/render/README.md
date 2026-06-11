# Render migration helper

This script helps migrate environment variables defined in `render.yaml` to an existing Render service by updating the service's env vars via the Render API. It does NOT create services automatically. Use this when you want to safely push sensitive values from your local environment into Render.

Important safety notes
- Do NOT commit secrets to Git. The script reads sensitive values from your local environment only (process.env).
- You must have a Render API key and permissions for the workspace/service.

Prerequisites
- Node 18+ (native fetch)
- From repository root run `npm install` to install `js-yaml` dependency added to `devDependencies`.

How it works
1. Reads `render.yaml` in the repository root and picks the service named by the first CLI argument (default `watchdog-api`).
2. For env keys that have no `value` in the YAML (i.e., were marked sensitive with `sync: false`) the script reads values from your shell environment.
3. Replaces the service's env-vars via the Render API and triggers a deploy.

Usage examples

PowerShell (Windows):

```powershell
# set your Render API key in the current session (DO NOT commit)
$env:RENDER_API_KEY = "<your-render-api-key>"
# set any sensitive env vars referenced in render.yaml (examples)
$env:FIREBASE_PRIVATE_KEY = "<value>"
$env:FIREBASE_SERVICE_ACCOUNT_JSON = "<value>"

# run the migration (pass service name if different)
npm run render:migrate -- watchdog-api
```

Bash/macOS/Linux:

```bash
export RENDER_API_KEY="<your-render-api-key>"
export FIREBASE_PRIVATE_KEY="<value>"
export FIREBASE_SERVICE_ACCOUNT_JSON='{"type":"..."}'

npm run render:migrate -- watchdog-api
```

If the script reports any missing keys, set them in your shell and re-run.

Creating a new service from `render.yaml`
- This script updates env vars for an existing service only. To create a new service from the blueprint you can either:
  - Import the repository and `render.yaml` in the Render Dashboard and create the service manually, or
  - Use the Render Blueprints API to validate and create the blueprint programmatically (requires `ownerId` and more advanced steps). If you want, I can prepare a separate script to create a service via the Blueprints API — confirm first.

API troubleshooting
- To quickly verify your API key and list services manually, try:

```bash
curl --request GET "https://api.render.com/v1/services?limit=20" \
  -H "Authorization: Bearer $RENDER_API_KEY" \
  -H "Accept: application/json"
```

Next actions I can take for you
- Generate a script to create a new service from `render.yaml` via the Blueprints API (requires `ownerId`).
- Modify `render.yaml` or create a new service entry if you want me to prepare a blueprint for creation.
- Run additional automation to migrate secret files to Render (the API supports secret-files endpoint).

Tell me which of the above you want me to do next.