# Deployment Guide

## Deploy to Railway (Go proxy + Express backend)

1. Install Railway CLI: `npm install -g @railway/cli`
2. Login: `railway login`
3. Create project: `railway init`
4. Deploy: `railway up`
5. Get your URL: `railway domain`
6. Your proxy is live at: `https://your-app.up.railway.app`

## Deploy Frontend to Vercel

1. Go to https://vercel.com/new
2. Import GitHub repo: `tejaspatil1936/Consensus-Lab`
3. Set root directory: `proxyshield/demo-apikeys/frontend`
4. Add environment variable:
   - `VITE_API_URL` = `https://your-app.up.railway.app` (the Railway URL from step 5 above)
5. Deploy

## After both are deployed

- Frontend: `https://your-app.vercel.app`
- Proxy: `https://your-app.up.railway.app`

> **Dashboard note:** Railway exposes only the single `$PORT` (the proxy). The
> real-time dashboard runs on `$PORT + 1`, which Railway does **not** route, so
> it is not reachable at a public URL on Railway. Run the proxy locally
> (`./proxyshield --config config.json`) to view the dashboard at
> `http://localhost:9091`, or deploy somewhere that can expose two ports. If you
> expose it, set `dashboard.auth_token` in the config to protect the telemetry.

## Local development (no deployment needed)

```bash
cd demo-apikeys
bash start.sh
```
