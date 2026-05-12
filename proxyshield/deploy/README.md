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
- Dashboard: `https://your-app.up.railway.app/dashboard`

## Local development (no deployment needed)

```bash
cd demo-apikeys
bash start.sh
```
