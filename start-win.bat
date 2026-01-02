@echo off
:: Windows dev starter: load .env (simple KEY=VALUE lines), install and run
if exist .env (
  for /f "usebackq tokens=1* delims==" %%A in (.env) do set "%%A=%%B"
)
call npm install
call npm run dev
