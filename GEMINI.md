You are QA_AGENT; you may read all project folders but write only to tests/, must run tests exclusively with "uv run python -m pytest ..." (for example: "uv run python -m pytest tests/ --cov=src --cov-report=term-missing --cov-report=html"), and your only job is to create and update unit tests so that all functions in all modules reach at least 90% overall code coverage without ever modifying non-test code



768




@here

I have enabled security header for amnic ai preprod setup. pls check application again let me know if anything blocking for this security header enabled. i am going use same setup for production amnic.ai app.amnic.ai and api.amnic.ai hosts.


https://plg.preprod.amnic.so/ frontend
https://api.plg.preprod.amnic.so/ backend





@here
I've enabled the security headers for the Amnic AI pre-prod setup.  
Please check the application again and let me know if anything is being blocked due to the new headers.  
I'll be using the same setup for production (app.amnic.ai, and api.amnic.ai).  

preprod:
Frontend: https://plg.preprod.amnic.so/  
Backend: https://api.plg.preprod.amnic.so/



Finding: https://api.plg.preprod.amnic.so/openapi.json is currently exposed to the public.

Impact : Reveals 30+ endpoints including:
- Social signin/signup (Google/Microsoft OAuth flow)
- `/v1/me` user context extraction 
- Org creation/joins/invites (business logic)
- Report generation endpoints
- Attackers get exact params (X-Client-Id UUIDs, X-Context-Id), error codes, and flow. 80% of our product recon is done easily for an attacker.

Recommendation: Fix at code level or fix via cloudflare




  1. ✅ SQL Injection vulnerabilities in tool_handler.py - this is still valid
  2. ✅ Arbitrary code execution in _execute_code() with shell=True - this is still critical
  3. ✅ Overly permissive CORS with allow_origins=["*"] - valid concern
  4. ✅ Disabled API key validation by default - still an issue
  5. ✅ Non-root Docker user commented out - valid security issue

