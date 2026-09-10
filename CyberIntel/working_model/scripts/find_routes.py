import re
with open('app.py','r',encoding='utf-8',errors='ignore') as f:
    content = f.read()
routes = re.findall(r"@app\.route\([\"\']([/a-zA-Z0-9_<>]+)[\"\']", content)
for r in routes:
    if any(k in r.lower() for k in ['entity','profile','financial','complaint','search']):
        print(r)
