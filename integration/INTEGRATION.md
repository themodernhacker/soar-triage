# Wiring the integration into Wazuh

This connects the triage pipeline to Wazuh's native, **event-driven** integration
mechanism (`wazuh-integratord`). No polling: the manager runs the script the
instant an alert of level ≥ 10 is raised, and hands it the alert as JSON.

All commands assume the honeypot-siem lab is already running (the manager
container is `single-node-wazuh.manager-1`). Adjust the container name if yours
differs (`docker compose ps`).

## 1. Copy the code into the manager

From this repo's root:

```bash
# the pipeline modules go in a subfolder so their names never clash with other integrations
docker exec single-node-wazuh.manager-1 mkdir -p /var/ossec/integrations/soar_triage
docker cp src/. single-node-wazuh.manager-1:/var/ossec/integrations/soar_triage/

# the launcher Wazuh actually calls
docker cp integration/custom-soar-triage single-node-wazuh.manager-1:/var/ossec/integrations/custom-soar-triage
```

## 2. Provide credentials (never bake them into the image)

Create `.env` from the template, fill in your real values, and copy it next to
the launcher. `main.py` loads it and never overrides variables already in the
environment.

```bash
# on the host: cp .env.example .env  and edit .env
docker cp .env single-node-wazuh.manager-1:/var/ossec/integrations/.env
```

`GITHUB_TOKEN` must be a **fine-grained PAT scoped to Issues: Read and write on
the one repo**, nothing broader. `ABUSEIPDB_API_KEY` is optional (the lab's own
traffic is RFC 1918, so it is classified locally and the lookup is skipped).

## 3. Fix ownership and permissions

Own the files **`root:wazuh`, not `wazuh:wazuh`**. `wazuh-integratord` runs as the
`wazuh` user and refuses to execute an integration that the running user can write
to (it errors with "has write permissions"). Root-owned, group `wazuh`, mode 750
lets `wazuh` execute it but not modify it, which is exactly how Wazuh's own bundled
integrations (slack, virustotal, ...) are shipped.

```bash
docker exec single-node-wazuh.manager-1 sh -c '
  chown -R root:wazuh /var/ossec/integrations/soar_triage /var/ossec/integrations/custom-soar-triage /var/ossec/integrations/.env &&
  chmod 750 /var/ossec/integrations/custom-soar-triage &&
  chmod -R 750 /var/ossec/integrations/soar_triage &&
  chmod 640 /var/ossec/integrations/.env'
```

## 4. Register the integration in ossec.conf

Add this block inside `<ossec_config>` in
`/var/ossec/etc/ossec.conf` (in the manager). It fires the script for any alert
at level 10 or above and passes the full alert as JSON:

```xml
<integration>
  <name>custom-soar-triage</name>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

Quick way to insert it and restart:

```bash
docker exec single-node-wazuh.manager-1 sh -c '
  sed -i "s#</ossec_config>#  <integration>\n    <name>custom-soar-triage</name>\n    <level>10</level>\n    <alert_format>json</alert_format>\n  </integration>\n</ossec_config>#" /var/ossec/etc/ossec.conf'
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

## 5. Verify it is live

```bash
# integratord should now stay running (it exits cleanly when nothing is configured)
docker exec single-node-wazuh.manager-1 sh -c 'grep -i integrat /var/ossec/logs/ossec.log | tail -5'
```

Then trigger a real alert (from the honeypot-siem repo):

```powershell
python attack\brute_force.py 127.0.0.1 2222
python attack\run_session.py 127.0.0.1 2222
```

## 6. Watch it fire

With `SOAR_TRIAGE_TRACE` and `SOAR_TRIAGE_LOG` set in `.env` (see `.env.example`):

```bash
# the pipeline's own trace (enrich -> triage -> ticket)
docker exec single-node-wazuh.manager-1 sh -c 'tail -20 /var/ossec/logs/soar-triage.log'

# the decision log with full reasoning (one JSON record per decision)
docker exec single-node-wazuh.manager-1 sh -c 'tail -5 /var/ossec/logs/soar-triage-decisions.log'

# integratord's own view (execution errors show up here)
docker exec single-node-wazuh.manager-1 sh -c 'grep -i integrat /var/ossec/logs/ossec.log | tail -5'
```

The GitHub Issue it files appears in this repo's **Issues** tab.

## Manual run (no Wazuh needed, for testing the pipeline)

```bash
python src/main.py path/to/alert.json
```

A sample alert to try is in [`../tests/`](../tests/) fixtures / the honeypot lab's
indexer export.

## Removing it

Delete the `<integration>` block from `ossec.conf`, restart the manager, and
remove the files under `/var/ossec/integrations/`.
