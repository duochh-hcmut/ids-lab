
## What you need

- Docker Engine and Compose v2. The command is `docker compose`.
- Bash, Git, and a network connection the first time, so Docker can pull images and Kali can run `apt`.
- Ports `8080` and `3000` free. Subnet `172.20.0.0/16` free of any other Docker network.
- `shasum` (macOS) or `sha256sum` (Linux). The script picks whichever is installed.

The full matrix has been run on macOS, Docker Desktop 28.3.3, arm64. Linux with Docker Engine uses the same commands.

Python 3 and host `tcpdump` are only for reading evidence afterward. The scripts do not need them.

## First run

From the repository root:

```sh
docker info
chmod +x scripts/*.sh
./scripts/run-all.sh
```

`docker info` should print server details. If it reports a socket error, start Docker Desktop and run it again.

`run-all.sh` does all of the following:

1. Creates the `172.20.0.0/16` network, Nginx at `172.20.0.20`, Kali at `172.20.0.10`, Suricata, and the `tcpdump` container.
2. Installs `nmap`, `curl`, and `ping` in Kali when they are missing. The first install takes a few minutes.
3. Runs E0 through E8. E3 is the slow scan and takes about 90 seconds. With images already present, the whole matrix takes about 3 minutes. The first Kali image pull takes longer.
4. Writes evidence to `suricata/logs/runs/E0` through `E8`.
5. Restores `suricata/rules/local.rules` to rev 3 when the script exits.

This command does not pull or start the Wireshark image.

## What the script runs

| ID | What the script does | Expected result |
|---|---|---|
| E0 | `suricata -T` | `E0/suricata-T.txt` contains `configuration loaded` |
| E1 | ping and `GET /` | HTTP 200, empty `fast.log` |
| E2 | `nmap -sS` of 1000 ports, at least 100 packets/second | SID `1000001` rev 3 alerts. The reference run had 50 alerts for 1000 SYNs |
| E3 | `nmap -sS` of 40 ports, 2-second delay | No `1000001` alert |
| E4 | `GET /admin/config.php` | One `1000003` alert, no `1000001`, HTTP 404 |
| E5 | `GET /../../etc/passwd` | No SID `1000002`, HTTP 400 |
| E6 | `GET` with `%2e%2e` | No SID `1000002`, HTTP 400 |
| E7 | `GET /` under the rev 2 rules | SID `1000001` rev 2 alerts once on the homepage |
| E8 | `GET /admin` with SID `1000003` set to `drop` | `fast.log` contains `wDrop`, and Nginx still logs the request and returns 404 |

The E2 alert count can drift by a few if the machine cannot hold `--min-rate 100`. SID `1000001` rev 3 should still alert, and E3 should stay quiet. An alert in E3 means the threshold no longer separates the slow scan. Read `runs/E3/fast.log` before using that run.

## Read the evidence

Each directory `suricata/logs/runs/<ID>/` contains:

- `notes.md`: the command, UTC time, and the HTTP status when the run used curl
- `rules-used.rules`: the exact rule file loaded for that run
- `fast.log`: one alert per line
- `eve.json`: one JSON object per line
- `evidence.pcap`: packets for that run only. E0 has no capture

Count alerts:

```sh
grep -c "1000001" suricata/logs/runs/E2/fast.log
grep "1000001" suricata/logs/runs/E1/fast.log
```

Read one HTTP event:

```sh
grep '"event_type":"alert"' suricata/logs/runs/E4/eve.json
```

Read a capture on the host:

```sh
tcpdump -nn -r suricata/logs/runs/E2/evidence.pcap | head
```

Another full run overwrites `suricata/logs/runs/E0` through `E8`. Copy the current evidence first if you want to keep it:

```sh
cp -R suricata/logs/runs suricata/logs/runs-kept
```

## Run a single scenario

The lab has to be up. If it is not:

```sh
./scripts/up.sh
./scripts/prepare-attacker.sh
```

Then:

```sh
./scripts/run-baseline.sh
./scripts/run-syn-scan.sh
./scripts/run-syn-slow.sh
./scripts/run-http.sh admin
./scripts/run-http.sh traversal
./scripts/run-http.sh encoded
```

E7 and E8 swap the rule file. Run those two only through `./scripts/run-all.sh`, which restores rev 3 on exit. If a run is interrupted and `local.rules` no longer matches rev 3:

```sh
cp suricata/rules/local.rules.rev3 suricata/rules/local.rules
docker restart lab_ids
```

Edit rules in `suricata/rules/local.rules.rev3`. `local.rules` is the file mounted into the container, and the scripts overwrite it.

## Stop the lab

```sh
docker compose down
```

`down` removes the containers and the network. Evidence under `suricata/logs/runs/` stays on disk.

## Wireshark

The results table does not depend on it. To open a capture in the GUI:

```sh
docker compose up -d wireshark
```

Open `http://localhost:3000`, then open a file under `/config/pcap/runs/`, for example `/config/pcap/runs/E2/evidence.pcap`.

## When a command fails

| Symptom | What to do |
|---|---|
| `cannot connect to the Docker daemon` | Start Docker, then run `docker info` again |
| `address already in use` on `8080` or `3000` | Free the port, or stop an old lab with `docker compose down` |
| `Pool overlaps` on `172.20.0.0/16` | Run `docker network ls` and remove the network that already holds this subnet |
| `suricata did not report engine started` | Run `docker logs --tail 80 lab_ids`. The rules or `suricata.yaml` failed to load |
| E0 fails | Read `suricata/logs/runs/E0/suricata-T.txt` |
| Kali cannot install `nmap` | The machine needs outbound network for `apt-get update`. Run `./scripts/prepare-attacker.sh` again |
| `fast.log` is empty for a run that should alert | Read `sensor-start.txt` in that run directory and `docker logs lab_ids` |

After a successful run the containers stay up. `./scripts/run-all.sh` is enough for the next run. `docker compose down` is optional.
