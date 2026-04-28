# Création d'un timer systemd (exemple de log nvidia-smi)

(source : [https://documentation.suse.com/fr-fr/sle-micro/6.0/html/Micro-systemd-working-with-timers/index.html](https://documentation.suse.com/fr-fr/sle-micro/6.0/html/Micro-systemd-working-with-timers/index.html))

## Création du script à exécuter

Contenu du script bash `/root/gpu-monitor.sh`

```bash
#!/usr/bin/env bash

nvidia-smi --query-gpu=timestamp,gpu_name,serial,utilization.gpu,utilization.memory,temperature.gpu,power.draw --format=csv,noheader,nounits >> /root/gpu-monitor-$HOSTNAME.csv
```

Droits d'exécution :
```bash
chmod +x /root/gpu-monitor.sh
```


## Création du service systemd lançant ce script

Contenu de l'unit systemd `/etc/systemd/system/gpu-monitor.service`:

```bash
[Unit]
Description="Append GPU info in /root/gpu-monitor.csv"

[Service]
ExecStart=/root/gpu-monitor.sh
```

## Création du timer systemd lançant le service

Contenu du timer systemd `/etc/systemd/system/gpu-monitor.timer`

```bash
[Unit]
Description="Run gpu-monitor.service every 2 minutes"

[Timer]
OnUnitActiveSec=2min
Unit=gpu-monitor.service

[Install]
WantedBy=multi-user.target
```

## Lancement du timer

```bash
systemctl daemon-reload
systemctl enable gpu-monitor.timer
systemctl start gpu-monitor.timer
```
