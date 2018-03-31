[Unit]
Description=Shang Full Node
After=network.target

[Service]
User=shang
Group=shang
WorkingDirectory=~

Type=forking
PIDFile=/var/run/shangd.pid

ExecStart=/usr/bin/shangd --config-file /etc/shangd.conf \
    --detach --pidfile /var/run/shangd.pid

[Install]
WantedBy=multi-user.target
