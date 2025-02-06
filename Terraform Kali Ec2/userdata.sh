#!/bin/bash
# Enable comprehensive logging
exec > >(tee -a /var/log/user-data.log | logger -t user-data) 2>&1

# Update system and install core tools
apt-get update -y
apt-get upgrade -y
apt-get install -y curl unzip jq awscli

# Install AWS Session Manager Plugin
curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o "session-manager-plugin.deb"
dpkg -i session-manager-plugin.deb

# Install CloudWatch Agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
dpkg -i amazon-cloudwatch-agent.deb

# Configure CloudWatch Agent for SSM Logs
cat <<'EOT' > /opt/aws/amazon-cloudwatch-agent/bin/config.json
{
  "agent": {
    "run_as_user": "root",
    "debug": false
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/amazon/ssm/amazon-ssm-agent.log",
            "log_group_name": "${cloudwatch_log_group}",
            "log_stream_name": "{instance_id}-ssm-logs",
            "timestamp_format": "%Y-%m-%d %H:%M:%S"
          }
        ]
      }
    }
  }
}
EOT

# Start CloudWatch Agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json

# Security Hardening
systemctl disable avahi-daemon
systemctl stop avahi-daemon
systemctl disable cups
systemctl stop cups

# Cleanup
rm session-manager-plugin.deb amazon-cloudwatch-agent.deb

# Create login monitoring script
cat <<EOF > /usr/local/bin/monitor_logins.sh
#!/bin/bash
# Get logged-in users with IP
users_info=$(who | awk '{print $1, "-", $5}')
# Send message to all logged-in users
if [[ ! -z "$users_info" ]]; then
    wall <<EOM
=============================
  Active Logged-in Users:
=============================
$users_info
=============================
EOM
fi
EOF

# Make the script executable
chmod +x /usr/local/bin/monitor_logins.sh

# Add to cron (runs every 5 mins)
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/monitor_logins.sh") | crontab -

# Setup tools
wget https://raw.githubusercontent.com/Cyber-Chronicles/Cyber.github.io/refs/heads/main/Scripts/setup.sh -O /tmp/script.sh
chmod +x /tmp/script.sh
/tmp/script.sh
touch /tmp/check.txt && echo "Install setup ran till the end" >> /tmp/check.txt

# Final system update
apt-get autoremove -y
apt-get clean

exit 0
