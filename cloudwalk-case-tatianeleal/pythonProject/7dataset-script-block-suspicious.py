import os

# Bloqueio de IPs suspeitos usando iptables
def block_ip(ip):
    command = f"sudo iptables -A INPUT -s {ip} -j DROP"
    os.system(command)
    print(f"IP {ip} bloqueado.")

# Bloqueio de IPs com muitas requisições
def block_suspicious_ips(df):
    high_volume_ips = detect_high_volume_ips(df)
    for ip in high_volume_ips.index:
        block_ip(ip)

# block_suspicious_ips para bloquear IPs suspeitos
block_suspicious_ips(data)
