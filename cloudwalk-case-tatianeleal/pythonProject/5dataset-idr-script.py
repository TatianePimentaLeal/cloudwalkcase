import pandas as pd

data = pd.read_csv('test-dataset.csv')

# Parâmetros para detecção de atividades suspeitas
requests_threshold = 100  # número limite de requisições repetidas de um mesmo IP
suspicious_countries = ['us', 'ru', 'cn']  # países suspeitos ou inesperados
unusual_ports = [22, 3389]  # portas que são incomuns para acesso web

def detect_high_volume_ips(df):
    ip_counts = df['ClientIP'].value_counts()
    return ip_counts[ip_counts > requests_threshold]

def detect_suspicious_countries(df):
    return df[df['ClientCountry'].isin(suspicious_countries)]

def detect_unusual_ports(df):
    return df[df['ClientSrcPort'].isin(unusual_ports)]

def generate_alerts(df):
    alerts = []

    # IPs com alta quantidade de requisições
    high_volume_ips = detect_high_volume_ips(df)
    if not high_volume_ips.empty:
        alerts.append(f"IPs com volume elevado de requisições: {list(high_volume_ips.index)}")

    # Países suspeitos
    suspicious_country_requests = detect_suspicious_countries(df)
    if not suspicious_country_requests.empty:
        alerts.append(f"Requisições de países suspeitos: {suspicious_country_requests['ClientIP'].unique()}")

    # Portas de origem incomuns
    unusual_port_requests = detect_unusual_ports(df)
    if not unusual_port_requests.empty:
        alerts.append(f"Requisições usando portas incomuns: {unusual_port_requests['ClientSrcPort'].unique()}")

    return alerts

alerts = generate_alerts(data)
for alert in alerts:
    print(alert)


