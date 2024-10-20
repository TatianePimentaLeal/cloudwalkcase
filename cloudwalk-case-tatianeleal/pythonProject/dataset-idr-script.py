import pandas as pd

# Carregar o dataset
data = pd.read_csv('test-dataset.csv')

# Parâmetros para detecção de atividades suspeitas
requests_threshold = 100  # número limite de requisições repetidas de um mesmo IP
suspicious_countries = ['us', 'ru', 'cn']  # países suspeitos ou inesperados
unusual_ports = [22, 3389]  # portas que são incomuns para acesso web


# Função para detectar IPs com muitas requisições
def detect_high_volume_ips(df):
    ip_counts = df['ClientIP'].value_counts()
    return ip_counts[ip_counts > requests_threshold]


# Função para detectar requisições de países suspeitos
def detect_suspicious_countries(df):
    return df[df['ClientCountry'].isin(suspicious_countries)]


# Função para detectar uso de portas incomuns
def detect_unusual_ports(df):
    return df[df['ClientSrcPort'].isin(unusual_ports)]


# Função para agregar os alertas
def generate_alerts(df):
    alerts = []

    # Detectar IPs com alta quantidade de requisições
    high_volume_ips = detect_high_volume_ips(df)
    if not high_volume_ips.empty:
        alerts.append(f"IPs com volume elevado de requisições: {list(high_volume_ips.index)}")

    # Detectar países suspeitos
    suspicious_country_requests = detect_suspicious_countries(df)
    if not suspicious_country_requests.empty:
        alerts.append(f"Requisições de países suspeitos: {suspicious_country_requests['ClientIP'].unique()}")

    # Detectar portas de origem incomuns
    unusual_port_requests = detect_unusual_ports(df)
    if not unusual_port_requests.empty:
        alerts.append(f"Requisições usando portas incomuns: {unusual_port_requests['ClientSrcPort'].unique()}")

    return alerts


# Gerar alertas
alerts = generate_alerts(data)
for alert in alerts:
    print(alert)


