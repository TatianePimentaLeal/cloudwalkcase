import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os

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


# Função para enviar o alerta por e-mail
def send_email(alerts, to_email, from_email, smtp_server, smtp_port, login, password):
    if not alerts:
        print("Nenhum alerta gerado, nenhum e-mail será enviado.")
        return

    # Montar o corpo do e-mail
    alert_message = "\n".join(alerts)
    subject = "Alerta de Atividade Suspeita na Rede"

    # Criar o conteúdo do e-mail
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(alert_message, 'plain'))

    try:
        # Estabelecer conexão com o servidor SMTP e enviar o e-mail
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Se o servidor exigir TLS
        server.login(login, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print(f"E-mail enviado para {to_email}")
    except Exception as e:
        print(f"Falha no envio do e-mail: {e}")


# Função para bloquear IPs suspeitos usando iptables
def block_ip(ip):
    command = f"sudo iptables -A INPUT -s {ip} -j DROP"
    os.system(command)
    print(f"IP {ip} bloqueado.")


# Função para bloquear IPs com muitas requisições
def block_suspicious_ips(df):
    high_volume_ips = detect_high_volume_ips(df)
    for ip in high_volume_ips.index:
        block_ip(ip)


# Parâmetros de envio de e-mail
to_email = "idr.quarantine@exemplo.com"  # E-mail para onde os alertas serão enviados
from_email = "sec.analyst@exemplo.com"  # Seu e-mail
smtp_server = "smtp.gmail.com"  # Servidor SMTP do Gmail
smtp_port = 587  # Porta SMTP
login = "sec.analyst@exemplo.com"  # Login de e-mail (seu e-mail)
password = "sua_senha"  # Senha do e-mail (use senhas de app no Gmail)

# Carregar o dataset
data = pd.read_csv('test-dataset.csv')

# Gerar alertas
alerts = generate_alerts(data)

# Enviar os alertas por e-mail
send_email(alerts, to_email, from_email, smtp_server, smtp_port, login, password)

# Bloquear os IPs suspeitos detectados
block_suspicious_ips(data)
