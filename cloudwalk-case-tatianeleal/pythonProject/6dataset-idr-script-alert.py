import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

requests_threshold = 100
suspicious_countries = ['us', 'ru', 'cn']
unusual_ports = [22, 3389]

def detect_high_volume_ips(df):
    ip_counts = df['ClientIP'].value_counts()
    return ip_counts[ip_counts > requests_threshold]

def detect_suspicious_countries(df):
    return df[df['ClientCountry'].isin(suspicious_countries)]

def detect_unusual_ports(df):
    return df[df['ClientSrcPort'].isin(unusual_ports)]

def generate_alerts(df):
    alerts = []

    high_volume_ips = detect_high_volume_ips(df)
    if not high_volume_ips.empty:
        alerts.append(f"IPs com volume elevado de requisições: {list(high_volume_ips.index)}")

    suspicious_country_requests = detect_suspicious_countries(df)
    if not suspicious_country_requests.empty:
        alerts.append(f"Requisições de países suspeitos: {suspicious_country_requests['ClientIP'].unique()}")

    unusual_port_requests = detect_unusual_ports(df)
    if not unusual_port_requests.empty:
        alerts.append(f"Requisições usando portas incomuns: {unusual_port_requests['ClientSrcPort'].unique()}")

    return alerts


def send_email(alerts, to_email, from_email, smtp_server, smtp_port, login, password):
    if not alerts:
        print("Nenhum alerta gerado, nenhum e-mail será enviado.")
        return

    alert_message = "\n".join(alerts)
    subject = "Alerta de Atividade Suspeita na Rede"

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(alert_message, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(login, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print(f"E-mail enviado para {to_email}")
    except Exception as e:
        print(f"Falha no envio do e-mail: {e}")


to_email = "idr.quarantine@exemplo.com"
from_email = "sec.analyst@exemplo.com"
smtp_server = "smtp.gmail.com"
smtp_port = 587
login = "sec.analyst@exemplo.com"
password = "senha"

data = pd.read_csv('test-dataset.csv')

alerts = generate_alerts(data)

# Envio dos alertas por e-mail
send_email(alerts, to_email, from_email, smtp_server, smtp_port, login, password)
