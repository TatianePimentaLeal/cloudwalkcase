import pandas as pd

def analyze_suspicious_activity(file_path, port_threshold=100, ip_threshold=100):
    """
    Análise das atividades suspeitas (verificação de portas e IPs com alta frequência).
    """
    df = pd.read_csv(file_path)

    ip_counts = df['ClientIP'].value_counts()
    port_counts = df['ClientSrcPort'].value_counts()

    # Filtragem de IPs e portas que excedem o limite definido
    suspicious_ips = ip_counts[ip_counts > ip_threshold]
    suspicious_ports = port_counts[port_counts > port_threshold]

    return suspicious_ips, suspicious_ports

file_path = 'test-dataset.csv'
suspicious_ips, suspicious_ports = analyze_suspicious_activity(file_path)

print("IPs suspeitos:")
print(suspicious_ips)

print("\nPortas suspeitas:")
print(suspicious_ports)
