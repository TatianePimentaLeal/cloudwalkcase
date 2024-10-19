import pandas as pd

def analyze_suspicious_activity(file_path, port_threshold=100, ip_threshold=100):
    """
    Analisa atividades suspeitas com base em portas e IPs que aparecem com alta frequência.

    :param file_path: Caminho para o arquivo CSV.
    :param port_threshold: Limite para considerar uma porta suspeita (quantidade de acessos).
    :param ip_threshold: Limite para considerar um IP suspeito (quantidade de acessos).
    :return: DataFrames de IPs e portas suspeitos.
    """
    # Ler o arquivo CSV
    df = pd.read_csv(file_path)

    # Contar a frequência de IPs e portas
    ip_counts = df['ClientIP'].value_counts()
    port_counts = df['ClientSrcPort'].value_counts()

    # Filtrar IPs e portas que excedem o limite definido
    suspicious_ips = ip_counts[ip_counts > ip_threshold]
    suspicious_ports = port_counts[port_counts > port_threshold]

    return suspicious_ips, suspicious_ports

file_path = 'test-dataset.csv'
suspicious_ips, suspicious_ports = analyze_suspicious_activity(file_path)

# Exibir os IPs e portas suspeitas
print("IPs suspeitos:")
print(suspicious_ips)

print("\nPortas suspeitas:")
print(suspicious_ports)
