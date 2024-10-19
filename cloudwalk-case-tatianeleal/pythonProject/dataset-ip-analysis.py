import pandas as pd
import ipaddress


def is_private_ip(ip):
    """
    Verifica se um endereço IP é privado ou público.

    :param ip: String contendo o endereço IP.
    :return: True se o IP for privado, False se for público.
    """
    try:
        # Converte o IP para o formato correto e verifica se é privado
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        # Caso o IP seja inválido (não é um IP), retornamos False
        return False


def count_public_private_ips_with_details(file_path):
    """
    Conta a quantidade de endereços IP públicos e privados, e retorna os 20 IPs públicos mais frequentes
    com seus detalhes (país, host, método, etc.).

    :param file_path: Caminho para o arquivo CSV.
    :return: Contagem de IPs públicos e privados, além dos detalhes dos 20 IPs públicos mais frequentes.
    """
    # Ler o arquivo CSV
    df = pd.read_csv(file_path)

    # Filtrar apenas endereços IPv4 válidos
    df['is_private'] = df['ClientIP'].apply(is_private_ip)

    # Contar IPs privados e públicos
    private_ips_count = df[df['is_private'] == True].shape[0]
    public_ips_count = df[df['is_private'] == False].shape[0]

    # Filtrar IPs públicos
    public_ips_df = df[df['is_private'] == False]

    # Contar os 20 IPs públicos mais frequentes
    top_20_public_ips = public_ips_df['ClientIP'].value_counts().head(20).index.tolist()

    # Filtrar os detalhes para os 20 IPs públicos mais frequentes
    top_20_details = public_ips_df[public_ips_df['ClientIP'].isin(top_20_public_ips)][
        ['ClientIP', 'ClientCountry', 'ClientRequestHost', 'ClientRequestMethod', 'ClientDeviceType',
         'ClientRequestPath', 'ClientRequestReferer']
    ]

    return private_ips_count, public_ips_count, top_20_details


# Exemplo de uso
file_path = 'test-dataset.csv'  # Altere para o caminho correto
private_ips_count, public_ips_count, top_20_details = count_public_private_ips_with_details(file_path)

# Exibir resultados
print(f"Quantidade de IPs privados: {private_ips_count}")
print(f"Quantidade de IPs públicos: {public_ips_count}")
print("\nDetalhes dos 20 IPs públicos mais frequentes:")
print(top_20_details)
