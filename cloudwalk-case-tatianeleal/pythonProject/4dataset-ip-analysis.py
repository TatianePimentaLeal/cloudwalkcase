import pandas as pd
import ipaddress


def is_private_ip(ip):
    try:
        # Conversão do IP para o formato correto, verificação do tipo (privado)
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        # Caso o IP seja inválido (não é um IP), retorna False
        return False


def count_public_private_ips_with_details(file_path):
    df = pd.read_csv(file_path)

    # Filtragem dos endereços IPv4 válidos
    df['is_private'] = df['ClientIP'].apply(is_private_ip)

    # Contagem dos IPs privados e públicos
    private_ips_count = df[df['is_private'] == True].shape[0]
    public_ips_count = df[df['is_private'] == False].shape[0]

    public_ips_df = df[df['is_private'] == False]

    # Contagem dos 20 IPs públicos mais frequentes
    top_20_public_ips = public_ips_df['ClientIP'].value_counts().head(20).index.tolist()

    top_20_details = public_ips_df[public_ips_df['ClientIP'].isin(top_20_public_ips)][
        ['ClientIP', 'ClientCountry', 'ClientRequestHost', 'ClientRequestMethod', 'ClientDeviceType',
         'ClientRequestPath', 'ClientRequestReferer']
    ]

    return private_ips_count, public_ips_count, top_20_details

file_path = 'test-dataset.csv'
private_ips_count, public_ips_count, top_20_details = count_public_private_ips_with_details(file_path)

print(f"Quantidade de IPs privados: {private_ips_count}")
print(f"Quantidade de IPs públicos: {public_ips_count}")
print("\nDetalhes dos 20 IPs públicos mais frequentes:")
print(top_20_details)



