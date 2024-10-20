import pandas as pd

def analyze_suspicious_accesses(df):
    """
    Analisar se os acessos ao referer 'hernandez.com' seguem um padrão de brute force ou comportamento suspeito.

    :param df: DataFrame com os dados filtrados contendo 'hernandez.com' no referer.
    :return: Detalhamento das atividades suspeitas.
    """
    # Agrupar pelos IPs e contar a quantidade de acessos por IP
    ip_counts = df['ClientIP'].value_counts()

    # Exibir os IPs com mais acessos ao domínio 'hernandez.com'
    print("IP com mais acessos ao referer 'hernandez.com':")
    print(ip_counts.head(10))  # Top 10 IPs que mais acessaram

    # Verificar se estão tentando acessar URLs sensíveis (como login, autenticação)
    suspicious_paths = df['ClientRequestPath'].value_counts().head(10)

    print("\nPrincipais URLs acessadas pelos IPs:")
    print(suspicious_paths)

    # Contagem dos métodos de requisição HTTP (GET, POST, etc.)
    request_methods = df['ClientRequestMethod'].value_counts()

    print("\nMétodos de requisição usados:")
    print(request_methods)

    # Verificar se há um padrão de repetição ao longo do tempo (se houver timestamps disponíveis)
    if 'ClientRequestTimestamp' in df.columns:
        df['ClientRequestTimestamp'] = pd.to_datetime(df['ClientRequestTimestamp'])
        time_analysis = df.groupby(df['ClientRequestTimestamp'].dt.date).size()

        print("\nAcessos por data:")
        print(time_analysis)
    else:
        print("\nTimestamp de requisições não disponível para análise temporal.")

# Carregar os dados em um DataFrame
data = pd.read_csv('test-dataset.csv')  # Substitua pelo caminho do seu arquivo
hernandez_accesses = data[data['ClientRequestReferer'].str.contains('hernandez.com')]  # Filtrando os acessos

# Chamar a função para analisar os acessos suspeitos
analyze_suspicious_accesses(hernandez_accesses)
