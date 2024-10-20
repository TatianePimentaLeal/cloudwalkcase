import pandas as pd

file_path = 'test-dataset.csv'
df = pd.read_csv(file_path)

patterns = {}

# Contagem das ocorrências de valores específicos nas colunas escolhidas

# Top 10 IPs mais frequentes
patterns['ClientIP'] = df['ClientIP'].value_counts().head(10)

# Top 10 Hosts mais acessados
patterns['ClientRequestHost'] = df['ClientRequestHost'].value_counts().head(10)

# Top 10 URIs mais solicitados
patterns['ClientRequestURI'] = df['ClientRequestURI'].value_counts().head(10)

# Distribuição por tipo de dispositivo
patterns['ClientDeviceType'] = df['ClientDeviceType'].value_counts()

# Distribuição por país
patterns['ClientCountry'] = df['ClientCountry'].value_counts()

# Padrões extraídos
print(patterns)


