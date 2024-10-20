# Case CloudWalk

## **2 Desenvolvimento e Implementação**

#### 2.1 Análise do arquivo

Primeiramente, era ter um panorama mais claro da massa de dados do arquivo CSV, assim, utilizei um pequeno código em Python para iniciar a análise:

```python
with open("test-dataset.csv","r") as file:
    file_teste = file.read()
dataset = file_teste.split()
print(dataset)
```

Assim pude iniciar a visualização dos dados e ter uma ideia das colunas e conteúdo.

Em seguida, montei o seguinte prompt no GPT3.5:

> Crie um algoritmo em Python que:
> 
> 1. Leia o arquivo CSV anexo
> 2. Organize os dados de acordo com os nomes das colunas
> 3. Conte o número de vezes em que dados aparecerem mais de 3 vezes na tabela e printe a quantidade de vezes
> 4. Extraia padrões de acordo com os itens das colunas do documento

E recebendo o seguinte retorno:

"O arquivo CSV contém as seguintes colunas:

1. `ClientIP`
2. `ClientRequestHost`
3. `ClientRequestMethod`
4. `ClientRequestURI`
5. `EdgeStartTimestamp`
6. `ZoneName`
7. `ClientASN`
8. `ClientCountry`
9. `ClientDeviceType`
10. `ClientSrcPort`
11. `ClientRequestBytes`
12. `ClientRequestPath`
13. `ClientRequestReferer`
14. `ClientRequestScheme`
15. `ClientRequestUserAgent`

Agora, organizarei os dados e contarei quantas vezes certos dados aparecem mais de 3 vezes, além de identificar padrões relevantes com base nesses dados.

Os dados foram organizados e valores que aparecem mais de 3 vezes foram identificados. Contudo, devido à grande quantidade de informações, o resultado foi truncado.

Posso gerar uma análise mais refinada ou extrair padrões específicos com base em colunas que te interessam. Por exemplo, padrões de acessos repetidos por IP, Host ou outra categoria específica. Como gostaria de proceder?''

Optando por seguir a segunda alternativa, inicialmente, o resultado da análise foi o seguinte:

---

Para extrair padrões específicos, vou focar nas seguintes colunas para identificar ocorrências repetidas que podem indicar padrões:

1. **ClientIP**: Para ver se algum endereço IP faz múltiplas requisições.
2. **ClientRequestHost**: Para identificar se algum host recebe acessos frequentes.
3. **ClientRequestURI**: Para identificar se algum URI específico é mais solicitado.
4. **ClientDeviceType**: Para analisar o tipo de dispositivo mais usado.
5. **ClientCountry**: Para verificar se há um país que realiza mais requisições.

Vou analisar os dados dessas colunas e extrair padrões de frequências.

Aqui estão os padrões extraídos das colunas mais relevantes do dataset:

1. **ClientIP (Top 10 IPs mais frequentes)**:
   
   - 53.153.77.110: 156 requisições
   - 208.150.99.181: 119 requisições
   - 125.227.246.131: 116 requisições
   - 185.24.37.122: 115 requisições
   - 209.158.28.49: 114 requisições
   - 129.53.13.62: 114 requisições
   - 222.30.33.183: 114 requisições
   - 159.168.200.38: 112 requisições
   - 21.166.16.150: 112 requisições
   - 192.19.249.147: 112 requisições

2. **ClientRequestHost (Top 10 Hosts mais acessados)**:
   
   - porter.biz: 13.232 acessos
   - acosta.com: 4.815 acessos
   - joseph.org: 2.262 acessos
   - brown.net: 2.088 acessos
   - pearson.com: 1.621 acessos
   - walters-thompson.com: 1.142 acessos
   - marshall-odonnell.net: 917 acessos
   - moore.com: 827 acessos
   - jackson.com: 569 acessos
   - kirby.info: 404 acessos

3. **ClientRequestURI (Top 10 URIs mais solicitados)**:
   
   - /want/think/event: 2.944 requisições
   - /want/media/street: 1.804 requisições
   - /sound/explain/suggest: 735 requisições
   - /serious/she/drive: 715 requisições
   - /about/partner/determine: 711 requisições
   - /middle: 676 requisições
   - /authority: 649 requisições
   - /piece/statement/common/Mrs: 612 requisições
   - /whom/ever/box/nothing: 593 requisições
   - /personal/blood/none/force: 513 requisições

4. **ClientDeviceType (Distribuição por tipo de dispositivo)**:
   
   - desktop: 14.720 acessos
   - tablet: 11.033 acessos
   - mobile: 4.247 acessos

5. **ClientCountry (Distribuição por país)**:
   
   - Índia (in): 18.372 requisições
   - Estados Unidos (us): 11.481 requisições
   - Brasil (br): 37 requisições
   - Japão (jp): 34 requisições
   - Reino Unido (gb): 26 requisições

Esses padrões mostram que o **host mais acessado** é "porter.biz", os **IPs e URIs** indicam acessos repetidos de certas fontes, e a maior parte do tráfego vem da **Índia e dos EUA**, com uma predominância de **dispositivos desktop**.

---

Solicitei o código da análise ao GPT para que eu pudesse revisá-lo e rodá-lo para efetuar a comprovação da ediciência da análise. Após o ajuste do path do arquivo CSV, rodei o bloco de código e obtive o retorno dos dados:

```python
import pandas as pd

'''
with open("test-dataset.csv","r") as file:
    file_teste = file.read()
dataset = file_teste.split()
print(dataset)
'''

file_path = 'test-dataset.csv'
df = pd.read_csv(file_path)

# Dicionário para armazenar os padrões extraídos
patterns = {}

# Contar as ocorrências de valores específicos nas colunas escolhidas

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

# Exibir os padrões extraídos
print(patterns)
```

Resultado:

```python
\\pythonProject\\dataset-analysis.py 
{'ClientIP': ClientIP
53.153.77.110      156
208.150.99.181     119
125.227.246.131    116
185.24.37.122      115
209.158.28.49      114
222.30.33.183      114
129.53.13.62       114
192.19.249.147     112
21.166.16.150      112
159.168.200.38     112
Name: count, dtype: int64, 'ClientRequestHost': ClientRequestHost
porter.biz               13232
acosta.com                4815
joseph.org                2262
brown.net                 2088
pearson.com               1621
walters-thompson.com      1142
marshall-odonnell.net      917
moore.com                  827
jackson.com                569
kirby.info                 404
Name: count, dtype: int64, 'ClientRequestURI': ClientRequestURI
/want/think/event              2944
/want/media/street             1804
/sound/explain/suggest          735
/serious/she/drive              715
/about/partner/determine        711
/middle                         676
/authority                      649
/piece/statement/common/Mrs     612
/whom/ever/box/nothing          593
/personal/blood/none/force      513
Name: count, dtype: int64, 'ClientDeviceType': ClientDeviceType
desktop    14720
tablet     11033
mobile      4247
Name: count, dtype: int64, 'ClientCountry': ClientCountry
in    18372
us    11481
br       37
jp       34
gb       26
fr       20
cn       10
de        8
au        8
ca        4
Name: count, dtype: int64}
```

Dado o retorno, foi possível comprovar a funcionalidade do código e a análise dos dados preliminares.

---

#### 2.2 Levantamento de anomalias e atividades suspeitas

Com os dados mais claros e uma pré-análise do panorama de usuários, foi iniciada a fase de levantameno de acessos suspeitos ou anômalos, com a verificação de padrões nos dados.

Novamente com o Python e utilizado novamente a biblioteca Pandas, iniciei o escaneamento de IPs e Portas do arquivo, uma vez que são ótimos indicativos de atividades maliciosas:

```python
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

print("\\nPortas suspeitas:")
print(suspicious_ports)
```

Através da análise, não foram encontradas portas que, usualmente, trazem sinal de alerta, mas pelos padrões dos IPs, alguns execeram em muito o threshold estabelecido no código como forma de balizar os acessos:

```python
IPs suspeitos:
ClientIP
53.153.77.110      156
208.150.99.181     119
125.227.246.131    116
185.24.37.122      115
209.158.28.49      114
222.30.33.183      114
129.53.13.62       114
192.19.249.147     112
21.166.16.150      112
159.168.200.38     112
195.171.155.166    110
11.148.137.128     109
157.226.241.234    108
13.235.167.220     107
88.40.53.243       106
26.158.117.152     106
117.200.193.5      105
56.172.84.231      105
132.107.158.218    105
172.73.227.140     105
26.249.70.42       104
57.112.34.158      104
98.197.20.168      103
159.147.102.107    103
23.159.246.188     103
7.113.8.157        103
221.112.50.103     102
133.157.216.48     102
218.83.247.217     101
Name: count, dtype: int64

Portas suspeitas:
Series([], Name: count, dtype: int64)
```

Dados os resultados dos IPs, solicitei ao GPT4 que me ajudasse a criar uma função para levantar os IPs privados (por serem mais seguros e rodarem dentro de LANs de empresas) e os públicos (que poderiam estar ligados à pessoas externas e provaveis invasores).
A função resultante foi a seguinte:

```python
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
        ['ClientIP', 'ClientCountry', 'ClientRequestHost', 'ClientRequestMethod', 'ClientDeviceType', 'ClientRequestPath', 'ClientRequestReferer']
    ]

    return private_ips_count, public_ips_count, top_20_details

# Exemplo de uso
file_path = 'caminho/para/seu/arquivo.csv'  # Altere para o caminho correto
private_ips_count, public_ips_count, top_20_details = count_public_private_ips_with_details(file_path)

# Exibir resultados
print(f"Quantidade de IPs privados: {private_ips_count}")
print(f"Quantidade de IPs públicos: {public_ips_count}")
print("\\nDetalhes dos 20 IPs públicos mais frequentes:")
print(top_20_details) 
```

E ela resultou em uma suspeita devido ao padrão de IPs mostrado anteriormente, a quantidade de acessos e os "ClientRequestPath"do usuário:

```python
Quantidade de IPs privados: 229
Quantidade de IPs públicos: 29771

Detalhes dos 20 IPs públicos mais frequentes:
              ClientIP  ...       ClientRequestReferer
18      26.158.117.152  ...  <http://www.hernandez.com/>
37     157.226.241.234  ...  <http://www.hernandez.com/>
141      209.158.28.49  ...  <http://www.hernandez.com/>
145     13.235.167.220  ...  <http://www.hernandez.com/>
190     159.168.200.38  ...  <http://www.hernandez.com/>
...                ...  ...                        ...
29360    21.166.16.150  ...  <http://www.hernandez.com/>
29361   26.158.117.152  ...  <http://www.hernandez.com/>
29370   192.19.249.147  ...  <http://www.hernandez.com/>
29374     129.53.13.62  ...  <http://www.hernandez.com/>
29375  157.226.241.234  ...  <http://www.hernandez.com/>

[2250 rows x 7 columns]
```

Pela recomendação do Copilot, efetuei uma busca **WHOIS ** no site https://www.whois.com/ e pude corroborar que os IPs retornados na busca estaam espalhados pelo mundo e possuem tags de  "OrgAbuseEmail" o que, de acordo com a International Leal Technology Association e com indicadores de comprometimento (indicatos or compromise or IOC) , são um indício de ameaça, mais precisamente ao verificar os dados, até mesmo de brute force attack.

#### 2.3 Resposta e Detecção de Incidente (Incident Detection and Response - IDR) e Implementação de Políticas de Segurança

Como não estamos utilizando ferramentas pagas como o Splunk, Fortinet ou Google Chronicle, as proposições de solução para resposta e detecção de incidente serão propostas como scripts.

Como verificado na análise prévia do dataset com Python, foi possível apurar que o dataset contém indícios de movimentações suspeitas:

- IPs que aparecem muitas vezes em um curto período de tempo (indicativo de possíveis ataques de força bruta ou DoS);
- Países ou ASN fora do esperado (pode sugerir atividade maliciosa originada de locais incomuns)
- Requisições HTTP suspeitas (URLs incomuns ou com grandes volumes de dados)
- Portas de origem fora do padrão (pode sugerir tentativas de evasão ou comportamento incomum ou indicativo de anomalia).

Assim, foi concebido o script abaixo, com o auxílio do GPT4, para apurar:

- o volume de requisições
- países de origem das requisições
- uso de portas incomum

```python
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
```

Depois, revisando o código com o GPT4, alterei o script para monitorar os logs de rede, detectar padrões suspeito de acordo com diretivas internas aplicadas a ele e, assim, gerar alertas por email com os dados dos eventos.

```python
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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
    alert_message = "\\n".join(alerts)
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
```

Por fim, para bloqueio de acessos de IPs suspeitos, seria necessária a integraão com sistemas de proteção como Firewall, um Sistema de Prevenção de Intrusões (IPS, ou em inglês Intrusion Prevention System - IPS) ou ainda servidores proxy/reverse proxy.

Para fins de aplicação ao case, escolhi a adição de uma funcionalidade de bloqueio de IPs diretamente com Python e o iptabes para sistemas Linux:

```python
import os

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

# Chamar block_suspicious_ips para bloquear IPs suspeitos
block_suspicious_ips(data)
```

Este bloco de código, quando agregado ao script de alerta, permite a ação completa do IDR compreendendo:

- a detecção de ocorrências suspeitas na rede;

- o envio de alertas das suspeitas por email para análise;

- o bloqueio de IPs suspeitos com atividades maliciosas via iptables do Linux.

```python
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
    alert_message = "\\n".join(alerts)
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
```

Retorno do script de IDR acima:

```python
\\pythonProject\\dataset-full-idr-integration.py 

# Bloqueio dos IPs suspeitos
IP 208.150.99.181 bloqueado.
IP 125.227.246.131 bloqueado.
IP 185.24.37.122 bloqueado.
IP 209.158.28.49 bloqueado.
IP 222.30.33.183 bloqueado.
IP 129.53.13.62 bloqueado.
```

3 Conclusão e Fechamento
