# Case CloudWalk

## **2 Desenvolvimento e Implementação**

### 2.1 Análise do arquivo

Primeiramente, era importante ter um panorama mais claro da massa de dados do arquivo CSV, assim, utilizei um pequeno código em Python para iniciar a análise:

```python
# Verificação geral do documento
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

---

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

''

---

Os dados foram organizados e valores que aparecem mais de 3 vezes foram identificados. Desta forma, segui o caminho de extração de padrões específicos com base em colunas de interesse. Por exemplo, padrões de acessos repetidos por IP, Host ou outra categoria específica. 

O resultado da análise foi o seguinte:

- Para análise dos padões específicos, foi dado enfoque nas seguintes colunas para a extração de padrões mais consistentes
1. **ClientIP**: Para ver se algum endereço IP faz múltiplas requisições.
2. **ClientRequestHost**: Para identificar se algum host recebe acessos frequentes.
3. **ClientRequestURI**: Para identificar se algum URI específico é mais solicitado.
4. **ClientDeviceType**: Para analisar o tipo de dispositivo mais usado.
5. **ClientCountry**: Para verificar se há um país que realiza mais requisições.

Em seguida, os dados dessas colunas foram verificados com mais especificidade resultando no seguinte panorama:

1. **ClientIP (Top 10 IPs mais frequentes)**:
   
   ![cloudwalkcase/cloudwalk-case-images/Img1_ClientIP.jpg at main · TatianePimentaLeal/cloudwalkcase · GitHub](https://github.com/TatianePimentaLeal/cloudwalkcase/blob/main/cloudwalk-case-images/Img1_ClientIP.jpg)
   
   *Imagem 1. Gráfico de IPs mais frequentes*

2. **ClientRequestURI (Top 10 URIs mais solicitados)**:
   
   ![cloudwalkcase/cloudwalk-case-images/Img2_ClientRequestURI.jpg at 2fd4e1c8302852bffd4e2864470fbf99651aedb2 · TatianePimentaLeal/cloudwalkcase · GitHub](https://github.com/TatianePimentaLeal/cloudwalkcase/blob/2fd4e1c8302852bffd4e2864470fbf99651aedb2/cloudwalk-case-images/Img2_ClientRequestURI.jpg)
   
   *Imagem 2. Gráfico de URIs mais solicitados*

3. **ClientDeviceType (Distribuição por tipo de dispositivo)**:
   
   ![cloudwalkcase/cloudwalk-case-images/Img3_ClientDeviceType.jpg at main · TatianePimentaLeal/cloudwalkcase · GitHub](https://github.com/TatianePimentaLeal/cloudwalkcase/blob/main/cloudwalk-case-images/Img3_ClientDeviceType.jpg)
   
   *Imagem 3. Gráfico distribuição de dispositivos*

4. **ClientCountry (Distribuição por país)**:
   
   ![cloudwalkcase/cloudwalk-case-images/Img4_ClientCountry.jpg at main · TatianePimentaLeal/cloudwalkcase · GitHub](https://github.com/TatianePimentaLeal/cloudwalkcase/blob/main/cloudwalk-case-images/Img4_ClientCountry.jpg)

       * Imagem 4. Gráfico de países com maior incidência*



Esses padrões mostram que os **IPs e URIs** indicam acessos repetidos de certas fontes, e a maior parte do tráfego vem da **Índia e dos EUA**, com uma predominância de **dispositivos desktop** - que podem indicar bots zumbis.

Solicitei o código da análise ao GPT para que eu pudesse revisá-lo e rodá-lo para efetuar a comprovação da ediciência da análise. Após o ajuste do path do arquivo CSV, rodei o bloco de código e obtive o retorno dos dados:

```python
import pandas as pd

file_path = 'test-dataset.csv'
df = pd.read_csv(file_path)

patterns = {}

# Contagem das ocorrências de valores específicos nas colunas escolhidas
patterns['ClientIP'] = df['ClientIP'].value_counts().head(10)
patterns['ClientRequestHost'] = df['ClientRequestHost'].value_counts().head(10)
patterns['ClientRequestURI'] = df['ClientRequestURI'].value_counts().head(10)
patterns['ClientDeviceType'] = df['ClientDeviceType'].value_counts()
patterns['ClientCountry'] = df['ClientCountry'].value_counts()

print(patterns)
```

O código acima efetua a contagem dos top 10 ligados aos elementos mais importantes da tabela em se tratando da análise de tráfego, permitindo um overview dos elementos maior incidência ao longo do dataset, retornando padrões de acordo com o que foi previamente estipulado.

O resultado trouxe o seguinte panorama de dados, previamente colocados em forma de gráfico pela avaliação preliminar das informações:

```python
\\pythonProject\\dataset-analysis.py 

#
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

#
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

#
Name: count, dtype: int64, 'ClientDeviceType': ClientDeviceType
desktop    14720
tablet     11033
mobile      4247

#
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

Atestadas as informações acima, foi possível comprovar a funcionalidade do código e a análise preliminar.

---

### 

### 2.2 Levantamento de anomalias e atividades suspeitas

Com os dados mais claros e uma pré-análise do panorama de usuários, foi iniciada a fase de levantameno de acessos suspeitos ou anômalos, com a verificação de padrões nos dados.

Novamente com o Python e utilizado novamente a biblioteca Pandas, iniciei o escaneamento de IPs e Portas do arquivo, uma vez que são ótimos indicativos de atividades maliciosas:

```python
import pandas as pd

def analyze_suspicious_activity(file_path, port_threshold=100, ip_threshold=100):

    # Análise das atividades suspeitas (verificação de portas e IPs com alta frequência).

    df = pd.read_csv(file_path)

    ip_counts = df['ClientIP'].value_counts()
    port_counts = df['ClientSrcPort'].value_counts()

    suspicious_ips = ip_counts[ip_counts > ip_threshold]
    suspicious_ports = port_counts[port_counts > port_threshold]

    return suspicious_ips, suspicious_ports

file_path = 'test-dataset.csv'
suspicious_ips, suspicious_ports = analyze_suspicious_activity(file_path)

print("IPs suspeitos:")
print(suspicious_ips)

print("\nPortas suspeitas:")
print(suspicious_ports)
```

Neste script temos a análise das suspeitas de ataque e tentativa de invação da rede. Foram utilizadas uma variável para determinar o limite para se considerar uma porta como suspeita (quantidade de acessos), uma variável para limitar a consideração de um IP suspeito (quantidade de acessos) e o retorno de *DataFrames* de IPs e portas suspeitos.

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

Portas suspeitas:
Series([], Name: count, dtype: int64)
```

Dados os resultados dos IPs, solicitei ao GPT4 que me ajudasse a criar uma função para levantar os IPs privados (por serem mais seguros e rodarem dentro de LANs de empresas) e os públicos (que poderiam estar ligados à pessoas externas e provaveis invasores).
A função resultante trouxe a divisão entre IPs públicos e privados, verificando os 20 IPs públicos mais frequentes, visto que neles se concentram a maioria dos ataques :

```python
import pandas as pd
import ipaddress

def is_private_ip(ip):
    """
    Verifica se um endereço IP é privado ou público.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def count_public_private_ips_with_details(file_path):

    df = pd.read_csv(file_path)

    df['is_private'] = df['ClientIP'].apply(is_private_ip)

    private_ips_count = df[df['is_private'] == True].shape[0]
    public_ips_count = df[df['is_private'] == False].shape[0]

    public_ips_df = df[df['is_private'] == False]

    top_20_public_ips = public_ips_df['ClientIP'].value_counts().head(20).index.tolist()

    top_20_details = public_ips_df[public_ips_df['ClientIP'].isin(top_20_public_ips)][
        ['ClientIP', 'ClientCountry', 'ClientRequestHost', 'ClientRequestMethod', 'ClientDeviceType', 'ClientRequestPath', 'ClientRequestReferer']
    ]

    return private_ips_count, public_ips_count, top_20_details

file_path = 'test-dataset.csv'
private_ips_count, public_ips_count, top_20_details = count_public_private_ips_with_details(file_path)

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

Adicionalmente, de acordo com o framework Mitre Att&ck, em uma busca preliminar, confirmava as suspeitas de tentativas de obtenção de acesso:

![cloudwalkcase/cloudwalk-case-images/Img5_mitre-attack-search.png at main · TatianePimentaLeal/cloudwalkcase · GitHub](https://github.com/TatianePimentaLeal/cloudwalkcase/blob/main/cloudwalk-case-images/Img5_mitre-attack-search.png)

**Imagem 5.** Buscas no Mitre Att&ck Navigator - padrões de ataque para Network

![cloudwalkcase/cloudwalk-case-images/Img6_mitre-attack-search.png at main · TatianePimentaLeal/cloudwalkcase · GitHub](https://github.com/TatianePimentaLeal/cloudwalkcase/blob/main/cloudwalk-case-images/Img6_mitre-attack-search.png)

**Imagem 6.** Buscas no Mitre Att&ck Navigator - Data sources (Network)

---

### 

### 2.3 Resposta e Detecção de Incidente (Incident Detection and Response - IDR) e Implementação de Políticas de Segurança

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

data = pd.read_csv('test-dataset.csv')

# Parâmetros para detecção de atividades suspeitas
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

# Gerar alertas
alerts = generate_alerts(data)
for alert in alerts:
    print(alert)
```

Através do script acima, foram configurados parâmetros para a configuração de limite (threshold) de:

- Requisições de ummesmo IP;

- Retorno de países suspeitos;

- Parâmetros de portas que são incomuns para acesso web.

Depois, revisando o código com o GPT4, alterei o script para monitorar os logs de rede, detectar padrões suspeito de acordo com diretivas internas aplicadas a ele e, assim, gerar alertas por email com os dados dos eventos.

```python
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
        server.starttls()  
        server.login(login, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print(f"E-mail enviado para {to_email}")
    except Exception as e:
        print(f"Falha no envio do e-mail: {e}")

# Parâmetros de envio de e-mail
to_email = "idr.quarantine@exemplo.com"
from_email = "sec.analyst@exemplo.com"
smtp_server = "smtp.gmail.com" 
smtp_port = 587 
login = "sec.analyst@exemplo.com"  
password = "senha" 

data = pd.read_csv('test-dataset.csv')

alerts = generate_alerts(data)

# Enviar os alertas por e-mail
send_email(alerts, to_email, from_email, smtp_server, smtp_port, login, password)
```

Por fim, para bloqueio de acessos de IPs suspeitos, seria necessária a integraão com sistemas de proteção como Firewall, um Sistema de Prevenção de Intrusões (IPS, ou em inglês Intrusion Prevention System - IPS) ou ainda servidores proxy/reverse proxy.

Para fins de aplicação ao case, escolhi a adição de uma funcionalidade de bloqueio de IPs diretamente com Python e o iptabes para sistemas Linux:

```python
import os

def block_ip(ip):
    command = f"sudo iptables -A INPUT -s {ip} -j DROP"
    os.system(command)
    print(f"IP {ip} bloqueado.")

def block_suspicious_ips(df):
    high_volume_ips = detect_high_volume_ips(df)
    for ip in high_volume_ips.index:
        block_ip(ip)

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

    alert_message = "\\n".join(alerts)
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

def block_ip(ip):
    command = f"sudo iptables -A INPUT -s {ip} -j DROP"
    os.system(command)
    print(f"IP {ip} bloqueado.")

def block_suspicious_ips(df):
    high_volume_ips = detect_high_volume_ips(df)
    for ip in high_volume_ips.index:
        block_ip(ip)

to_email = "idr.quarantine@exemplo.com"
from_email = "sec.analyst@exemplo.com"
smtp_server = "smtp.gmail.com"
smtp_port = 587 
login = "sec.analyst@exemplo.com"
password = "senha" 

data = pd.read_csv('test-dataset.csv')

alerts = generate_alerts(data)

send_email(alerts, to_email, from_email, smtp_server, smtp_port, login, password)

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

---

## 3 Conclusão e Fechamento

Em conclusão à análise do case da CloudWalk, através do dataset fornecido e das solicitações feitas pelo time de avaliação, foi possível compreender o cerne do desafio verificar as capacidades de análise, pesquisa, persistência e perspicácia do candidato.

O grande volume de dados propiciou que fosse possível a análise de padrões de uma mais profunda, que exigia:

. o entendimento preliminar do que consistia o conjunto de dados (dados de tráfego de rede);

. suas informações internal (colunas e dados gerais);

. o que poderia haver de errado com os dados (análise).

Por isso, iniciei o estudo com o entendimento dos dados, refinando alguns padrões, repetições e comportamentos suspeitos de acordo com frameworks e guidelines como o **Mitre Att&ck **(que apresenta táticas, técnicas e procedimentos de ataque), **NIST 800-53** e **ISO 27001 **(que apresenta informações de controles de acesso) com a ajuda do GPT4 e do Python para agilizar a análise.

Com a impossibilidade de utilização de ferramentas pagas de SIEM, mas com o entendimento de que havia padrões suspeitos nos dados colhidos e analisados, concebi um script em Python que pudesse rodar em Linux e que propiciasse a aplicação de uma política balisada pelos guideline supracitados, e que premitisse o envio de alertas com os IPs suspeitos, para uma análise mais específica do time de analistas, assim como o bloqueio do IP até a verificação da idoneidade do IP.

Pela natureza do comportamento observado no dataset e, considerando o comportamento em face ao Mitre Att&ck, o cenário configura um possível ataque de força bruta ao Infinite Pay ([https://www.infinitepay.io/](https://www.infinitepay.io/)), plataforma de pagamentos da CloudWalk, o que poderia ser desastroso em vários quesitos: danos materials no caso de manipulação de dados de clientes ou reputacionais em caso de sucesso na invação.

A utilização de AI com o GPT4 para suporte na análise dos dados e criação de códigos rápidos para tested e incrementos, bem como o uso do Gemini e Copilot para a confirmação e informações como o WHOIS.

O monitoramento do tráfego de rede é de extrema importância para que os clientes, a platform e a empresa CloudWalk fiquem seguros contra invasores.
