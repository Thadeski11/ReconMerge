# ReconMerge
ReconMerge é uma ferramenta de linha de comando em Python projetada para realizar a enumeração de subdomínios de forma eficiente.A ferramenta combina métodos ativos (força bruta com DNS assíncrono) e passivos (consulta a fontes públicas de dados) para mapear a superfície de ataque de um domínio alvo.

## Funcionalidades
Enumeração Ativa (Força Bruta Asíncrona):
* Lê uma wordlist (-w/--wordlist) fornecida pelo usuário, gerando uma lista de subdomínios potenciais (ex.: palavra.dominio.com).
* Utiliza a biblioteca asyncio para verificar se esses subdomínios se resolvem para um endereço IP válido através de consultas DNS de forma rápida e concorrente, respeitando um tempo limite (-t/--time).


Enumeração Passiva (Busca em Fontes Públicas):
* Quando a flag --public é ativada, a ferramenta busca subdomínios em fontes e APIs públicas, sem depender de uma wordlist.
* As fontes de busca incluem: crt.sh, HackerTarget, VirusTotal (requer APIKEY), e Chaos Project Discovery (requer APIKEY).
* Esta abordagem é útil para encontrar subdomínios já conhecidos e documentados publicamente.


Saída e Geração de Relatórios:
* Permite salvar todos os resultados de subdomínios encontrados em um arquivo de texto especificado pelo usuário (-o/--output).


## Instalação
1. Clonar o Repositório

Use o ```git``` para baixar o código-fonte para sua máquina local:

```python
git clone https://github.com/Thadeski11/ReconMerge.git
cd ReconMerge
```
2. Instalar Dependências

O ReconMerge requer algumas bibliotecas externas. Use o ```pip``` para instalar todas as dependências listadas no ```requirements.txt```:

```python
# Recomendado: Crie um ambiente virtual
python3 -m venv venv
source venv/bin/activate  # No Windows, use 'venv\Scripts\activate'

# Instala as dependências
pip install -r requirements.txt
```
## Exemplos de Utilização
Cenário 1: Modo Ativo (Força Bruta Rápida)
Este comando utiliza uma lista de palavras local (```big_subdomains_wordlist.txt```) para testar subdomínios, define um timeout de 60 consultas por segundo, e salva todos os subdomínios encontrados em ```subs_ativos.txt```.
```python
python reconmerge.py -d dominioalvo.com -w big_subdomains_wordlist.txt -t 60 -o subs_ativos.txt
```

Cenário 2: Modo Passivo (OSINT Completo)
Este comando ativa o modo de busca pública (```--public```) e utiliza chaves de API para fazer consultas a todas as fontes disponíveis, gerando um relatório consolidado. **As chaves não são obrigatórias para realizar essa consulta.**
```python
python reconmerge.py -d alvo.com --public -vt SUA_CHAVE_VIRUSTOTAL_AQUI -ch SUA_CHAVE_CHAOS_AQUI -o subs_publicos.txt
```
