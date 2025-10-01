import argparse
import socket
import time
import asyncio
import dns.asyncresolver
from pycrtsh import Crtsh
import requests

parser = argparse.ArgumentParser(prog="ReconMerge", description="")
parser.add_argument("-d", "--domain", help="Passar o domínio alvo.")
parser.add_argument("-w", "--wordlist", help="Passar a payload de testes.")
parser.add_argument("-t", "--time", type=int, default=10, help="Definir tempo limite por segundo")
parser.add_argument("-o", "--output", help="Salva os resultados em um arquivo de texto.")
parser.add_argument("--public", action="store_true", dest="public", help='''
Ativa a busca de subdomínios por bases públicas.
Algumas fontes requerem chaves de API.
Não é necessário passar argumentos de Wordlist ou Time.''')
parser.add_argument("-vt", "--virustotalkey", help="Passar APIKEY do virustotal (Não Obrigatório)")
parser.add_argument("-ch", "--chaoskey", help="Passar APIKEY da ChaosProjectdiscovery (Não Obrigatório)")
args = parser.parse_args()


async def DNS(subdomain, semaphore):
	async with semaphore:
		try:
			loop = asyncio.get_running_loop()
			dados = await loop.run_in_executor(None, socket.getaddrinfo, subdomain, None, socket.AF_INET)
			addr = dados[2][4][0]
			return subdomain, addr
		except (socket.gaierror, UnicodeError):
			return subdomain, None


async def Main(domain, wordlist, timed=10):
	semaphore = asyncio.Semaphore(timed)

	subdomains = []
	subdomains_done = []

	with open(wordlist, "r") as f:
		for i in f:
			i = i.strip()
			subdomain_test = f"{i}.{domain}"
			subdomains.append(subdomain_test)

	addr = [DNS(subdomain, semaphore) for subdomain in subdomains]
	tasks_done = await asyncio.gather(*addr)
	for subdomain, ip in tasks_done:
		if ip:
			subdomains_done.append(subdomain)

	return subdomains_done


async def run_check_subdomain():
	results_subdomains = await Main(args.domain, args.wordlist, args.time)
	for alive in results_subdomains:
		print(alive)
	return results_subdomains


sub_list = []

def crt(domain):
	try:
		c = Crtsh()
		sub = c.subdomains(domain)
		for subdomains in sub:
			sub_list.append(subdomains)
	except Exception as e:
		print(f"❌ Erro ao consultar crt.sh: Falha de conexão ou erro: {e}")

def hackertarget(domain):
	try:
		url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
		r = requests.get(url, timeout=2)
		for sub in r.text.splitlines():
			if sub and ',' in sub:
				subdomains = sub.split(",")[0].strip()
				sub_list.append(subdomains)
	except requests.exceptions.RequestException as e:
		print(f"❌ Erro ao consultar HackerTarget: Falha de conexão ou timeout: {e}")

def virustotal(domain, apikey):
	try:
		url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={apikey}&domain={domain}"
		r = requests.get(url, timeout=3)
		html = r.text
		subdomains = html.split('"subdomains":[')[1].split(']')[0].replace('"','').replace(',','\n')
		for sub in subdomains.splitlines():
			sub_list.append(sub)
	except requests.exceptions.RequestException:
		print("❌ Erro de Conexão ou Timeout com a VirusTotal.")
	except IndexError:
		print("❌ Falha ao extrair dados da VirusTotal. Chave inválida ou limite excedido.")

def chaos(domain, apikey):
	try:
		url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
		headers = {'Authorization': f'{apikey}', 'Connection': 'close'}
		r = requests.get(url, headers=headers, timeout=3)
		html = r.text
		subdomains = html.split('[')[1].split(']')[0].replace('"', '').replace(',','\n')
		for sub in subdomains.splitlines():
			assembled_subdomains = f"{sub}.{domain}"
			sub_list.append(assembled_subdomains)
	except requests.exceptions.RequestException:
		print("❌ Erro de Conexão ou Timeout com a Chaos API.")
	except IndexError:
		print("❌ Falha ao extrair dados da Chaos API. Chave inválida ou limite excedido.")


def Output(results, file_name):
	if file_name:
		if isinstance(results, list):
			with open(f"{file_name}", "w") as f:
				for i in results:
					f.write(i + "\n")


if args.public:
	crt(args.domain)
	hackertarget(args.domain)
	if args.virustotalkey:
		virustotal(args.domain, args.virustotalkey)
	if args.chaoskey:
		chaos(args.domain, args.chaoskey)
	public_subdomains = sorted(set(sub_list))
	Output(public_subdomains, args.output)
else: 
	results_subdomains = asyncio.run(run_check_subdomain())
	Output(results_subdomains, args.output)
