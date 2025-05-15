from flask import Flask, jsonify, request
import requests
import mymessage_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import binascii
from concurrent.futures import ThreadPoolExecutor
import time
from threading import Semaphore

app = Flask(__name__)

# Configurações de criptografia
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
keys = set()  # Conjunto para armazenar as chaves válidas

# Semáforo para limitar requisições simultâneas
request_semaphore = Semaphore(5)

# Função para gerar UID aleatório de 64 bits
def generate_random_uid_64():
    return random.randint(1, 9_223_372_036_854_775_807)

# Função para criptografar a mensagem
def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

# Função para buscar os tokens (agora com suporte a 100.000 tokens)
def fetch_tokens():
    token_url = "https://tokensff.vercel.app/token"
    all_tokens = []
    max_tokens = 100000
    per_page = 1000  # Quantidade de tokens por requisição
    pages = max_tokens // per_page
    
    try:
        for page in range(pages):
            # Adiciona parâmetro de paginação se o endpoint suportar
            url = f"{token_url}?page={page+1}&per_page={per_page}"
            
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                tokens_data = response.json()
                
                # Verifica se é a nova estrutura (lista de objetos)
                if isinstance(tokens_data, list):
                    for item in tokens_data:
                        if isinstance(item, dict) and 'token' in item:
                            all_tokens.append(item['token'])
                # Verifica se é o formato antigo (dicionário com chave 'tokens')
                elif isinstance(tokens_data, dict) and 'tokens' in tokens_data:
                    all_tokens.extend(tokens_data['tokens'])
                
                print(f"[DEBUG] Página {page+1}: {len(tokens_data)} tokens recebidos (Total: {len(all_tokens)})")
                
                # Interrompe se já atingiu o máximo necessário
                if len(all_tokens) >= max_tokens:
                    break
                
                # Pequeno delay entre requisições para evitar sobrecarga
                time.sleep(0.5)
            else:
                print(f"[ERRO] Falha ao buscar tokens na página {page+1}. Status: {response.status_code}")
        
        # Limita ao número máximo desejado
        all_tokens = all_tokens[:max_tokens]
        print(f"[DEBUG] Tokens recebidos no total: {len(all_tokens)}")
        
        if not all_tokens:
            print("[ERRO] Nenhum token válido encontrado")
            return []
        
        return all_tokens
    except Exception as e:
        print(f"[ERRO] Exceção ao buscar tokens: {str(e)}")
        return []

# Função para enviar requisições com a mensagem
def send_request(token, hex_encrypted_data):
    with request_semaphore:
        url = "https://client.us.freefiremobile.com/RequestAddingFriend"
        payload = bytes.fromhex(hex_encrypted_data)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'Authorization': f"Bearer {token}",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB48"
        }

        try:
            # Adiciona um pequeno delay para evitar rate limiting
            time.sleep(0.3)
            
            response = requests.post(url, data=payload, headers=headers, timeout=10)
            
            # Log detalhado para diagnóstico
            log_msg = f"Token: {token[:10]}... Status: {response.status_code}"
            if response.status_code != 200:
                log_msg += f" | Response: {response.text[:100]}"
            print(log_msg)
            
            return response.status_code == 200
        except Exception as e:
            print(f"[ERRO] Com token {token[:10]}...: {str(e)}")
            return False

# Adicionar uma nova chave
@app.route('/make_key', methods=['GET'])
def make_key():
    key = request.args.get('key')
    if not key:
        return jsonify({"error": "Parâmetro 'key' ausente"}), 400
    keys.add(key)
    return jsonify({"message": f"CHAVE '{key}' ADICIONADA COM SUCESSO"}), 200

# Remover uma chave existente
@app.route('/del_key', methods=['GET'])
def del_key():
    key = request.args.get('key')
    if not key:
        return jsonify({"error": "Parâmetro 'key' ausente"}), 400
    if key in keys:
        keys.remove(key)
        return jsonify({"message": f"CHAVE '{key}' REMOVIDA COM SUCESSO"}), 200
    else:
        return jsonify({"error": f"Chave '{key}' não encontrada"}), 404

# Enviar requisições com a mensagem usando uma chave válida
@app.route('/request', methods=['GET'])
def send_spam():
    api_key = request.args.get('api_key')
    user_id = request.args.get('uid')

    if not api_key or not user_id:
        return jsonify({"error": "Parâmetros obrigatórios ausentes: api_key ou uid"}), 400

    if api_key not in keys:
        return jsonify({"error": "Chave de API inválida"}), 403

    # Processar a solicitação
    message = mymessage_pb2.MyMessage()
    message.field1 = 9797549324
    message.field2 = int(user_id)
    message.field3 = 22

    serialized_message = message.SerializeToString()
    encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_message)
    hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

    tokens = fetch_tokens()
    if not tokens:
        return jsonify({"error": "Nenhum token disponível"}), 500

    print(f"[INÍCIO] Enviando solicitações para {len(tokens)} tokens...")

    success_count = 0
    failed_count = 0
    
    # Aumentando o número de workers para lidar com mais tokens
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(lambda token: send_request(token, hex_encrypted_data), tokens))

    success_count = sum(1 for result in results if result)
    failed_count = len(results) - success_count
    
    print(f"[RESULTADO] Total: {len(tokens)}, Sucessos: {success_count}, Falhas: {failed_count}")

    return jsonify({
        "message": f"{success_count} SOLICITAÇÕES DE AMIZADE ENVIADAS COM SUCESSO",
        "details": {
            "total_tokens": len(tokens),
            "success": success_count,
            "failed": failed_count,
            "success_rate": f"{(success_count/len(tokens))*100:.2f}%"
        }
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=50066, threaded=True)
