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

# Função para buscar 300 tokens
def fetch_tokens():
    token_url = "https://tokensff.vercel.app/token"
    try:
        response = requests.get(token_url, timeout=10)
        if response.status_code == 200:
            tokens_data = response.json()
            
            # Verifica se é a nova estrutura (lista de objetos)
            if isinstance(tokens_data, list):
                tokens = []
                for item in tokens_data[:300]:  # Limita a 300 tokens
                    if isinstance(item, dict) and 'token' in item:
                        tokens.append(item['token'])
                print(f"[DEBUG] Tokens recebidos (novo formato): {len(tokens)}")
                return tokens
            # Verifica se é o formato antigo (dicionário com chave 'tokens')
            elif isinstance(tokens_data, dict) and 'tokens' in tokens_data:
                print(f"[DEBUG] Tokens recebidos (formato antigo): {len(tokens_data['tokens'][:300])}")
                return tokens_data['tokens'][:300]
            else:
                print("[ERRO] Formato de tokens desconhecido")
                return []
        else:
            print(f"[ERRO] Falha ao buscar tokens. Status: {response.status_code}")
            return []
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
    
    # Ajustando o número de workers para 300 tokens
    with ThreadPoolExecutor(max_workers=10) as executor:
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
