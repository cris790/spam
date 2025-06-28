from flask import Flask, jsonify, request
import requests
import mymessage_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import binascii
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# Configurações de criptografia
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Função para gerar UID aleatório de 64 bits
def generate_random_uid_64():
    return random.randint(1, 9_223_372_036_854_775_807)

# Função para criptografar a mensagem
def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

# Função para buscar os tokens (agora com limite de 350)
def fetch_tokens():
    token_url = "https://tokenff.discloud.app/token"
    try:
        response = requests.get(token_url)
        if response.status_code == 200:
            tokens_data = response.json()
            
            # Handle both formats:
            # 1. Old format: {"tokens": ["token1", "token2", ...]}
            # 2. New format: [{"token": "token1"}, {"token": "token2"}, ...]
            
            if isinstance(tokens_data, dict) and 'tokens' in tokens_data:
                # Old format
                return tokens_data['tokens'][:900]  # Aumentado para 350 tokens
            elif isinstance(tokens_data, list):
                # New format - extract tokens from objects
                tokens = []
                for item in tokens_data[:900]:  # Aumentado para 350 tokens
                    if isinstance(item, dict) and 'token' in item:
                        tokens.append(item['token'])
                return tokens
            else:
                print("Formato de tokens desconhecido")
                return []
        else:
            print(f"Falha ao buscar os tokens, código de status: {response.status_code}")
            return []
    except Exception as e:
        print(f"Erro ao buscar os tokens: {e}")
        return []

# Função para enviar requisições com a mensagem
def send_request(token, hex_encrypted_data):
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
        'ReleaseVersion': "OB49"
    }

    try:
        response = requests.post(url, data=payload, headers=headers, timeout=10)
        return response.status_code == 200
    except:
        return False

# Enviar requisições com a mensagem (agora sem verificação de chave)
@app.route('/request', methods=['GET'])
def send_spam():
    user_id = request.args.get('uid')

    if not user_id:
        return jsonify({"error": "Parâmetro obrigatório ausente: uid"}), 400

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

    # Aumentar o número de workers para lidar com mais tokens
    success_count = 0
    with ThreadPoolExecutor(max_workers=20) as executor:  # Aumentado para 20 workers
        results = list(executor.map(lambda token: send_request(token, hex_encrypted_data), tokens))

    success_count = sum(1 for result in results if result)

    return jsonify({
        "message": f"{success_count} SOLICITAÇÕES DE AMIZADE ENVIADAS COM SUCESSO",
        "total_tokens": len(tokens),
        "success_rate": f"{(success_count/len(tokens))*100:.2f}%"
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=50066)
