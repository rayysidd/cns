from flask import Flask, request, jsonify

app = Flask(__name__)

# Store identity -> public key PEM (string)
key_registry = {}

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    identity = data.get('identity')
    public_key = data.get('public_key')
    if not identity or not public_key:
        return jsonify({'error': 'identity and public_key required'}), 400
    
    key_registry[identity] = public_key
    return jsonify({'message': f'Registered {identity} successfully'})

@app.route('/get_key/<identity>', methods=['GET'])
def get_key(identity):
    public_key = key_registry.get(identity)
    if not public_key:
        return jsonify({'error': 'Identity not found'}), 404
    return jsonify({'identity': identity, 'public_key': public_key})

if __name__ == '__main__':
    app.run(port=5000)