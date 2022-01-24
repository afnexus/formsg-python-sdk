from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder
from nacl.signing import VerifyKey
import requests
import base64
import json
import logging
import os
import re

def decrypt_form(request, secret_key, public_key, has_attachments, api_href):
    verify_signature(request, public_key, api_href)

    request_body_json = request.get_json()

    logging.info('Request body %s', request_body_json)

    submission_public_key, nonce_encrypted = request_body_json['data']['encryptedContent'].split(';')
    nonce, encrypted_content = nonce_encrypted.split(':')

    secret_key_py = PrivateKey(secret_key, encoder=Base64Encoder)
    public_key_js = PublicKey(submission_public_key, encoder=Base64Encoder)

    # Convert nonce base64 to bytes
    nonce = base64.b64decode(nonce)
    # Convert encrypted_content base64 to bytes
    encrypted_content = base64.b64decode(encrypted_content)

    # Create box object with public and secret key
    box_py = Box(secret_key_py, public_key_js)
    data = box_py.decrypt(nonce + encrypted_content)

    clear_text = json.loads(data.decode('utf-8'))

    clear_text_data = {
        "data": {
                "formId": request_body_json['data']['formId'],
                "submissionId": request_body_json['data']['submissionId'],
                "decryptedContent": clear_text,
                "version": request_body_json['data']['version'],
                "created": request_body_json['data']['created'],
        }
    }

    if has_attachments == True:
        decrypt_files(secret_key, clear_text_data, request_body_json)

    return clear_text_data

def decrypt_files(secret_key, clear_text_data, request_body_json):
    for question in clear_text_data['data']['decryptedContent']: 
        if question['fieldType'] == 'attachment':
            s3_download_url = request_body_json['data']['attachmentDownloadUrls'][question['_id']]
            r = requests.get(s3_download_url)
            
            s3_body_json = r.json()
            
            submission_public_key = s3_body_json['encryptedFile']['submissionPublicKey']
            nonce = s3_body_json['encryptedFile']['nonce']
            binary = s3_body_json['encryptedFile']['binary']

            secretKey_py = PrivateKey(secret_key, encoder=Base64Encoder)
            publicKey_js = PublicKey(submission_public_key, encoder=Base64Encoder)

            nonce = base64.b64decode(nonce)
            box_js = base64.b64decode(binary)

            box_py = Box(secretKey_py, publicKey_js)
            attachment_decrypted_content = box_py.decrypt(nonce + box_js)

            file_storage_directory = create_folders_to_store_files(clear_text_data['data']['submissionId'], question['_id'])

            with open(file_storage_directory + '/' + question['answer'], 'wb') as f:
                f.write(attachment_decrypted_content)

def create_folders_to_store_files(submission_id, question_id):
    # Check if folder to store FormSG files exist 
    if not os.path.isdir('formsg-files'):
        # Create folder if not exist
        os.mkdir('formsg-files') 
    

    if not os.path.isdir('formsg-files/' + submission_id):
        # Create folder if not exist
        os.mkdir('formsg-files/' + submission_id) 
    
    file_storage_directory = 'formsg-files/' + submission_id + '/' + question_id

    if not os.path.isdir(file_storage_directory):
        # Create folder if not exist
        os.mkdir(file_storage_directory) 

    return file_storage_directory

def verify_signature(request, public_key, api_href):
    x_formsg_signature = request.headers.get('X-Formsg-Signature')
    logging.info('X-Formsg-Signature %s', x_formsg_signature)

    timestamp, submission_id, form_id, signature_scheme = x_formsg_signature.split(',')
    
    timestamp = re.search(r'(?<==).*$', timestamp).group()
    submission_id = re.search(r'(?<==).*$', submission_id).group()
    form_id = re.search(r'(?<==).*$', form_id).group()
    signature_scheme = re.search(r'(?<==).*$', signature_scheme).group()

    base_string = f'{api_href}.{submission_id}.{form_id}.{timestamp}'

    base_string_base64 = base64.b64encode(bytes(base_string, 'utf-8'))

    public_key_base64 = bytes(public_key, 'utf-8')

    verify_key = VerifyKey(public_key_base64, encoder=Base64Encoder)

    signature_bytes = Base64Encoder.decode(signature_scheme)
    verify_key.verify(base_string_base64, signature_bytes,
                    encoder=Base64Encoder)