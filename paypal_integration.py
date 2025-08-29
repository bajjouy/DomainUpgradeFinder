import requests
import base64
import json
from flask import current_app, url_for

class PayPalAPI:
    """PayPal REST API integration class"""
    
    def __init__(self):
        self.client_id = current_app.config.get('PAYPAL_CLIENT_ID')
        self.client_secret = current_app.config.get('PAYPAL_CLIENT_SECRET')
        self.mode = current_app.config.get('PAYPAL_MODE', 'sandbox')
        
        # Set PayPal API base URL based on mode
        if self.mode == 'live':
            self.base_url = 'https://api.paypal.com'
        else:
            self.base_url = 'https://api.sandbox.paypal.com'
    
    def get_access_token(self):
        """Get PayPal access token for API authentication"""
        url = f"{self.base_url}/v1/oauth2/token"
        
        # Create basic auth header
        credentials = f"{self.client_id}:{self.client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        headers = {
            'Accept': 'application/json',
            'Accept-Language': 'en_US',
            'Authorization': f'Basic {encoded_credentials}'
        }
        
        data = 'grant_type=client_credentials'
        
        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            return token_data['access_token']
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get PayPal access token: {str(e)}")
    
    def create_payment(self, package, user):
        """Create a PayPal payment"""
        try:
            access_token = self.get_access_token()
            
            url = f"{self.base_url}/v1/payments/payment"
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {access_token}'
            }
            
            # Create payment data
            payment_data = {
                "intent": "sale",
                "payer": {
                    "payment_method": "paypal"
                },
                "transactions": [{
                    "amount": {
                        "total": f"{package.price_dollars:.2f}",
                        "currency": "USD"
                    },
                    "description": f"{package.coins} coins for {user.email}",
                    "custom": json.dumps({
                        "user_id": user.id,
                        "package_id": package.id,
                        "coins": package.coins
                    })
                }],
                "redirect_urls": {
                    "return_url": url_for('paypal_success', _external=True),
                    "cancel_url": url_for('paypal_cancel', _external=True)
                }
            }
            
            response = requests.post(url, headers=headers, json=payment_data)
            response.raise_for_status()
            
            payment_response = response.json()
            
            # Find approval URL
            approval_url = None
            for link in payment_response.get('links', []):
                if link['rel'] == 'approval_url':
                    approval_url = link['href']
                    break
            
            return {
                'payment_id': payment_response['id'],
                'approval_url': approval_url,
                'status': payment_response['state']
            }
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to create PayPal payment: {str(e)}")
    
    def execute_payment(self, payment_id, payer_id):
        """Execute a PayPal payment after user approval"""
        try:
            access_token = self.get_access_token()
            
            url = f"{self.base_url}/v1/payments/payment/{payment_id}/execute"
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {access_token}'
            }
            
            execute_data = {
                "payer_id": payer_id
            }
            
            response = requests.post(url, headers=headers, json=execute_data)
            response.raise_for_status()
            
            execution_response = response.json()
            
            # Extract transaction details
            if execution_response['state'] == 'approved':
                transaction = execution_response['transactions'][0]
                custom_data = json.loads(transaction.get('custom', '{}'))
                
                return {
                    'success': True,
                    'transaction_id': execution_response['id'],
                    'amount': transaction['amount']['total'],
                    'user_id': custom_data.get('user_id'),
                    'package_id': custom_data.get('package_id'),
                    'coins': custom_data.get('coins'),
                    'payer_email': execution_response['payer']['payer_info']['email']
                }
            else:
                return {'success': False, 'message': 'Payment not approved'}
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to execute PayPal payment: {str(e)}")
    
    def get_payment_details(self, payment_id):
        """Get details of a PayPal payment"""
        try:
            access_token = self.get_access_token()
            
            url = f"{self.base_url}/v1/payments/payment/{payment_id}"
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {access_token}'
            }
            
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get PayPal payment details: {str(e)}")