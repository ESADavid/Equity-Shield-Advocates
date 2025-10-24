import boto3
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from cryptography.fernet import Fernet
import base64
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

class CredentialManager:
    """
    Secure credential management with AWS Secrets Manager and encrypted local storage.
    """

    def __init__(self):
        self.use_aws = os.getenv('USE_AWS_SECRETS', 'false').lower() == 'true'
        self.aws_region = os.getenv('AWS_REGION', 'us-east-1')
        self.local_key_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'cred_key.enc')
        self.local_creds_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'credentials.enc')

        # Initialize encryption
        self._init_encryption()

        # AWS clients
        self.secrets_client = None
        if self.use_aws:
            try:
                self.secrets_client = boto3.client('secretsmanager', region_name=self.aws_region)
                logger.info("Initialized AWS Secrets Manager client")
            except NoCredentialsError:
                logger.warning("AWS credentials not found, falling back to local storage")
                self.use_aws = False

    def _init_encryption(self) -> None:
        """Initialize encryption key"""
        if os.path.exists(self.local_key_file):
            try:
                with open(self.local_key_file, 'rb') as f:
                    self.encryption_key = f.read()
                self.fernet = Fernet(self.encryption_key)
            except Exception as e:
                logger.error(f"Failed to load encryption key: {str(e)}")
                self._generate_new_key()
        else:
            self._generate_new_key()

    def _generate_new_key(self) -> None:
        """Generate new encryption key"""
        self.encryption_key = Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)

        # Save key securely
        os.makedirs(os.path.dirname(self.local_key_file), exist_ok=True)
        with open(self.local_key_file, 'wb') as f:
            f.write(self.encryption_key)

        logger.info("Generated new encryption key for credentials")

    def _encrypt_data(self, data: Dict[str, Any]) -> str:
        """Encrypt credential data"""
        json_data = json.dumps(data)
        return self.fernet.encrypt(json_data.encode()).decode()

    def _decrypt_data(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt credential data"""
        try:
            decrypted = self.fernet.decrypt(encrypted_data.encode())
            return json.loads(decrypted.decode())
        except Exception as e:
            logger.error(f"Failed to decrypt credential data: {str(e)}")
            return {}

    def store_credential(self, service_name: str, credential_data: Dict[str, Any],
                        rotation_days: int = 90) -> bool:
        """
        Store credential securely
        """
        try:
            # Add metadata
            full_data = {
                'data': credential_data,
                'created_at': datetime.now().isoformat(),
                'rotation_days': rotation_days,
                'next_rotation': (datetime.now() + timedelta(days=rotation_days)).isoformat(),
                'version': '1.0'
            }

            if self.use_aws:
                return self._store_aws(service_name, full_data)
            else:
                return self._store_local(service_name, full_data)

        except Exception as e:
            logger.error(f"Failed to store credential for {service_name}: {str(e)}")
            return False

    def retrieve_credential(self, service_name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve credential from storage
        """
        try:
            if self.use_aws:
                data = self._retrieve_aws(service_name)
            else:
                data = self._retrieve_local(service_name)

            if data and 'data' in data:
                # Check if rotation is needed
                next_rotation = data.get('next_rotation')
                if next_rotation:
                    next_rot = datetime.fromisoformat(next_rotation)
                    if datetime.now() > next_rot:
                        logger.warning(f"Credential for {service_name} needs rotation")
                        # Could trigger rotation here

                return data['data']
            return None

        except Exception as e:
            logger.error(f"Failed to retrieve credential for {service_name}: {str(e)}")
            return None

    def _store_aws(self, service_name: str, data: Dict[str, Any]) -> bool:
        """Store credential in AWS Secrets Manager"""
        try:
            secret_name = f"equity-shield/{service_name}"

            self.secrets_client.put_secret_value(
                SecretId=secret_name,
                SecretString=json.dumps(data)
            )

            logger.info(f"Stored credential for {service_name} in AWS Secrets Manager")
            return True

        except ClientError as e:
            logger.error(f"AWS Secrets Manager error: {str(e)}")
            return False

    def _retrieve_aws(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve credential from AWS Secrets Manager"""
        try:
            secret_name = f"equity-shield/{service_name}"

            response = self.secrets_client.get_secret_value(SecretId=secret_name)
            secret_string = response['SecretString']

            return json.loads(secret_string)

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return None
            logger.error(f"AWS Secrets Manager error: {str(e)}")
            return None

    def _store_local(self, service_name: str, data: Dict[str, Any]) -> bool:
        """Store credential in encrypted local file"""
        try:
            # Load existing credentials
            all_creds = self._load_local_credentials()

            # Update with new credential
            all_creds[service_name] = data

            # Encrypt and save
            encrypted_data = self._encrypt_data(all_creds)
            os.makedirs(os.path.dirname(self.local_creds_file), exist_ok=True)

            with open(self.local_creds_file, 'w') as f:
                f.write(encrypted_data)

            logger.info(f"Stored credential for {service_name} locally")
            return True

        except Exception as e:
            logger.error(f"Failed to store local credential: {str(e)}")
            return False

    def _retrieve_local(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve credential from local encrypted file"""
        try:
            all_creds = self._load_local_credentials()
            return all_creds.get(service_name)

        except Exception as e:
            logger.error(f"Failed to retrieve local credential: {str(e)}")
            return None

    def _load_local_credentials(self) -> Dict[str, Any]:
        """Load all local credentials"""
        if not os.path.exists(self.local_creds_file):
            return {}

        try:
            with open(self.local_creds_file, 'r') as f:
                encrypted_data = f.read().strip()
                return self._decrypt_data(encrypted_data)
        except Exception as e:
            logger.error(f"Failed to load local credentials: {str(e)}")
            return {}

    def rotate_credential(self, service_name: str, new_credential_data: Dict[str, Any]) -> bool:
        """
        Rotate credential with new data
        """
        try:
            # Get current credential to preserve rotation settings
            current = self.retrieve_credential(service_name)
            if current:
                rotation_days = current.get('rotation_days', 90)
            else:
                rotation_days = 90

            # Store new credential
            success = self.store_credential(service_name, new_credential_data, rotation_days)

            if success:
                logger.info(f"Successfully rotated credential for {service_name}")

                # Could send notification here
                # self._notify_rotation(service_name)

            return success

        except Exception as e:
            logger.error(f"Failed to rotate credential for {service_name}: {str(e)}")
            return False

    def delete_credential(self, service_name: str) -> bool:
        """
        Delete credential from storage
        """
        try:
            if self.use_aws:
                return self._delete_aws(service_name)
            else:
                return self._delete_local(service_name)

        except Exception as e:
            logger.error(f"Failed to delete credential for {service_name}: {str(e)}")
            return False

    def _delete_aws(self, service_name: str) -> bool:
        """Delete credential from AWS"""
        try:
            secret_name = f"equity-shield/{service_name}"
            self.secrets_client.delete_secret(
                SecretId=secret_name,
                ForceDeleteWithoutRecovery=True
            )
            logger.info(f"Deleted credential for {service_name} from AWS")
            return True
        except ClientError as e:
            logger.error(f"AWS delete error: {str(e)}")
            return False

    def _delete_local(self, service_name: str) -> bool:
        """Delete credential from local storage"""
        try:
            all_creds = self._load_local_credentials()
            if service_name in all_creds:
                del all_creds[service_name]
                encrypted_data = self._encrypt_data(all_creds)
                with open(self.local_creds_file, 'w') as f:
                    f.write(encrypted_data)
                logger.info(f"Deleted credential for {service_name} locally")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete local credential: {str(e)}")
            return False

    def list_credentials(self) -> List[str]:
        """
        List all stored credential service names
        """
        try:
            if self.use_aws:
                return self._list_aws()
            else:
                return self._list_local()

        except Exception as e:
            logger.error(f"Failed to list credentials: {str(e)}")
            return []

    def _list_aws(self) -> List[str]:
        """List AWS credentials"""
        try:
            paginator = self.secrets_client.get_paginator('list_secrets')
            credentials = []

            for page in paginator.paginate(
                Filters=[{'Key': 'name', 'Values': ['equity-shield/']}]
            ):
                for secret in page['SecretList']:
                    name = secret['Name']
                    if name.startswith('equity-shield/'):
                        credentials.append(name.replace('equity-shield/', ''))

            return credentials

        except ClientError as e:
            logger.error(f"AWS list error: {str(e)}")
            return []

    def _list_local(self) -> List[str]:
        """List local credentials"""
        try:
            all_creds = self._load_local_credentials()
            return list(all_creds.keys())
        except Exception as e:
            return []

    def validate_credential(self, service_name: str) -> Dict[str, Any]:
        """
        Validate credential health and status
        """
        result = {
            'service_name': service_name,
            'exists': False,
            'valid': False,
            'needs_rotation': False,
            'errors': []
        }

        try:
            credential = self.retrieve_credential(service_name)

            if credential:
                result['exists'] = True

                # Check required fields based on service
                if service_name == 'jpmorgan':
                    required_fields = ['client_id', 'client_secret', 'api_key']
                elif service_name == 'aws':
                    required_fields = ['access_key_id', 'secret_access_key']
                else:
                    required_fields = ['username', 'password']

                missing_fields = [field for field in required_fields if field not in credential]
                if missing_fields:
                    result['errors'].append(f"Missing required fields: {', '.join(missing_fields)}")
                else:
                    result['valid'] = True

                # Check rotation status
                if self.use_aws:
                    # Would need to check AWS metadata
                    pass
                else:
                    all_creds = self._load_local_credentials()
                    cred_data = all_creds.get(service_name, {})
                    next_rotation = cred_data.get('next_rotation')
                    if next_rotation:
                        next_rot = datetime.fromisoformat(next_rotation)
                        if datetime.now() > next_rot:
                            result['needs_rotation'] = True

            else:
                result['errors'].append("Credential not found")

        except Exception as e:
            result['errors'].append(f"Validation error: {str(e)}")

        return result

    def health_check(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check of credential storage
        """
        health = {
            'storage_type': 'aws' if self.use_aws else 'local',
            'encryption_enabled': True,
            'total_credentials': 0,
            'valid_credentials': 0,
            'credentials_needing_rotation': 0,
            'errors': []
        }

        try:
            credentials = self.list_credentials()
            health['total_credentials'] = len(credentials)

            for service in credentials:
                validation = self.validate_credential(service)
                if validation['valid']:
                    health['valid_credentials'] += 1
                if validation['needs_rotation']:
                    health['credentials_needing_rotation'] += 1
                if validation['errors']:
                    health['errors'].extend(validation['errors'])

        except Exception as e:
            health['errors'].append(f"Health check error: {str(e)}")

        return health

# Global credential manager instance
credential_manager = CredentialManager()
