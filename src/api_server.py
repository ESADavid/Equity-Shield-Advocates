from flask import Flask, jsonify, request, abort, g
from flask_cors import CORS
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import datetime
import logging
import os
from typing import Optional, Dict, List, Any
import json
from src.bank_communication import get_account_info, validate_routing_number, initiate_transfer
from src.jpmorgan_client import jpmorgan_client
from src.jpmorgan_sync import jpmorgan_sync
from src.jpmorgan_webhooks import webhook_handler

# Check if JPMorgan client is available
JPMORGAN_AVAILABLE = jpmorgan_client is not None
from src.auth_middleware import auth_middleware
from src.mfa_handler import mfa_handler
from src.audit_logger import audit_logger

# Configure logging first
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configure CORS
CORS(app, resources={
    r"/*": {
        "origins": '*',
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-API-KEY"]
    }
})

# Configure rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configure Flask-Caching
cache = Cache(app, config={
    'CACHE_TYPE': 'simple',
    'CACHE_DEFAULT_TIMEOUT': 300,
    'CACHE_KEY_PREFIX': 'api_'
})

DATA_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'corporate_data.json')
CORPORATE_STRUCTURE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'corporate_structure.json')

def require_auth(f):
    """
    Enhanced authentication decorator with JWT, MFA, and audit logging
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.path == '/health':
            return f(*args, **kwargs)

        # Check for JWT token first
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            # JWT authentication path
            try:
                # Validate JWT token
                token_payload = auth_middleware.validate_token(auth_header.split(' ')[1])
                if not token_payload:
                    audit_logger.log_auth_event('jwt_validation_failed', 'unknown_user',
                        success=False, details={'reason': 'invalid_token'})
                    return jsonify({
                        'status': 'error',
                        'error': 'Invalid token',
                        'message': 'Please refresh your token or login again'
                    }), 401

                user_id = token_payload['user_id']
                g.user_id = user_id
                g.auth_method = 'jwt'

                # Check if MFA is required and not bypassed
                if not mfa_handler.should_bypass_mfa(user_id):
                    mfa_token = request.headers.get('X-MFA-Token')
                    if not mfa_token:
                        audit_logger.log_auth_event('mfa_required', user_id,
                            success=False, details={'endpoint': request.path})
                        return jsonify({
                            'status': 'error',
                            'error': 'MFA required',
                            'message': 'Multi-factor authentication token required'
                        }), 401

                    # Verify MFA token
                    challenge_id = request.headers.get('X-MFA-Challenge-ID')
                    if not challenge_id or not mfa_handler.verify_mfa_challenge(challenge_id, mfa_token):
                        audit_logger.log_mfa_event('verification_failed', user_id, False)
                        return jsonify({
                            'status': 'error',
                            'error': 'Invalid MFA token',
                            'message': 'MFA verification failed'
                        }), 401

                    audit_logger.log_mfa_event('verification_success', user_id, True)

                audit_logger.log_auth_event('jwt_auth_success', user_id, True)
                audit_logger.log_api_access(user_id, request.path, request.method, 200)

            except Exception as e:
                audit_logger.log_security_incident('auth_error', 'medium',
                    details={'error': str(e), 'endpoint': request.path})
                return jsonify({
                    'status': 'error',
                    'error': 'Authentication error',
                    'message': 'Authentication failed'
                }), 401

        else:
            # Fallback to API key authentication for backward compatibility
            api_key = request.headers.get('X-API-KEY')
            expected_key = 'equity-shield-2024-secure-key'

            if not api_key:
                audit_logger.log_auth_event('api_key_missing', 'unknown_user',
                    success=False, details={'endpoint': request.path})
                return jsonify({
                    'status': 'error',
                    'error': 'Authentication required',
                    'message': 'API key or JWT token required'
                }), 401

            if api_key != expected_key:
                audit_logger.log_auth_event('api_key_invalid', 'unknown_user',
                    success=False, details={'endpoint': request.path})
                return jsonify({
                    'status': 'error',
                    'error': 'Invalid API key',
                    'message': 'Invalid API key'
                }), 401

            g.user_id = 'api_key_user'
            g.auth_method = 'api_key'
            audit_logger.log_auth_event('api_key_auth_success', 'api_key_user', True)
            audit_logger.log_api_access('api_key_user', request.path, request.method, 200)

        return f(*args, **kwargs)
    return decorated_function

# Backward compatibility alias
require_api_key = require_auth

def load_json_file(file_path: str) -> Optional[Dict]:
    """Load and parse a JSON file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load JSON file {file_path}: {str(e)}")
        return None

def paginate_results(data: List[Any], page: int = 1, per_page: int = 10) -> Dict:
    """Paginate a list of results"""
    start = (page - 1) * per_page
    end = start + per_page
    total_pages = (len(data) + per_page - 1) // per_page
    
    return {
        'data': data[start:end],
        'page': page,
        'per_page': per_page,
        'total': len(data),
        'total_pages': total_pages
    }

@app.route('/health')
@cache.cached(timeout=60)
@limiter.exempt
def health_check():
    """Health check endpoint"""
    try:
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.datetime.now().isoformat(),
            'version': '1.0.0'
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Health check failed',
            'error': str(e)
        }), 500

@app.route('/api/corporate-data')
@require_api_key
@cache.cached(timeout=300)
@limiter.limit("30/minute")
def get_corporate_data():
    """Get corporate data"""
    try:
        live_data = load_json_file(DATA_FILE_PATH)
        if live_data is None:
            return jsonify({
                'status': 'error',
                'error': 'Failed to load live data',
                'message': 'Failed to load live data'
            }), 500

        corporate_summary = {
            'name': 'Equity Shield Advocates',
            'type': 'Corporation',
            'status': 'Active',
            'executive_summary': live_data.get('Executive Summary', ''),
            'fund_overview': live_data.get('Fund Overview', ''),
            'investment_strategy': live_data.get('Investment Strategy', ''),
            'team_structure': live_data.get('Team Structure', ''),
            'risk_assessment': live_data.get('Risk Assessment', ''),
            'aum': live_data.get('AUM', '')
        }
        return jsonify({'status': 'success', 'data': corporate_summary})
    except Exception as e:
        logger.error(f"Error in get_corporate_data: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': 'Internal server error',
            'message': 'Internal server error'
        }), 500

@app.route('/api/corporate-structure')
@require_api_key
@cache.cached(timeout=300)
@limiter.limit("30/minute")
def get_corporate_structure():
    """Get corporate structure"""
    try:
        structure_data = load_json_file(CORPORATE_STRUCTURE_PATH)
        if structure_data is None:
            return jsonify({
                'status': 'error',
                'error': 'Failed to load corporate structure',
                'message': 'Failed to load corporate structure'
            }), 500

        # Return empty dict if structure_data is empty
        if not structure_data:
            return jsonify({'status': 'success', 'data': {}})

        return jsonify({'status': 'success', 'data': structure_data})
    except Exception as e:
        logger.error(f"Error in get_corporate_structure: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': 'Internal server error',
            'message': 'Internal server error'
        }), 500

@app.route('/api/companies/', defaults={'sector': None})
@app.route('/api/companies/<sector>')
@require_api_key
@cache.memoize(300)
@limiter.limit("30/minute")
def get_companies_by_sector(sector: str):
    """Get companies by sector"""
    if sector is None:
        return jsonify({
            'status': 'error',
            'error': 'Sector parameter is required',
            'message': 'Sector parameter is required'
        }), 400

    try:
        structure_data = load_json_file(CORPORATE_STRUCTURE_PATH)
        if structure_data is None:
            return jsonify({
                'status': 'error',
                'error': 'Failed to load corporate structure',
                'message': 'Failed to load corporate structure'
            }), 500

        sector_data = structure_data.get(sector)
        if sector_data is None:
            return jsonify({
                'status': 'error',
                'error': f"Sector '{sector}' not found",
                'message': f"Sector '{sector}' not found"
            }), 404

        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        paginated_data = paginate_results(sector_data, page, per_page)

        return jsonify({
            'status': 'success',
            'sector': sector,
            **paginated_data
        })
    except ValueError as e:
        return jsonify({
            'status': 'error',
            'error': 'Invalid pagination parameters',
            'message': 'Invalid pagination parameters'
        }), 400
    except Exception as e:
        logger.error(f"Error in get_companies_by_sector: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': 'Internal server error',
            'message': 'Internal server error'
        }), 500

@app.route('/api/company/', defaults={'ticker': None})
@app.route('/api/company/<ticker>')
@require_api_key
@cache.memoize(300)
@limiter.limit("30/minute")
def get_company_by_ticker(ticker: str):
    """Get company by ticker symbol"""
    if ticker is None:
        return jsonify({
            'status': 'error',
            'error': 'Ticker parameter is required',
            'message': 'Ticker parameter is required'
        }), 400

    try:
        structure_data = load_json_file(CORPORATE_STRUCTURE_PATH)
        if structure_data is None:
            return jsonify({
                'status': 'error',
                'error': 'Failed to load corporate structure',
                'message': 'Failed to load corporate structure'
            }), 500

        for sector, companies in structure_data.items():
            for company in companies:
                if company.get('ticker', '').lower() == ticker.lower():
                    return jsonify({
                        'status': 'success',
                        'sector': sector,
                        'data': company
                    })

        return jsonify({
            'status': 'error',
            'error': f"Company with ticker '{ticker}' not found",
            'message': f"Company with ticker '{ticker}' not found"
        }), 404
    except Exception as e:
        logger.error(f"Error in get_company_by_ticker: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': 'Internal server error',
            'message': 'Internal server error'
        }), 500

@app.route('/api/real-assets')
@require_api_key
@cache.cached(timeout=300)
@limiter.limit("30/minute")
def get_real_assets():
    """Get real assets with pagination and filtering"""
    try:
        # Get and validate pagination parameters
        try:
            page_str = request.args.get('page')
            per_page_str = request.args.get('per_page')
            page = int(page_str) if page_str else 1
            per_page = int(per_page_str) if per_page_str else 10
            if page < 1:
                page = 1
            if per_page < 1:
                per_page = 10
        except (ValueError, TypeError):
            page = 1
            per_page = 10

        live_data = load_json_file(DATA_FILE_PATH)
        if live_data is None:
            # Return empty result set if file doesn't exist
            return jsonify({
                'status': 'success',
                'data': [],
                'page': page,
                'per_page': per_page,
                'total': 0,
                'total_pages': 0,
                'last_updated': datetime.datetime.now().isoformat()
            })

        # Extract and prepare assets data
        assets = []
        asset_keys = ['MSFT', 'GOOG', 'JPM', 'BAC', 'C', 'PLD', 'AMT', 'SPG']
        
        # Apply filters if provided
        # Get and validate market cap filters
        try:
            min_market_cap = request.args.get('min_market_cap')
            max_market_cap = request.args.get('max_market_cap')
            min_market_cap = float(min_market_cap) if min_market_cap is not None else None
            max_market_cap = float(max_market_cap) if max_market_cap is not None else None
        except ValueError:
            return jsonify({
                'status': 'error',
                'error': 'Invalid market cap parameters',
                'message': 'Market cap filters must be valid numbers'
            }), 400

        for key in asset_keys:
            if key in live_data:
                asset_info = live_data[key]
                if isinstance(asset_info, dict):  # Ensure it's a dictionary
                    market_cap = asset_info.get('market_cap')
                    
                    # Apply market cap filters
                    if min_market_cap and (not market_cap or market_cap < min_market_cap):
                        continue
                    if max_market_cap and (not market_cap or market_cap > max_market_cap):
                        continue
                    
                    assets.append({
                        'symbol': key,
                        'market_cap': market_cap,
                        'revenue': asset_info.get('revenue'),
                        'last_updated': asset_info.get('last_updated')
                    })

        # Sort if requested
        sort_by = request.args.get('sort_by', 'symbol')
        sort_order = request.args.get('sort_order', 'asc')
        
        if sort_by in ['symbol', 'market_cap', 'revenue']:
            reverse = sort_order.lower() == 'desc'
            assets.sort(key=lambda x: (x.get(sort_by) is None, x.get(sort_by)), reverse=reverse)

        paginated_data = paginate_results(assets, page, per_page)

        return jsonify({
            'status': 'success',
            **paginated_data,
            'last_updated': datetime.datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error in get_real_assets: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': 'Internal server error',
            'message': 'Internal server error'
        }), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'status': 'error',
        'message': 'Resource not found',
        'error': str(error)
    }), 404

@app.errorhandler(429)
def ratelimit_handler(error):
    """Handle rate limit exceeded errors"""
    return jsonify({
        'status': 'error',
        'message': 'Rate limit exceeded',
        'error': str(error)
    }), 429

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({
        'status': 'error',
        'message': 'Internal server error',
        'error': str(error)
    }), 500

@app.errorhandler(Exception)
def handle_exception(error):
    """Handle all other exceptions"""
    logger.error(f"Unhandled exception: {str(error)}")
    return jsonify({
        'status': 'error',
        'message': 'An unexpected error occurred',
        'error': str(error)
    }), 500

# Bank endpoints
@app.route('/api/banking-info')
@require_api_key
@cache.cached(timeout=300)
@limiter.limit("30/minute")
def get_banking_info():
    """Get banking information"""
    return jsonify({
        'routing_number': '021000021',
        'account_number': '546910413',
        'ein_number': '12-3456789'
    })

@app.route('/api/banks/<bank_name>/account')
@require_api_key
@cache.cached(timeout=300)
@limiter.limit("30/minute")
def get_bank_account(bank_name):
    """Get bank account information"""
    # Enhanced integration: Use JPMorgan API for JPMorgan accounts
    if 'jpmorgan' in bank_name.lower():
        if not JPMORGAN_AVAILABLE:
            logger.warning("JPMorgan client not available, using fallback")
            # Fallback to existing method
            account_info = get_account_info(bank_name)
            if not account_info:
                return jsonify({
                    'status': 'error',
                    'error': f'Bank {bank_name} not found',
                    'message': f'Bank {bank_name} not found'
                }), 404
            return jsonify({
                'status': 'success',
                'data': account_info,
                'integration': 'fallback'
            })

        try:
            # Extract account ID from request or use default
            account_id = request.args.get('account_id', 'default_account')
            account_info = jpmorgan_client.get_account_balance(account_id)
            return jsonify({
                'status': 'success',
                'data': account_info,
                'integration': 'jpmorgan_api'
            })
        except Exception as e:
            logger.error(f"JPMorgan account fetch failed: {str(e)}")
            # Fallback to existing method
            account_info = get_account_info(bank_name)
            if not account_info:
                return jsonify({
                    'status': 'error',
                    'error': f'Bank {bank_name} not found',
                    'message': f'Bank {bank_name} not found'
                }), 404
            return jsonify({
                'status': 'success',
                'data': account_info,
                'integration': 'fallback'
            })

    # Standard account fetch for other banks
    account_info = get_account_info(bank_name)
    if not account_info:
        return jsonify({
            'status': 'error',
            'error': f'Bank {bank_name} not found',
            'message': f'Bank {bank_name} not found'
        }), 404
    return jsonify(account_info)

@app.route('/api/banks/validate-routing', methods=['POST'])
@require_api_key
@limiter.limit("30/minute")
def validate_routing():
    """Validate a routing number"""
    data = request.get_json()
    if not data or 'routing_number' not in data:
        return jsonify({
            'status': 'error',
            'error': 'routing_number is required',
            'message': 'routing_number is required'
        }), 400
    
    routing_number = data['routing_number']
    is_valid = validate_routing_number(routing_number)
    
    return jsonify({
        'routing_number': routing_number,
        'valid': is_valid
    })

@app.route('/api/banks/transfer', methods=['POST'])
@require_api_key
@limiter.limit("30/minute")
def transfer():
    """Initiate a bank transfer"""
    data = request.get_json()
    required_fields = ['from_bank', 'to_bank', 'amount', 'currency']

    if not data or not all(field in data for field in required_fields):
        return jsonify({
            'status': 'error',
            'error': f'Missing required fields',
            'message': f'Required fields: {", ".join(required_fields)}'
        }), 400

    # Enhanced integration: If JPMorgan is involved, use JPMorgan API
    if 'jpmorgan' in data['from_bank'].lower() or 'jpmorgan' in data['to_bank'].lower():
        if not JPMORGAN_AVAILABLE:
            logger.warning("JPMorgan client not available, using fallback")
            # Fallback to existing transfer method
            result = initiate_transfer(
                data['from_bank'],
                data['to_bank'],
                data['amount'],
                data['currency']
            )
            return jsonify({
                'status': 'success',
                'data': result,
                'integration': 'fallback'
            })

        try:
            result = jpmorgan_client.initiate_transfer(
                data['from_bank'],
                data['to_bank'],
                data['amount'],
                data['currency']
            )
            return jsonify({
                'status': 'success',
                'data': result,
                'integration': 'jpmorgan_api'
            })
        except Exception as e:
            logger.error(f"JPMorgan transfer failed: {str(e)}")
            # Fallback to existing transfer method
            result = initiate_transfer(
                data['from_bank'],
                data['to_bank'],
                data['amount'],
                data['currency']
            )
            return jsonify({
                'status': 'success',
                'data': result,
                'integration': 'fallback'
            })

    # Standard transfer for other banks
    result = initiate_transfer(
        data['from_bank'],
        data['to_bank'],
        data['amount'],
        data['currency']
    )

    return jsonify(result)

@app.route('/api/jpmorgan/sync', methods=['POST'])
@require_api_key
@limiter.limit("10/minute")
def sync_jpmorgan_data():
    """Manually trigger JPMorgan data synchronization"""
    if not JPMORGAN_AVAILABLE:
        return jsonify({
            'status': 'error',
            'message': 'JPMorgan integration not available - client not configured'
        }), 503

    try:
        results = jpmorgan_sync.perform_full_sync()
        return jsonify({
            'status': 'success',
            'message': 'JPMorgan data synchronization completed',
            'results': results
        })
    except Exception as e:
        logger.error(f"JPMorgan sync failed: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'JPMorgan data synchronization failed',
            'error': str(e)
        }), 500

@app.route('/api/jpmorgan/accounts')
@require_api_key
@cache.cached(timeout=300)
@limiter.limit("30/minute")
def get_jpmorgan_accounts():
    """Get JPMorgan corporate accounts"""
    if not JPMORGAN_AVAILABLE:
        return jsonify({
            'status': 'error',
            'message': 'JPMorgan integration not available - client not configured'
        }), 503

    try:
        client_id = os.getenv('JPMORGAN_CLIENT_ID')
        if not client_id:
            return jsonify({
                'status': 'error',
                'message': 'JPMorgan client ID not configured'
            }), 500

        accounts = jpmorgan_client.get_corporate_accounts(client_id)
        return jsonify({
            'status': 'success',
            'data': accounts
        })
    except Exception as e:
        logger.error(f"Failed to fetch JPMorgan accounts: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch JPMorgan accounts',
            'error': str(e)
        }), 500

@app.route('/api/jpmorgan/portfolio/<account_id>')
@require_api_key
@cache.cached(timeout=300)
@limiter.limit("30/minute")
def get_jpmorgan_portfolio(account_id):
    """Get JPMorgan investment portfolio for account"""
    if not JPMORGAN_AVAILABLE:
        return jsonify({
            'status': 'error',
            'message': 'JPMorgan integration not available - client not configured'
        }), 503

    try:
        portfolio = jpmorgan_client.get_investment_portfolio(account_id)
        return jsonify({
            'status': 'success',
            'data': portfolio
        })
    except Exception as e:
        logger.error(f"Failed to fetch JPMorgan portfolio: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to fetch JPMorgan portfolio',
            'error': str(e)
        }), 500

@app.route('/api/webhooks/jpmorgan', methods=['POST'])
def jpmorgan_webhook():
    """Handle incoming webhooks from JPMorgan systems"""
    try:
        # Get raw payload
        payload = request.get_data(as_text=True)

        # Verify signature if provided
        signature = request.headers.get('X-JPMorgan-Signature')
        if signature and not webhook_handler.verify_webhook_signature(payload, signature):
            audit_logger.log_security_incident('invalid_webhook_signature', 'medium',
                details={'endpoint': request.path})
            logger.warning("Invalid webhook signature received")
            return jsonify({'status': 'error', 'message': 'Invalid signature'}), 401

        # Parse JSON payload
        try:
            webhook_data = json.loads(payload)
        except json.JSONDecodeError:
            audit_logger.log_security_incident('invalid_webhook_payload', 'low',
                details={'endpoint': request.path, 'error': 'invalid_json'})
            return jsonify({'status': 'error', 'message': 'Invalid JSON payload'}), 400

        # Extract event type
        event_type = webhook_data.get('event_type') or webhook_data.get('type')
        if not event_type:
            audit_logger.log_security_incident('missing_webhook_event_type', 'low',
                details={'endpoint': request.path})
            return jsonify({'status': 'error', 'message': 'Missing event_type'}), 400

        # Process webhook
        result = webhook_handler.process_webhook(event_type, webhook_data)

        # Log webhook processing
        audit_logger.log_api_access('jpmorgan_webhook', request.path, request.method,
            200 if result['status'] == 'success' else 500)

        # Return appropriate response
        if result['status'] == 'success':
            return jsonify(result), 200
        else:
            return jsonify(result), 500

    except Exception as e:
        audit_logger.log_security_incident('webhook_processing_error', 'medium',
            details={'error': str(e), 'endpoint': request.path})
        logger.error(f"Webhook processing error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500

# Authentication endpoints
@app.route('/api/auth/login', methods=['POST'])
def login():
    """JWT login endpoint"""
    try:
        data = request.get_json()
        if not data or 'user_id' not in data:
            return jsonify({
                'status': 'error',
                'error': 'User ID required',
                'message': 'user_id field is required'
            }), 400

        user_id = data['user_id']
        user_data = data.get('user_data', {})

        # Generate tokens
        access_token, refresh_token = auth_middleware.generate_tokens(user_id, user_data)

        audit_logger.log_auth_event('login_success', user_id, True)

        return jsonify({
            'status': 'success',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': auth_middleware.token_expiry * 60  # Convert to seconds
        })

    except Exception as e:
        audit_logger.log_auth_event('login_failed', data.get('user_id', 'unknown') if 'data' in locals() else 'unknown',
            success=False, details={'error': str(e)})
        return jsonify({
            'status': 'error',
            'error': 'Login failed',
            'message': str(e)
        }), 500

@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh access token endpoint"""
    try:
        data = request.get_json()
        if not data or 'refresh_token' not in data:
            return jsonify({
                'status': 'error',
                'error': 'Refresh token required',
                'message': 'refresh_token field is required'
            }), 400

        refresh_token = data['refresh_token']
        new_access_token = auth_middleware.refresh_access_token(refresh_token)

        if not new_access_token:
            audit_logger.log_auth_event('token_refresh_failed', 'unknown_user', False)
            return jsonify({
                'status': 'error',
                'error': 'Invalid refresh token',
                'message': 'Refresh token is invalid or expired'
            }), 401

        audit_logger.log_auth_event('token_refresh_success', 'unknown_user', True)

        return jsonify({
            'status': 'success',
            'access_token': new_access_token,
            'token_type': 'Bearer'
        })

    except Exception as e:
        audit_logger.log_auth_event('token_refresh_error', 'unknown_user', False,
            details={'error': str(e)})
        return jsonify({
            'status': 'error',
            'error': 'Token refresh failed',
            'message': str(e)
        }), 500

@app.route('/api/auth/logout', methods=['POST'])
@auth_middleware.require_jwt
def logout():
    """Logout endpoint - revoke tokens"""
    try:
        user_id = g.user_id
        auth_middleware.revoke_tokens(user_id)

        audit_logger.log_auth_event('logout_success', user_id, True)

        return jsonify({
            'status': 'success',
            'message': 'Successfully logged out'
        })

    except Exception as e:
        audit_logger.log_auth_event('logout_error', getattr(g, 'user_id', 'unknown'), False,
            details={'error': str(e)})
        return jsonify({
            'status': 'error',
            'error': 'Logout failed',
            'message': str(e)
        }), 500

# MFA endpoints
@app.route('/api/mfa/setup', methods=['POST'])
@auth_middleware.require_jwt
def setup_mfa():
    """Setup MFA for user"""
    try:
        user_id = g.user_id

        if mfa_handler.is_mfa_enabled(user_id):
            return jsonify({
                'status': 'error',
                'error': 'MFA already enabled',
                'message': 'Multi-factor authentication is already enabled for this account'
            }), 400

        setup_info = mfa_handler.get_mfa_setup_info(user_id)

        audit_logger.log_mfa_event('setup_initiated', user_id, True)

        return jsonify({
            'status': 'success',
            'data': setup_info
        })

    except Exception as e:
        audit_logger.log_mfa_event('setup_error', getattr(g, 'user_id', 'unknown'), False,
            details={'error': str(e)})
        return jsonify({
            'status': 'error',
            'error': 'MFA setup failed',
            'message': str(e)
        }), 500

@app.route('/api/mfa/enable', methods=['POST'])
@auth_middleware.require_jwt
def enable_mfa():
    """Enable MFA after verification"""
    try:
        user_id = g.user_id
        data = request.get_json()

        if not data or 'code' not in data:
            return jsonify({
                'status': 'error',
                'error': 'Verification code required',
                'message': 'code field is required'
            }), 400

        code = data['code']

        if mfa_handler.enable_mfa(user_id, code):
            audit_logger.log_mfa_event('enabled', user_id, True)
            return jsonify({
                'status': 'success',
                'message': 'MFA has been enabled for your account'
            })
        else:
            audit_logger.log_mfa_event('enable_failed', user_id, False)
            return jsonify({
                'status': 'error',
                'error': 'Invalid verification code',
                'message': 'The verification code is incorrect'
            }), 400

    except Exception as e:
        audit_logger.log_mfa_event('enable_error', getattr(g, 'user_id', 'unknown'), False,
            details={'error': str(e)})
        return jsonify({
            'status': 'error',
            'error': 'MFA enable failed',
            'message': str(e)
        }), 500

@app.route('/api/mfa/challenge', methods=['POST'])
@auth_middleware.require_jwt
def create_mfa_challenge():
    """Create MFA challenge for authentication"""
    try:
        user_id = g.user_id
        challenge_id = mfa_handler.create_mfa_challenge(user_id)

        if not challenge_id:
            return jsonify({
                'status': 'error',
                'error': 'MFA challenge creation failed',
                'message': 'Unable to create MFA challenge'
            }), 400

        audit_logger.log_mfa_event('challenge_created', user_id, True)

        return jsonify({
            'status': 'success',
            'challenge_id': challenge_id,
            'message': 'MFA challenge created. Please provide your verification code.'
        })

    except Exception as e:
        audit_logger.log_mfa_event('challenge_error', getattr(g, 'user_id', 'unknown'), False,
            details={'error': str(e)})
        return jsonify({
            'status': 'error',
            'error': 'MFA challenge creation failed',
            'message': str(e)
        }), 500

@app.route('/api/mfa/status', methods=['GET'])
@auth_middleware.require_jwt
def get_mfa_status():
    """Get MFA status for current user"""
    try:
        user_id = g.user_id
        status = mfa_handler.get_mfa_status(user_id)

        return jsonify({
            'status': 'success',
            'data': status
        })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': 'Failed to get MFA status',
            'message': str(e)
        }), 500

# Audit endpoints
@app.route('/api/audit/events', methods=['GET'])
@auth_middleware.require_jwt
def get_audit_events():
    """Get audit events with filtering"""
    try:
        # Check if user has admin privileges (simplified check)
        user_id = g.user_id
        if user_id not in ['admin', 'auditor']:  # In production, check proper roles
            audit_logger.log_security_incident('unauthorized_audit_access', 'high',
                details={'user_id': user_id, 'endpoint': request.path})
            return jsonify({
                'status': 'error',
                'error': 'Unauthorized',
                'message': 'Insufficient privileges to access audit logs'
            }), 403

        # Parse query parameters
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        event_type = request.args.get('event_type')
        user_filter = request.args.get('user_id')
        limit = int(request.args.get('limit', 100))

        start_date = None
        end_date = None

        if start_date_str:
            try:
                start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({
                    'status': 'error',
                    'error': 'Invalid start_date format',
                    'message': 'Use ISO format for dates'
                }), 400

        if end_date_str:
            try:
                end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({
                    'status': 'error',
                    'error': 'Invalid end_date format',
                    'message': 'Use ISO format for dates'
                }), 400

        events = audit_logger.get_audit_events(
            start_date=start_date,
            end_date=end_date,
            event_type=event_type,
            user_id=user_filter,
            limit=limit
        )

        audit_logger.log_api_access(user_id, request.path, request.method, 200)

        return jsonify({
            'status': 'success',
            'data': events,
            'count': len(events)
        })

    except Exception as e:
        audit_logger.log_security_incident('audit_access_error', 'medium',
            details={'error': str(e), 'endpoint': request.path})
        return jsonify({
            'status': 'error',
            'error': 'Failed to retrieve audit events',
            'message': str(e)
        }), 500

@app.route('/api/audit/dashboard', methods=['GET'])
@auth_middleware.require_jwt
def get_security_dashboard():
    """Get security dashboard data"""
    try:
        user_id = g.user_id
        if user_id not in ['admin', 'security']:  # In production, check proper roles
            audit_logger.log_security_incident('unauthorized_dashboard_access', 'high',
                details={'user_id': user_id, 'endpoint': request.path})
            return jsonify({
                'status': 'error',
                'error': 'Unauthorized',
                'message': 'Insufficient privileges to access security dashboard'
            }), 403

        dashboard_data = audit_logger.get_security_dashboard_data()

        audit_logger.log_api_access(user_id, request.path, request.method, 200)

        return jsonify({
            'status': 'success',
            'data': dashboard_data
        })

    except Exception as e:
        audit_logger.log_security_incident('dashboard_access_error', 'medium',
            details={'error': str(e), 'endpoint': request.path})
        return jsonify({
            'status': 'error',
            'error': 'Failed to retrieve dashboard data',
            'message': str(e)
        }), 500

@app.route('/api/audit/compliance-report', methods=['GET'])
@auth_middleware.require_jwt
def get_compliance_report():
    """Generate compliance report"""
    try:
        user_id = g.user_id
        if user_id not in ['admin', 'compliance']:  # In production, check proper roles
            audit_logger.log_security_incident('unauthorized_compliance_access', 'high',
                details={'user_id': user_id, 'endpoint': request.path})
            return jsonify({
                'status': 'error',
                'error': 'Unauthorized',
                'message': 'Insufficient privileges to access compliance reports'
            }), 403

        # Parse date parameters
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')

        start_date = None
        end_date = None

        if start_date_str:
            try:
                start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({
                    'status': 'error',
                    'error': 'Invalid start_date format',
                    'message': 'Use ISO format for dates'
                }), 400

        if end_date_str:
            try:
                end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({
                    'status': 'error',
                    'error': 'Invalid end_date format',
                    'message': 'Use ISO format for dates'
                }), 400

        report = audit_logger.generate_compliance_report(
            start_date=start_date,
            end_date=end_date
        )

        audit_logger.log_api_access(user_id, request.path, request.method, 200)

        return jsonify({
            'status': 'success',
            'data': report
        })

    except Exception as e:
        audit_logger.log_security_incident('compliance_report_error', 'medium',
            details={'error': str(e), 'endpoint': request.path})
        return jsonify({
            'status': 'error',
            'error': 'Failed to generate compliance report',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    logger.info("Starting API server on port 5001...")
    app.run(host='0.0.0.0', port=5001)
