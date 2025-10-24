import logging
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict
import structlog
from flask import request, g

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

class AuditLogger:
    """
    Comprehensive audit logging system for authentication, API access,
    and security incidents with aggregation and compliance reporting.
    """

    def __init__(self):
        self.audit_log_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'audit_log.jsonl')
        self.compliance_report_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'compliance_report.json')

        # Configure structlog for structured logging
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                self._structlog_to_audit,
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

        self.logger = structlog.get_logger()

    def _structlog_to_audit(self, logger, name, event_dict):
        """Custom processor to write audit events to file"""
        if event_dict.get('audit_event', False):
            self._write_audit_event(event_dict)
        return event_dict

    def _write_audit_event(self, event_dict: Dict[str, Any]) -> None:
        """Write audit event to log file"""
        try:
            os.makedirs(os.path.dirname(self.audit_log_file), exist_ok=True)
            with open(self.audit_log_file, 'a') as f:
                f.write(json.dumps(event_dict) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit event: {str(e)}")

    def log_auth_event(self, event_type: str, user_id: str, success: bool,
                      details: Dict[str, Any] = None) -> None:
        """
        Log authentication events
        """
        if details is None:
            details = {}

        # Get request context
        request_info = self._get_request_context()

        audit_data = {
            'audit_event': True,
            'event_type': 'authentication',
            'sub_type': event_type,
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'success': success,
            'ip_address': request_info.get('ip_address'),
            'user_agent': request_info.get('user_agent'),
            'endpoint': request_info.get('endpoint'),
            'method': request_info.get('method'),
            'details': details
        }

        self.logger.info(
            f"Authentication event: {event_type}",
            **audit_data
        )

    def log_api_access(self, user_id: str, endpoint: str, method: str,
                      status_code: int, response_time: float = None) -> None:
        """
        Log API access events
        """
        request_info = self._get_request_context()

        audit_data = {
            'audit_event': True,
            'event_type': 'api_access',
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'endpoint': endpoint,
            'method': method,
            'status_code': status_code,
            'response_time_ms': response_time,
            'ip_address': request_info.get('ip_address'),
            'user_agent': request_info.get('user_agent'),
            'success': status_code < 400
        }

        log_level = 'info' if status_code < 400 else 'warning'
        getattr(self.logger, log_level)(
            f"API access: {method} {endpoint} - {status_code}",
            **audit_data
        )

    def log_security_incident(self, incident_type: str, severity: str,
                            user_id: str = None, details: Dict[str, Any] = None) -> None:
        """
        Log security incidents
        """
        if details is None:
            details = {}

        request_info = self._get_request_context()

        audit_data = {
            'audit_event': True,
            'event_type': 'security_incident',
            'incident_type': incident_type,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'ip_address': request_info.get('ip_address'),
            'user_agent': request_info.get('user_agent'),
            'endpoint': request_info.get('endpoint'),
            'details': details
        }

        severity_levels = {'low': 'info', 'medium': 'warning', 'high': 'error', 'critical': 'critical'}
        log_level = severity_levels.get(severity.lower(), 'warning')

        getattr(self.logger, log_level)(
            f"Security incident: {incident_type} ({severity})",
            **audit_data
        )

    def log_mfa_event(self, event_type: str, user_id: str, success: bool,
                     details: Dict[str, Any] = None) -> None:
        """
        Log MFA-related events
        """
        if details is None:
            details = {}

        request_info = self._get_request_context()

        audit_data = {
            'audit_event': True,
            'event_type': 'mfa',
            'sub_type': event_type,
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'success': success,
            'ip_address': request_info.get('ip_address'),
            'details': details
        }

        self.logger.info(
            f"MFA event: {event_type}",
            **audit_data
        )

    def log_credential_event(self, event_type: str, service_name: str,
                           user_id: str = None, success: bool = True,
                           details: Dict[str, Any] = None) -> None:
        """
        Log credential management events
        """
        if details is None:
            details = {}

        audit_data = {
            'audit_event': True,
            'event_type': 'credential_management',
            'sub_type': event_type,
            'timestamp': datetime.now().isoformat(),
            'service_name': service_name,
            'user_id': user_id,
            'success': success,
            'details': details
        }

        self.logger.info(
            f"Credential event: {event_type} for {service_name}",
            **audit_data
        )

    def _get_request_context(self) -> Dict[str, Any]:
        """Get current request context information"""
        try:
            return {
                'ip_address': getattr(request, 'remote_addr', None) if request else None,
                'user_agent': request.headers.get('User-Agent') if request else None,
                'endpoint': request.path if request else None,
                'method': request.method if request else None
            }
        except RuntimeError:
            # Outside of request context
            return {}

    def get_audit_events(self, start_date: datetime = None, end_date: datetime = None,
                        event_type: str = None, user_id: str = None,
                        limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Retrieve audit events with filtering
        """
        try:
            events = []

            if not os.path.exists(self.audit_log_file):
                return events

            with open(self.audit_log_file, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())

                        # Apply filters
                        if start_date and datetime.fromisoformat(event['timestamp']) < start_date:
                            continue
                        if end_date and datetime.fromisoformat(event['timestamp']) > end_date:
                            continue
                        if event_type and event.get('event_type') != event_type:
                            continue
                        if user_id and event.get('user_id') != user_id:
                            continue

                        events.append(event)

                        if len(events) >= limit:
                            break

                    except json.JSONDecodeError:
                        continue

            return events

        except Exception as e:
            logger.error(f"Failed to retrieve audit events: {str(e)}")
            return []

    def generate_compliance_report(self, start_date: datetime = None,
                                 end_date: datetime = None) -> Dict[str, Any]:
        """
        Generate compliance report from audit logs
        """
        try:
            if not start_date:
                start_date = datetime.now() - timedelta(days=30)
            if not end_date:
                end_date = datetime.now()

            events = self.get_audit_events(start_date, end_date, limit=10000)

            # Aggregate statistics
            report = {
                'report_period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'summary': {
                    'total_events': len(events),
                    'authentication_events': 0,
                    'api_access_events': 0,
                    'security_incidents': 0,
                    'mfa_events': 0,
                    'credential_events': 0
                },
                'authentication': {
                    'successful_logins': 0,
                    'failed_logins': 0,
                    'token_refreshes': 0,
                    'logout_events': 0
                },
                'api_access': {
                    'total_requests': 0,
                    'successful_requests': 0,
                    'failed_requests': 0,
                    'error_responses': 0
                },
                'security_incidents': {
                    'total_incidents': 0,
                    'by_severity': defaultdict(int),
                    'by_type': defaultdict(int)
                },
                'mfa': {
                    'enabled_users': set(),
                    'verification_attempts': 0,
                    'successful_verifications': 0,
                    'failed_verifications': 0
                },
                'users': defaultdict(lambda: {
                    'auth_events': 0,
                    'api_calls': 0,
                    'security_incidents': 0,
                    'last_activity': None
                }),
                'generated_at': datetime.now().isoformat()
            }

            for event in events:
                event_type = event.get('event_type')
                report['summary'][f'{event_type}_events'] += 1

                user_id = event.get('user_id')
                if user_id:
                    report['users'][user_id]['last_activity'] = event['timestamp']

                if event_type == 'authentication':
                    sub_type = event.get('sub_type')
                    success = event.get('success', False)

                    if sub_type == 'login':
                        if success:
                            report['authentication']['successful_logins'] += 1
                        else:
                            report['authentication']['failed_logins'] += 1
                    elif sub_type == 'token_refresh':
                        report['authentication']['token_refreshes'] += 1
                    elif sub_type == 'logout':
                        report['authentication']['logout_events'] += 1

                    if user_id:
                        report['users'][user_id]['auth_events'] += 1

                elif event_type == 'api_access':
                    report['api_access']['total_requests'] += 1
                    status_code = event.get('status_code', 0)

                    if status_code < 400:
                        report['api_access']['successful_requests'] += 1
                    else:
                        report['api_access']['failed_requests'] += 1
                        if status_code >= 500:
                            report['api_access']['error_responses'] += 1

                    if user_id:
                        report['users'][user_id]['api_calls'] += 1

                elif event_type == 'security_incident':
                    report['security_incidents']['total_incidents'] += 1
                    severity = event.get('severity', 'unknown')
                    incident_type = event.get('incident_type', 'unknown')

                    report['security_incidents']['by_severity'][severity] += 1
                    report['security_incidents']['by_type'][incident_type] += 1

                    if user_id:
                        report['users'][user_id]['security_incidents'] += 1

                elif event_type == 'mfa':
                    report['mfa']['verification_attempts'] += 1
                    success = event.get('success', False)

                    if success:
                        report['mfa']['successful_verifications'] += 1
                        if user_id:
                            report['mfa']['enabled_users'].add(user_id)
                    else:
                        report['mfa']['failed_verifications'] += 1

            # Convert sets to lists for JSON serialization
            report['mfa']['enabled_users'] = list(report['mfa']['enabled_users'])
            report['security_incidents']['by_severity'] = dict(report['security_incidents']['by_severity'])
            report['security_incidents']['by_type'] = dict(report['security_incidents']['by_type'])
            report['users'] = dict(report['users'])

            # Save report
            with open(self.compliance_report_file, 'w') as f:
                json.dump(report, f, indent=2)

            logger.info(f"Generated compliance report for period {start_date.date()} to {end_date.date()}")
            return report

        except Exception as e:
            logger.error(f"Failed to generate compliance report: {str(e)}")
            return {'error': str(e)}

    def cleanup_old_logs(self, days_to_keep: int = 90) -> int:
        """
        Clean up audit logs older than specified days
        Returns number of entries cleaned up
        """
        try:
            if not os.path.exists(self.audit_log_file):
                return 0

            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            temp_file = self.audit_log_file + '.tmp'
            cleaned_count = 0

            with open(self.audit_log_file, 'r') as f, open(temp_file, 'w') as temp_f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        event_date = datetime.fromisoformat(event['timestamp'])

                        if event_date >= cutoff_date:
                            temp_f.write(line)
                        else:
                            cleaned_count += 1

                    except (json.JSONDecodeError, KeyError):
                        # Keep malformed lines
                        temp_f.write(line)

            # Replace original file
            os.replace(temp_file, self.audit_log_file)

            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} old audit log entries")

            return cleaned_count

        except Exception as e:
            logger.error(f"Failed to cleanup old audit logs: {str(e)}")
            return 0

    def get_security_dashboard_data(self) -> Dict[str, Any]:
        """
        Get data for security dashboard
        """
        try:
            # Get last 7 days of events
            end_date = datetime.now()
            start_date = end_date - timedelta(days=7)

            events = self.get_audit_events(start_date, end_date, limit=5000)

            dashboard = {
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'metrics': {
                    'total_events': len(events),
                    'failed_logins': 0,
                    'security_incidents': 0,
                    'api_errors': 0,
                    'active_users': set()
                },
                'recent_events': events[-50:],  # Last 50 events
                'alerts': []
            }

            for event in events:
                event_type = event.get('event_type')
                user_id = event.get('user_id')

                if user_id:
                    dashboard['metrics']['active_users'].add(user_id)

                if event_type == 'authentication':
                    if not event.get('success', False):
                        dashboard['metrics']['failed_logins'] += 1

                elif event_type == 'security_incident':
                    dashboard['metrics']['security_incidents'] += 1

                    # Add high/critical incidents as alerts
                    severity = event.get('severity', '').lower()
                    if severity in ['high', 'critical']:
                        dashboard['alerts'].append({
                            'type': event.get('incident_type', 'unknown'),
                            'severity': severity,
                            'timestamp': event['timestamp'],
                            'user_id': user_id,
                            'details': event.get('details', {})
                        })

                elif event_type == 'api_access':
                    status_code = event.get('status_code', 0)
                    if status_code >= 500:
                        dashboard['metrics']['api_errors'] += 1

            # Convert set to int for JSON
            dashboard['metrics']['active_users'] = len(dashboard['metrics']['active_users'])

            return dashboard

        except Exception as e:
            logger.error(f"Failed to generate security dashboard data: {str(e)}")
            return {'error': str(e)}

# Global audit logger instance
audit_logger = AuditLogger()
