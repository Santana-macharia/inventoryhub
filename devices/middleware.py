"""
Session Timeout and Cache Control Middleware
Location: devices/middleware.py

This middleware handles:
1. Auto-logout after 20 minutes of inactivity
2. Clears browser cache to force fresh content
3. Session security and cleanup
"""

from django.contrib.auth import logout
from django.shortcuts import redirect
from django.utils import timezone
from django.conf import settings
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class SessionTimeoutMiddleware:
    """
    Middleware to automatically logout users after 20 minutes of inactivity
    and add cache control headers to prevent browser caching.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Session timeout in seconds (20 minutes)
        self.timeout = getattr(settings, 'SESSION_COOKIE_AGE', 1200)
    
    def __call__(self, request):
        # Process the request
        if request.user.is_authenticated:
            # Get the last activity timestamp from session
            last_activity = request.session.get('last_activity')
            
            if last_activity:
                # Convert string to datetime if stored as string
                if isinstance(last_activity, str):
                    try:
                        last_activity = datetime.fromisoformat(last_activity)
                    except (ValueError, TypeError):
                        last_activity = None
                
                # Check if session has expired
                if last_activity:
                    time_since_last_activity = (timezone.now() - last_activity).total_seconds()
                    
                    if time_since_last_activity > self.timeout:
                        # Session has expired - logout user
                        logger.info(f"Session expired for user: {request.user.username}")
                        
                        # Clear all session data
                        request.session.flush()
                        
                        # Logout the user
                        logout(request)
                        
                        # Redirect to login page with message
                        from django.contrib import messages
                        messages.warning(request, 'Your session has expired due to inactivity. Please login again.')
                        return redirect('login')
            
            # Update last activity timestamp
            request.session['last_activity'] = timezone.now().isoformat()
        
        # Get the response
        response = self.get_response(request)
        
        # Add cache control headers to prevent browser caching
        response = self.add_cache_control_headers(response, request)
        
        return response
    
    def add_cache_control_headers(self, response, request):
        """
        Add headers to prevent browser caching of pages.
        This ensures users always get fresh content after deployment.
        """
        
        # Only add cache headers for HTML responses (not static files)
        content_type = response.get('Content-Type', '')
        
        # Skip cache headers for static files, media files, and certain endpoints
        if any([
            '/static/' in request.path,
            '/media/' in request.path,
            request.path.startswith('/admin/jsi18n/'),
            'text/css' in content_type,
            'javascript' in content_type,
            'image/' in content_type,
            'font/' in content_type,
        ]):
            return response
        
        # Add comprehensive cache control headers for HTML pages
        response['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response['Pragma'] = 'no-cache'
        response['Expires'] = '0'
        
        # Add additional headers to prevent caching
        if 'text/html' in content_type or not content_type:
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate, private, max-age=0'
            response['X-Content-Type-Options'] = 'nosniff'
            
            # Add ETag based on current time to force revalidation
            response['ETag'] = f'"{timezone.now().timestamp()}"'
        
        return response


class ClearExpiredSessionsMiddleware:
    """
    Optional middleware to periodically clear expired sessions from database.
    This helps keep the session table clean.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.cleanup_counter = 0
        self.cleanup_frequency = 100  # Clear expired sessions every 100 requests
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Periodically clear expired sessions
        self.cleanup_counter += 1
        if self.cleanup_counter >= self.cleanup_frequency:
            self.cleanup_counter = 0
            try:
                from django.contrib.sessions.models import Session
                Session.objects.filter(expire_date__lt=timezone.now()).delete()
                logger.info("Cleared expired sessions from database")
            except Exception as e:
                logger.error(f"Error clearing expired sessions: {e}")
        
        return response