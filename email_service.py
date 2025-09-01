"""
Professional Email Notification Service for Domain Upgrade Pro
Uses existing SMTP configuration from database
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from models import SMTPSettings
import logging

logger = logging.getLogger(__name__)

class EmailService:
    """Professional email service for user notifications"""
    
    def __init__(self):
        self.smtp_settings = None
        self._load_smtp_settings()
    
    def _load_smtp_settings(self):
        """Load active SMTP settings from database"""
        try:
            self.smtp_settings = SMTPSettings.query.filter_by(is_active=True).first()
        except Exception as e:
            logger.error(f"Failed to load SMTP settings: {e}")
            self.smtp_settings = None
    
    def _send_email(self, to_email, subject, html_body, text_body=None):
        """Send email using SMTP configuration"""
        if not self.smtp_settings:
            logger.error("No active SMTP settings found")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.smtp_settings.sender_name} <{self.smtp_settings.sender_email}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            
            # Add text version if provided
            if text_body:
                text_part = MIMEText(text_body, 'plain')
                msg.attach(text_part)
            
            # Add HTML version
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
            
            # Send email
            server = smtplib.SMTP(self.smtp_settings.smtp_server, self.smtp_settings.smtp_port)
            server.starttls()
            server.login(self.smtp_settings.smtp_username, self.smtp_settings.smtp_password)
            text = msg.as_string()
            server.sendmail(self.smtp_settings.sender_email, to_email, text)
            server.quit()
            
            logger.info(f"Email sent successfully to {to_email}: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False
    
    def _get_base_template(self, title, content):
        """Get professional HTML email template"""
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{title}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f4f4f4;
                }}
                .email-container {{
                    background-color: white;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                .header {{
                    text-align: center;
                    border-bottom: 3px solid #4f46e5;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }}
                .logo {{
                    font-size: 28px;
                    font-weight: bold;
                    color: #4f46e5;
                    margin-bottom: 10px;
                }}
                .subtitle {{
                    color: #6b7280;
                    font-size: 16px;
                }}
                .content {{
                    margin: 30px 0;
                }}
                .highlight {{
                    background-color: #f3f4f6;
                    padding: 20px;
                    border-radius: 8px;
                    border-left: 4px solid #4f46e5;
                    margin: 20px 0;
                }}
                .footer {{
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #e5e7eb;
                    text-align: center;
                    color: #6b7280;
                    font-size: 14px;
                }}
                .button {{
                    display: inline-block;
                    background-color: #4f46e5;
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 6px;
                    font-weight: 500;
                    margin: 10px 0;
                }}
                .success {{ color: #059669; }}
                .warning {{ color: #d97706; }}
                .info {{ color: #2563eb; }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="header">
                    <div class="logo">Domain Upgrade Pro</div>
                    <div class="subtitle">Professional Domain Research Platform</div>
                </div>
                
                <div class="content">
                    {content}
                </div>
                
                <div class="footer">
                    <p>This is an automated message from Domain Upgrade Pro.</p>
                    <p>If you have any questions, please contact our support team.</p>
                    <p>© {datetime.now().year} Domain Upgrade Pro. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def send_welcome_email(self, user_email, user_name):
        """Send welcome email to new users"""
        subject = "Welcome to Domain Upgrade Pro! 🚀"
        
        content = f"""
        <h2>Welcome aboard, {user_name}!</h2>
        <p>Thank you for joining Domain Upgrade Pro, the premier platform for domain research and competitive analysis.</p>
        
        <div class="highlight">
            <h3>🎯 What You Can Do:</h3>
            <ul>
                <li><strong>Bulk Keyword Research</strong> - Process thousands of keywords at once</li>
                <li><strong>Google Search Analysis</strong> - Get detailed search results with rankings</li>
                <li><strong>Competitor Research</strong> - Discover domains ranking for your keywords</li>
                <li><strong>CSV Export</strong> - Download all results for analysis</li>
            </ul>
        </div>
        
        <p>You've received <strong>50 free trial coins</strong> to get started with your first searches.</p>
        
        <p style="text-align: center;">
            <a href="{self._get_app_url()}" class="button">Start Your First Search</a>
        </p>
        
        <p>Need help getting started? Check out our platform or contact our support team.</p>
        
        <p>Welcome to the future of domain research!</p>
        """
        
        html_body = self._get_base_template("Welcome to Domain Upgrade Pro", content)
        return self._send_email(user_email, subject, html_body)
    
    def send_credit_purchase_notification(self, user_email, user_name, amount, coins_added, transaction_id):
        """Send notification for credit purchases"""
        subject = f"Payment Confirmed - {coins_added} Credits Added ✅"
        
        content = f"""
        <h2>Payment Successfully Processed!</h2>
        <p>Hi {user_name},</p>
        <p>Your payment has been successfully processed and your credits have been added to your account.</p>
        
        <div class="highlight">
            <h3>📊 Transaction Details:</h3>
            <ul>
                <li><strong>Amount Paid:</strong> ${amount:.2f}</li>
                <li><strong>Credits Added:</strong> {coins_added:,} coins</li>
                <li><strong>Transaction ID:</strong> {transaction_id}</li>
                <li><strong>Date:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</li>
            </ul>
        </div>
        
        <p>Your credits are now available and ready to use for your keyword research projects.</p>
        
        <p style="text-align: center;">
            <a href="{self._get_app_url()}" class="button">Start Searching Now</a>
        </p>
        
        <p>Thank you for choosing Domain Upgrade Pro!</p>
        """
        
        html_body = self._get_base_template("Payment Confirmation", content)
        return self._send_email(user_email, subject, html_body)
    
    def send_password_change_notification(self, user_email, user_name, changed_by_admin=False):
        """Send notification for password changes"""
        if changed_by_admin:
            subject = "🔐 Your Password Has Been Changed by Administrator"
            content = f"""
            <h2>Password Changed by Administrator</h2>
            <p>Hi {user_name},</p>
            <p class="warning"><strong>Important Security Notice:</strong></p>
            <p>Your account password has been changed by a system administrator.</p>
            
            <div class="highlight">
                <h3>⚡ Action Required:</h3>
                <ul>
                    <li>You'll need to log in with your new password</li>
                    <li>Consider changing your password again for security</li>
                    <li>Contact support if you didn't request this change</li>
                </ul>
            </div>
            
            <p>If you have any concerns about this change, please contact our support team immediately.</p>
            """
        else:
            subject = "🔐 Password Successfully Changed"
            content = f"""
            <h2>Password Successfully Updated</h2>
            <p>Hi {user_name},</p>
            <p class="success">Your password has been successfully changed.</p>
            
            <div class="highlight">
                <h3>🔒 Security Information:</h3>
                <ul>
                    <li><strong>Changed:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</li>
                    <li><strong>Your account is secure</strong></li>
                    <li>Make sure to keep your new password safe</li>
                </ul>
            </div>
            
            <p>If you didn't make this change, please contact our support team immediately.</p>
            """
        
        html_body = self._get_base_template("Password Change Notification", content)
        return self._send_email(user_email, subject, html_body)
    
    def send_account_status_change_notification(self, user_email, user_name, is_active):
        """Send notification for account status changes"""
        if is_active:
            subject = "✅ Your Account Has Been Activated"
            status_text = "activated"
            status_class = "success"
            message = "You can now access all features of Domain Upgrade Pro."
        else:
            subject = "⚠️ Your Account Has Been Deactivated"
            status_text = "deactivated"
            status_class = "warning"
            message = "Your access to Domain Upgrade Pro has been temporarily suspended."
        
        content = f"""
        <h2>Account Status Update</h2>
        <p>Hi {user_name},</p>
        <p class="{status_class}">Your account has been <strong>{status_text}</strong> by a system administrator.</p>
        
        <div class="highlight">
            <h3>📋 Account Status:</h3>
            <ul>
                <li><strong>Status:</strong> {'Active' if is_active else 'Deactivated'}</li>
                <li><strong>Changed:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</li>
                <li><strong>Action:</strong> {message}</li>
            </ul>
        </div>
        
        <p>If you have questions about this change, please contact our support team.</p>
        """
        
        html_body = self._get_base_template("Account Status Change", content)
        return self._send_email(user_email, subject, html_body)
    
    def send_coin_adjustment_notification(self, user_email, user_name, amount, reason, new_balance):
        """Send notification for coin balance adjustments"""
        if amount > 0:
            subject = f"💰 {amount} Credits Added to Your Account"
            action = "added to"
            status_class = "success"
            icon = "💰"
        else:
            subject = f"📉 {abs(amount)} Credits Deducted from Your Account"
            action = "deducted from"
            status_class = "info"
            icon = "📉"
        
        content = f"""
        <h2>{icon} Account Balance Updated</h2>
        <p>Hi {user_name},</p>
        <p>Your credit balance has been updated by a system administrator.</p>
        
        <div class="highlight">
            <h3>💳 Transaction Details:</h3>
            <ul>
                <li><strong>Credits {action.split()[0].title()}:</strong> {abs(amount):,} coins</li>
                <li><strong>Reason:</strong> {reason or 'Administrative adjustment'}</li>
                <li><strong>New Balance:</strong> {new_balance:,} coins</li>
                <li><strong>Date:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</li>
            </ul>
        </div>
        
        <p>Your updated balance is now available for keyword searches.</p>
        
        <p style="text-align: center;">
            <a href="{self._get_app_url()}" class="button">View Your Account</a>
        </p>
        """
        
        html_body = self._get_base_template("Credit Balance Update", content)
        return self._send_email(user_email, subject, html_body)
    
    def send_search_completion_notification(self, user_email, user_name, keywords_count, total_results, credits_used):
        """Send notification when a large search is completed"""
        subject = f"🎯 Search Complete - {total_results:,} Results Found"
        
        content = f"""
        <h2>🎯 Your Search is Complete!</h2>
        <p>Hi {user_name},</p>
        <p>Your bulk keyword search has finished processing successfully.</p>
        
        <div class="highlight">
            <h3>📊 Search Results:</h3>
            <ul>
                <li><strong>Keywords Processed:</strong> {keywords_count:,}</li>
                <li><strong>Total Results Found:</strong> {total_results:,}</li>
                <li><strong>Credits Used:</strong> {credits_used:,}</li>
                <li><strong>Completed:</strong> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</li>
            </ul>
        </div>
        
        <p>You can now download your results and analyze the data.</p>
        
        <p style="text-align: center;">
            <a href="{self._get_app_url()}/business-search" class="button">View Results</a>
        </p>
        """
        
        html_body = self._get_base_template("Search Complete", content)
        return self._send_email(user_email, subject, html_body)
    
    def _get_app_url(self):
        """Get the application URL"""
        # You can configure this in your settings or use environment variable
        return "https://your-domain.replit.app"  # Update with your actual domain

# Global instance
email_service = EmailService()