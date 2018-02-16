from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import current_app as app

import logging
import smtplib

logger = logging.getLogger('kqueen_ui')


class EmailMessage:

    def __init__(self, subject='', html='', text='', recipients=[], sender=None, timeout=None):
        # message parameters
        self.html = html
        self.text = text
        self.subject = subject
        self.recipients = ', '.join(recipients)
        self.sender = sender or app.config.get('MAIL_DEFAULT_SENDER')

        # server parameters
        self.server = app.config.get('MAIL_SERVER', 'localhost')
        self.port = app.config.get('MAIL_PORT', 25)
        self.timeout = timeout or app.config.get('MAIL_CONN_TIMEOUT')
        self.use_ssl = app.config.get('MAIL_USE_SSL', False)
        self.ssl_keyfile = app.config.get('MAIL_SSL_KEYFILE')
        self.ssl_certfile = app.config.get('MAIL_SSL_CERTFILE')
        self.username = app.config.get('MAIL_USERNAME', '')
        self.password = app.config.get('MAIL_PASSWORD', '')

    def _get_message(self):
        message = MIMEMultipart('alternative')
        message['Subject'] = self.subject
        message['From'] = self.sender
        message['To'] = self.recipients

        part1 = MIMEText(self.text, 'plain')
        part2 = MIMEText(self.html, 'html')

        message.attach(part1)
        message.attach(part2)
        return message

    def _get_server(self):
        if self.use_ssl:
            server = smtplib.SMTP_SSL(self.server, self.port, keyfile=self.ssl_keyfile, certfile=self.ssl_certfile, timeout=self.timeout)
        else:
            server = smtplib.SMTP(self.server, self.port, timeout=self.timeout)
        if self.username and self.password:
            server.login(self.username, self.password)
        return server

    def send(self):
        message = self._get_message()
        logger.debug('E-Mail with subject "{}" sent to {} containing following message: {}'.format(self.subject, self.recipients, message))
        if app.testing:
            logger.debug('E-Mail not sent, application is in testing mode')
            return
        server = self._get_server()
        server.send_message(message, self.sender, self.recipients)
        server.quit()
