#here you need to import six where to generate token go and install it siz is model
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six

class TokenGenerator(PasswordResetTokenGenerator):
    #hash particular password
    def _make_hash_value(self, user, timestamp:int):
        return (six.text_type(user.pk)+six.text_type(timestamp)+six.text_type(user.is_active))

generate_token=TokenGenerator()
        
 
 
 
#using tread to send email in second
from threading import Thread

class EmailThread(Thread):
    def __init__(self, email_message):
        self.email_message = email_message
        super(EmailThread, self).__init__()

    def run(self):
        self.email_message.send()
 