from email import message
from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages

from django.views.generic import View

# urls for getting current site  and activate user account
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.urls import NoReverseMatch, reverse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, DjangoUnicodeDecodeError 
# ======================== for email =========================
from django.core.mail import send_mail, EmailMultiAlternatives
from django.core.mail import BadHeaderError, send_mail
from django.conf import settings
from django.core import mail
from django.core.mail.message import EmailMessage
# for sending email fast
from threading import Thread
# class TokenGenerator getting token from utils.py file in the same app
from .utils import TokenGenerator, generate_token, EmailThread

#==================import resetpassword generators====================
#you will be using this one to reset password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str


# Create your views here.
def handle_login(request):
    
    if request.method =="POST":
        username = request.POST['email']
        userpassword = request.POST['pass1']
        
        user = authenticate(username=username, password=userpassword)
        if user is not None:
            
            login(request, user)
            messages.success(request, "you're logged in ")
            return redirect('home')
        else:
            messages.error(request, "something went wrong ")
            return redirect("handle_login")
    else:
        return render(request, 'auth/login.html')

def handle_register(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        
        if password != confirm_password:
            messages.warning(request, "password is Not matching")
            return render(request, "auth/register.html")
        
        try:
            if User.objects.get(username=email):
                messages.warning(request, "email is Taken")
                return render(request, "auth/register.html")
              
        except Exception as identifier:
            pass
        
        user = User.objects.create_user(email, email, password)
        # Set is_staff to True if the user should have staff privileges
        # user.is_staff = False
        
        # Set is_active to False to require account activation
        # before sending a link you need to set is_active=false
        user.is_active = False
        user.save()
        # this how to get the url of the current site
        current_site = get_current_site(request)
        # sending email to a particular website like activate your account
        email_subject = "Activate Your Account"
        # sent a message, I want to send urls in form of encoded string format it will generate token so that it should activate the client 
      
        message = render_to_string('auth/activate.html', {
            'user': user,
            'domain': current_site,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            # for using generate_token you need to create a file called utils.py where you can generate token
            'token': generate_token.make_token(user)
        })
        # now you need to send message
        email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
        # by using email threading it will send the email 5 seconds faster
        EmailThread(email_message).start()
        messages.success(request, "We have sent you a Link in Your Email address To Activate your Account ")
        return redirect('handle_login')
        
    else:   
        return render(request, 'auth/register.html')

class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = str(urlsafe_base64_decode(uidb64), 'utf-8')
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.info(request, "Account activated successfully.")
            return redirect('handle_login')  
        else:
            return render(request, 'auth/activate_fail.html')

#==================logout start here===========================
# def logout(request):
    

#########################reset password function333333333333####################
class RequestResetEmailView(View):
    
    def get(self, request):
        return render(request, "auth/forgot_password.html")
    
    def post(self, request):
        email=request.POST['email']
        user=User.objects.filter(email=email)
       
        if user.exists():
            current_site = get_current_site(request)
            email_subject = "[Reset your password]"
        
            message = render_to_string('auth/reset_user_password.html', {
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0])
            })
            email_message = EmailMessage(email_subject, message, settings.EMAIL_HOST_USER, [email])
            EmailThread(email_message).start()
            messages.info(request, "We have sent you an email to reset reset your password ")
            return render(request, "auth/forgot_password.html")
        else:
            messages.error(request, "User with this email does not exist")
            return render(request, "auth/forgot_password.html")


#=====================set new password view======================
from django.core.exceptions import ValidationError

class SetView(View):
    #=========function for get request================
    def get(self, request, uidb64, token):
        try:
            user_id = urlsafe_base64_decode(uidb64)
            user = User.objects.get(pk=user_id)
            
            # Check if the token is valid
            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "The reset link is invalid")
                return render(request, 'auth/forgot_password.html')
    
        except (ValueError, ValidationError, User.DoesNotExist, DjangoUnicodeDecodeError) as identifier:
            messages.error(request, "An error occurred while processing your request")
            return render(request, 'auth/set_new_password.html')
        
        context = {
            'uid64': uidb64,
            'token': token
        }
        return render(request, 'auth/set_new_password.html', context)
    #================function for post request=============
    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token,
        }
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        
        if password != confirm_password:
            messages.warning(request, "password is Not matching")
            return render(request, "auth/set_new_password.html", context)
        
        try:
            user_id = force_bytes(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request, "pasword Reset Success PLease login with new passowrd")
            return redirect('handle_login')
            
        except DjangoUnicodeDecodeError as indentifier:
            messages.error(request, "something went wrong")
            
            return render(request, "auth/set_new_password.html", context)
