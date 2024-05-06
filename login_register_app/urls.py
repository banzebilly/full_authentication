from django.contrib import admin
from django.urls import path 
from . import views

urlpatterns = [

    path('login/', views.handle_login, name='handle_login'),
    path('register/', views.handle_register, name='handle_register'),
    
    path('activate/<uidb64>/<token>', views.ActivateAccountView.as_view(), name='activate'),
    path('forgot_password/', views.RequestResetEmailView.as_view(), name="forgot_password"),
    path('set_new_password/<uidb64>/<token>', views.SetView.as_view(), name="set_new_password"),
    
    
]
