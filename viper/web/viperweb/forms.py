# from django import forms
# from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm


class MyAuthenticationForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super(MyAuthenticationForm, self).__init__(*args, **kwargs)
        self.fields['username'].widget.attrs['placeholder'] = u'Username'
        self.fields['password'].widget.attrs['placeholder'] = u'Password'
