from django import forms
from django.contrib.auth import get_user_model
from django.core.validators import validate_email
from django.db.models import Q
from django.utils.translation import ugettext_lazy as _


class PasswordRecoveryForm(forms.Form):
    username_or_email = forms.CharField()

    def __init__(self, *args, **kwargs):
        self.case_sensitive = kwargs.pop('case_sensitive', True)
        search_fields = kwargs.pop('search_fields', ('username', 'email'))
        super(PasswordRecoveryForm, self).__init__(*args, **kwargs)

        message = ("No other fields than username and email are supported "
                   "by default")

        if len(search_fields) not in (1, 2):
            raise ValueError(message)
        for field in search_fields:
            if field not in ['username', 'email']:
                raise ValueError(message)

        labels = {
            'username': _('Username'),
            'email': _('Email'),
            'both': _('Username or Email'),
        }
        if len(search_fields) == 1:
            self.label_key = search_fields[0]
        else:
            self.label_key = 'both'
        self.fields['username_or_email'].label = labels[self.label_key]

    def clean_username_or_email(self):
        username = self.cleaned_data['username_or_email']
        cleaner = getattr(self, 'get_user_by_%s' % self.label_key)
        self.cleaned_data['user'] = cleaner(username)
        return username

    def get_user_by_username(self, username):
        user_model = get_user_model()
        key = 'username__%sexact' % ('' if self.case_sensitive else 'i')
        try:
            user = user_model.objects.get(**{key: username})
        except user_model.DoesNotExist:
            raise forms.ValidationError(_("Sorry, this user doesn't exist."))
        return user

    def get_user_by_email(self, email):
        user_model = get_user_model()
        validate_email(email)
        key = 'email__%sexact' % ('' if self.case_sensitive else 'i')
        try:
            user = user_model.objects.get(**{key: email})
        except user_model.DoesNotExist:
            raise forms.ValidationError(_("Sorry, this user doesn't exist."))
        return user

    def get_user_by_both(self, username):
        user_model = get_user_model()
        key = '__%sexact'
        key = key % '' if self.case_sensitive else key % 'i'
        f = lambda field: Q(**{field + key: username})
        filters = f('username') | f('email')
        try:
            user = user_model.objects.get(filters)
        except user_model.DoesNotExist:
            raise forms.ValidationError(_("Sorry, this user doesn't exist."))
        except user_model.MultipleObjectsReturned:
            raise forms.ValidationError(_("Unable to find user."))
        return user


class PasswordResetForm(forms.Form):
    password1 = forms.CharField(
        label=_('New password'),
        widget=forms.PasswordInput,
    )
    password2 = forms.CharField(
        label=_('New password (confirm)'),
        widget=forms.PasswordInput,
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super(PasswordResetForm, self).__init__(*args, **kwargs)

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1', '')
        password2 = self.cleaned_data['password2']
        if not password1 == password2:
            raise forms.ValidationError(_("The two passwords didn't match."))
        return password2

    def save(self):
        user_model = get_user_model()
        self.user.set_password(self.cleaned_data['password1'])
        user_model.objects.filter(pk=self.user.pk).update(
            password=self.user.password,
        )
