import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class UppercasePasswordValidator:
    def validate(self, password, user=None):
        if not re.search(r"[A-Z]", password):
            raise ValidationError(
                _("A senha deve conter pelo menos 1 letra maiuscula."),
                code="password_no_uppercase",
            )

    def get_help_text(self):
        return _("A senha deve conter pelo menos 1 letra maiuscula.")


class LowercasePasswordValidator:
    def validate(self, password, user=None):
        if not re.search(r"[a-z]", password):
            raise ValidationError(
                _("A senha deve conter pelo menos 1 letra minuscula."),
                code="password_no_lowercase",
            )

    def get_help_text(self):
        return _("A senha deve conter pelo menos 1 letra minuscula.")


class NumberPasswordValidator:
    def validate(self, password, user=None):
        if not re.search(r"\d", password):
            raise ValidationError(
                _("A senha deve conter pelo menos 1 numero."),
                code="password_no_number",
            )

    def get_help_text(self):
        return _("A senha deve conter pelo menos 1 numero.")


class SpecialCharacterPasswordValidator:
    def validate(self, password, user=None):
        if not re.search(r"[^A-Za-z0-9]", password):
            raise ValidationError(
                _("A senha deve conter pelo menos 1 caractere especial."),
                code="password_no_special",
            )

    def get_help_text(self):
        return _("A senha deve conter pelo menos 1 caractere especial.")
