from django.core.validators import RegexValidator

password_regex_pattern = RegexValidator(
    regex=r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*+=]).{8,}$",
    message={
        "password": "Your Password Is Weak",
        "Hint": "Min. 8 characters, 1 letter, 1 number and 1 special character",
    },
)
