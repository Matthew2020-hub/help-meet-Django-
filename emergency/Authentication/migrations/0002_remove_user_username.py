# Generated by Django 3.2.10 on 2022-07-12 15:57

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("Authentication", "0001_initial"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="user",
            name="username",
        ),
    ]
