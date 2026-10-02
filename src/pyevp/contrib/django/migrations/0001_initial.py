from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="UsedToken",
            fields=[
                ("key", models.CharField(max_length=64, primary_key=True, serialize=False)),
                ("expires_at", models.DateTimeField(db_index=True)),
            ],
        ),
    ]
