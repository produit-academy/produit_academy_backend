from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('classes_app', '0004_classsession_is_demo_classsession_student_and_more'),
    ]

    operations = [
        # 1. Add new fields to ClassSession
        migrations.AddField(
            model_name='classsession',
            name='cancel_reason',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='classsession',
            name='cancelled_by',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='cancelled_sessions',
                to=settings.AUTH_USER_MODEL,
            ),
        ),

        # 2. Remove old unique_together on TeacherAvailability (if any)
        migrations.AlterUniqueTogether(
            name='teacheravailability',
            unique_together=set(),
        ),

        # 3. Remove old day_of_week field
        migrations.RemoveField(
            model_name='teacheravailability',
            name='day_of_week',
        ),

        # 4. Change teacher FK from TeacherProfile to User
        migrations.AlterField(
            model_name='teacheravailability',
            name='teacher',
            field=models.ForeignKey(
                limit_choices_to={'role': 'teacher'},
                on_delete=django.db.models.deletion.CASCADE,
                related_name='teacher_availabilities',
                to=settings.AUTH_USER_MODEL,
            ),
        ),

        # 5. Add new date field
        migrations.AddField(
            model_name='teacheravailability',
            name='date',
            field=models.DateField(default=django.utils.timezone.now),
            preserve_default=False,
        ),

        # 6. Add created_at field
        migrations.AddField(
            model_name='teacheravailability',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),

        # 7. Set new unique_together AFTER date field exists
        migrations.AlterUniqueTogether(
            name='teacheravailability',
            unique_together={('teacher', 'date', 'start_time')},
        ),

        # 8. Update Meta options
        migrations.AlterModelOptions(
            name='teacheravailability',
            options={'ordering': ['date', 'start_time']},
        ),
    ]
