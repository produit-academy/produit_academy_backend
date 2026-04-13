from api.models import (
    StaffProfile as BaseStaffProfile,
    StaffTask as BaseStaffTask,
    TaskComment as BaseTaskComment,
)


class StaffProfile(BaseStaffProfile):
    class Meta:
        proxy = True
        verbose_name = 'Staff Profile'
        verbose_name_plural = 'Staff Profiles'


class StaffTask(BaseStaffTask):
    class Meta:
        proxy = True
        verbose_name = 'Staff Task'
        verbose_name_plural = 'Staff Tasks'


class TaskComment(BaseTaskComment):
    class Meta:
        proxy = True
        verbose_name = 'Task Comment'
        verbose_name_plural = 'Task Comments'
