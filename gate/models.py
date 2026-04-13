from api.models import (
    StudyMaterial as BaseStudyMaterial,
    CourseRequest as BaseCourseRequest,
    Question as BaseQuestion,
    Choice as BaseChoice,
    MockTest as BaseMockTest,
    MockTestQuestion as BaseMockTestQuestion,
)


class StudyMaterial(BaseStudyMaterial):
    class Meta:
        proxy = True
        verbose_name = 'Study Material'
        verbose_name_plural = 'Study Materials'


class CourseRequest(BaseCourseRequest):
    class Meta:
        proxy = True
        verbose_name = 'Course Request'
        verbose_name_plural = 'Course Requests'


class Question(BaseQuestion):
    class Meta:
        proxy = True
        verbose_name = 'Question'
        verbose_name_plural = 'Questions'


class Choice(BaseChoice):
    class Meta:
        proxy = True
        verbose_name = 'Choice'
        verbose_name_plural = 'Choices'


class MockTest(BaseMockTest):
    class Meta:
        proxy = True
        verbose_name = 'Mock Test'
        verbose_name_plural = 'Mock Tests'


class MockTestQuestion(BaseMockTestQuestion):
    class Meta:
        proxy = True
        verbose_name = 'Mock Test Question'
        verbose_name_plural = 'Mock Test Questions'
