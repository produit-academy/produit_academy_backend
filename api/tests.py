from django.test import TestCase, override_settings
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.exceptions import ValidationError
from rest_framework.test import APITestCase
from rest_framework import status

from api.models import User
from api.validators import (
    validate_uploaded_file, sanitize_filename,
    ALLOWED_DOCUMENT_EXTENSIONS, ALLOWED_AUDIO_EXTENSIONS
)
from api.storage import CloudinaryMediaStorage
from classes_app.models import Course, ClassSession, ClassReport, TeacherMonthlyReport


class SecurityValidationTests(TestCase):
    """Tests for file upload validation, sanitization, and SSRF prevention."""

    def test_sanitize_filename(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("valid_report.pdf"), "valid_report.pdf")
        self.assertEqual(sanitize_filename("bad\x00file.png"), "badfile.png")

    def test_disallowed_executable_extensions_rejected(self):
        dangerous_files = ["shell.php", "hack.exe", "script.sh", "page.html", "xss.svg", "auto.bat"]
        for fname in dangerous_files:
            file_obj = SimpleUploadedFile(fname, b"malicious content", content_type="text/plain")
            with self.assertRaises(ValidationError):
                validate_uploaded_file(file_obj)

    def test_whitelist_extension_enforced(self):
        valid_pdf = SimpleUploadedFile("doc.pdf", b"%PDF-1.4...", content_type="application/pdf")
        # Should pass
        validate_uploaded_file(valid_pdf, allowed_extensions=ALLOWED_DOCUMENT_EXTENSIONS)

        invalid_mp4 = SimpleUploadedFile("video.mp4", b"video data", content_type="video/mp4")
        with self.assertRaises(ValidationError):
            validate_uploaded_file(invalid_mp4, allowed_extensions=ALLOWED_DOCUMENT_EXTENSIONS)

    def test_file_size_limit_enforced(self):
        oversized = SimpleUploadedFile("huge.pdf", b"0" * (1024 * 1024 * 35), content_type="application/pdf")
        with self.assertRaises(ValidationError):
            validate_uploaded_file(oversized, max_size_bytes=1024 * 1024 * 10)

    def test_storage_ssrf_protection(self):
        storage = CloudinaryMediaStorage()
        # Non-Cloudinary domains must be blocked
        blocked_internal = storage._open("http://169.254.169.254/latest/meta-data/")
        self.assertIsNone(blocked_internal)

        blocked_external = storage._open("https://evil-attacker.com/payload.pdf")
        self.assertIsNone(blocked_external)


class PasswordSecurityAndAccountEnumerationTests(APITestCase):
    """Tests for password validation and account enumeration prevention."""

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username="student@produit.com",
            email="student@produit.com",
            password="StrongPassword123!",
            role="student",
            platform="classes",
            is_active=True,
            is_verified=True,
        )

    def test_password_reset_enumeration_protection(self):
        # Non-existent user should return generic success, NOT 404
        response = self.client.post("/api/password-reset-otp/", {"email": "doesnotexist@nowhere.com"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("If an account exists", response.data.get("detail", ""))

    def test_password_reset_confirm_rejects_weak_passwords(self):
        self.user.otp = "123456"
        from django.utils import timezone
        from datetime import timedelta
        self.user.otp_expiry = timezone.now() + timedelta(minutes=10)
        self.user.save()

        # Try setting common/short password "12345678" or "password"
        response = self.client.post("/api/password-reset-confirm/", {
            "email": "student@produit.com",
            "otp": "123456",
            "password": "password"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Verify user's password did NOT change to the weak password
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("StrongPassword123!"))

    def test_login_brute_force_lockout(self):
        # 5 consecutive failed logins
        for i in range(5):
            self.client.post("/api/login/", {
                "email": "student@produit.com",
                "password": "WrongPassword!"
            })

        # 6th attempt should be locked out
        response = self.client.post("/api/login/", {
            "email": "student@produit.com",
            "password": "WrongPassword!"
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn("temporarily locked", str(response.data.get("detail", "")))


class AuthorizationAndIDORTests(APITestCase):
    """Tests for report authorization, IDOR, and role-based permissions."""

    def setUp(self):
        cache.clear()
        self.student = User.objects.create_user(
            username="student_idor@produit.com",
            email="student_idor@produit.com",
            password="StrongPassword123!",
            role="student",
            platform="classes",
            is_active=True,
            is_verified=True,
        )
        self.teacher = User.objects.create_user(
            username="teacher@produit.com",
            email="teacher@produit.com",
            password="StrongPassword123!",
            role="teacher",
            platform="classes",
            is_active=True,
            is_verified=True,
        )
        self.course = Course.objects.create(name="Class 10 Physics", description="Physics Course")
        from django.utils import timezone
        self.session = ClassSession.objects.create(
            course=self.course,
            teacher=self.teacher,
            student=self.student,
            title="Physics Lesson 1",
            scheduled_time=timezone.now(),
            duration_minutes=60,
            status="Completed"
        )
        self.report = ClassReport.objects.create(
            class_session=self.session,
            teacher=self.teacher,
            student=self.student,
            status="submitted",
            performance_rating=3,
            text_report="Good progress"
        )

    def test_student_cannot_modify_or_delete_class_report(self):
        self.client.force_authenticate(user=self.student)

        # Student attempts PATCH to modify rating or status
        response = self.client.patch(f"/api/classes/reports/{self.report.id}/", {
            "performance_rating": 5,
            "status": "approved"
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Student attempts DELETE on the report
        del_response = self.client.delete(f"/api/classes/reports/{self.report.id}/")
        self.assertEqual(del_response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertTrue(ClassReport.objects.filter(pk=self.report.id).exists())

    def test_teacher_cannot_self_approve_report(self):
        self.client.force_authenticate(user=self.teacher)

        # Teacher attempts to approve their own report
        response = self.client.patch(f"/api/classes/reports/{self.report.id}/", {
            "status": "approved"
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.report.refresh_from_db()
        self.assertEqual(self.report.status, "submitted")

    def test_teacher_cannot_delete_submitted_report(self):
        self.client.force_authenticate(user=self.teacher)
        response = self.client.delete(f"/api/classes/reports/{self.report.id}/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertTrue(ClassReport.objects.filter(pk=self.report.id).exists())

    def test_teacher_cannot_self_approve_monthly_report(self):
        self.client.force_authenticate(user=self.teacher)
        monthly_report = TeacherMonthlyReport.objects.create(
            teacher=self.teacher,
            month=10,
            year=2026,
            status="draft"
        )
        response = self.client.patch(f"/api/classes/monthly-reports/{monthly_report.id}/", {
            "status": "approved"
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Teacher cannot delete monthly report
        del_response = self.client.delete(f"/api/classes/monthly-reports/{monthly_report.id}/")
        self.assertEqual(del_response.status_code, status.HTTP_403_FORBIDDEN)

    def test_classes_change_password_validates_password(self):
        self.client.force_authenticate(user=self.student)
        # Try changing password to a weak password like "123"
        response = self.client.post("/api/classes/change-password/", {
            "current_password": "StrongPassword123!",
            "new_password": "123"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Try changing with correct strong password
        response = self.client.post("/api/classes/change-password/", {
            "current_password": "StrongPassword123!",
            "new_password": "NewStrongPass456#!"
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.student.refresh_from_db()
        self.assertTrue(self.student.check_password("NewStrongPass456#!"))

    def test_staff_change_password_validates_password(self):
        staff = User.objects.create_user(
            username="staff_member@produit.com",
            email="staff_member@produit.com",
            password="StrongPassword123!",
            role="staff",
            is_active=True,
            is_verified=True,
        )
        self.client.force_authenticate(user=staff)
        # Weak password should fail
        response = self.client.post("/api/staff/change-password/", {
            "current_password": "StrongPassword123!",
            "new_password": "weak",
            "confirm_password": "weak"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class SecurityHeadersMiddlewareTests(APITestCase):
    """Test that all responses contain critical security headers."""

    def test_security_headers_present(self):
        response = self.client.get("/api/branches/")
        self.assertEqual(response.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("camera=(self)", response.get("Permissions-Policy", ""))
        self.assertIn("default-src 'self'", response.get("Content-Security-Policy", ""))


class NewSecurityHardeningTests(APITestCase):
    """Tests for newly hardened security features."""

    def setUp(self):
        cache.clear()

    def test_csp_header_present(self):
        response = self.client.get("/api/branches/")
        self.assertIn("Content-Security-Policy", response)
        self.assertIn("frame-ancestors 'none'", response["Content-Security-Policy"])

    def test_session_revocation_on_password_reset(self):
        from api.models import Session
        from django.utils import timezone
        from datetime import timedelta
        user = User.objects.create_user(
            username="reset_target@produit.com",
            email="reset_target@produit.com",
            password="InitialPass123!@",
            role="student",
            is_active=True,
            is_verified=True,
        )
        user.otp = "123456"
        user.otp_expiry = timezone.now() + timedelta(minutes=5)
        user.save()

        # Simulate active session
        Session.objects.create(user=user, session_key="session_token_123")
        cache.set(f"user_active_session_{user.id}", "session_token_123", timeout=300)

        # Confirm password reset
        response = self.client.post("/api/password-reset-confirm/", {
            "email": user.email,
            "otp": "123456",
            "password": "NewStrongPass999#!"
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Session should be revoked
        self.assertFalse(Session.objects.filter(user=user).exists())
        self.assertIsNone(cache.get(f"user_active_session_{user.id}"))

    def test_dummy_payment_blocked_when_disabled(self):
        user = User.objects.create_user(
            username="student_dummy@produit.com",
            email="student_dummy@produit.com",
            password="StrongPass123!#",
            role="student",
            platform="classes",
            is_active=True,
            is_verified=True,
        )
        self.client.force_authenticate(user=user)
        with override_settings(ALLOW_DUMMY_PAYMENT=False):
            response = self.client.post("/api/classes/student/pay/", {"booking_id": 9999})
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_teacher_profile_patch_validates_password(self):
        teacher = User.objects.create_user(
            username="teacher_val@produit.com",
            email="teacher_val@produit.com",
            password="StrongPass123!#",
            role="teacher",
            platform="classes",
            is_active=True,
            is_verified=True,
        )
        self.client.force_authenticate(user=teacher)
        # Trivial password should fail
        response = self.client.patch("/api/classes/teacher/manage-profile/", {
            "password": "123"
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_teacher_profile_patch_validates_profile_picture_extension(self):
        teacher = User.objects.create_user(
            username="teacher_pic@produit.com",
            email="teacher_pic@produit.com",
            password="StrongPass123!#",
            role="teacher",
            platform="classes",
            is_active=True,
            is_verified=True,
        )
        self.client.force_authenticate(user=teacher)
        bad_pic = SimpleUploadedFile("avatar.exe", b"fake binary", content_type="application/octet-stream")
        response = self.client.patch("/api/classes/teacher/manage-profile/", {
            "profile_picture": bad_pic
        }, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_dateutil_dependency_available(self):
        from dateutil.parser import parse
        parsed_dt = parse("2026-11-01T10:00:00Z")
        self.assertEqual(parsed_dt.year, 2026)

    def test_voice_note_idor_prevention_for_unrelated_student(self):
        """Teachers cannot upload voice notes targeting students not enrolled with them."""
        teacher = User.objects.create_user(
            username="teacher_vn@produit.com",
            email="teacher_vn@produit.com",
            password="StrongPass123!#",
            role="teacher",
            platform="classes",
            is_active=True,
            is_verified=True,
        )
        unrelated_student = User.objects.create_user(
            username="student_unrelated@produit.com",
            email="student_unrelated@produit.com",
            password="StrongPass123!#",
            role="student",
            platform="classes",
            is_active=True,
            is_verified=True,
        )
        self.client.force_authenticate(user=teacher)
        audio = SimpleUploadedFile("voice.mp3", b"ID3 fake audio data", content_type="audio/mpeg")
        response = self.client.post("/api/classes/voice-notes/", {
            "student": unrelated_student.id,
            "audio_file": audio,
            "text_summary": "Test Note"
        }, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_voice_note_rejects_disallowed_file_type(self):
        """Malicious executable or script files cannot be uploaded as voice notes."""
        teacher = User.objects.create_user(
            username="teacher_file_test@produit.com",
            email="teacher_file_test@produit.com",
            password="StrongPass123!#",
            role="teacher",
            platform="classes",
            is_active=True,
            is_verified=True,
        )
        self.client.force_authenticate(user=teacher)
        bad_file = SimpleUploadedFile("malware.php", b"<?php phpinfo(); ?>", content_type="application/x-php")
        response = self.client.post("/api/classes/voice-notes/", {
            "audio_file": bad_file,
            "text_summary": "Test Note"
        }, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_unauthenticated_request_denied_by_default(self):
        """Unauthenticated requests to protected endpoints return 401 Unauthorized."""
        self.client.force_authenticate(user=None)
        response = self.client.get("/api/profile/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

