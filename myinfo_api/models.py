from django.db import models

class MyInfoProfile(models.Model):
    uinfin = models.CharField(max_length=9, unique=True)
    name = models.CharField(max_length=255)
    email = models.EmailField(null=True, blank=True)
    mobile = models.CharField(max_length=20, null=True, blank=True)
    dob = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "MyInfo Profile"
        verbose_name_plural = "MyInfo Profiles"
    
    def __str__(self):
        return f"{self.name} ({self.uinfin})"