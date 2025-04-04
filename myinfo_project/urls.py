from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/myinfo/', include('myinfo_api.urls')),
    path('callback/', include('myinfo_api.urls'))
]