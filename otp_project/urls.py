from django.contrib import admin
from django.urls import path
from otp_app import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),  # Adding the admin URL pattern
    path('', views.register_view, name='register'),
    path('get-otp/', views.get_otp_view, name='get_otp'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
    path('create-user/', views.create_user_view, name='create_user'),
    path('success/', lambda request: render(request, 'success.html'), name='success'),

   path('login/', views.login_view, name='login'),
    path('home/', views.home, name='home'),
    path('coffee/', views.coffee, name='coffee'),



    path('admin-login/', views.admin_login, name='admin_login'),
    path('manage-users/', views.manage_users, name='manage_users'),
    path('delete-user/<int:user_id>/', views.delete_user, name='delete_user'),
     path('admin-logout/', views.admin_logout, name='admin_logout'),
]


if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
