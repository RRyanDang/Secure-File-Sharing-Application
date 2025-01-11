from django.contrib.auth import views as auth_views
from django.urls import path
from django.views.generic import RedirectView  # Import RedirectView for redirection
from . import views


urlpatterns = [
    path('', RedirectView.as_view(url='/login/', permanent=False)),  # Redirect root URL to login
    path('home/', views.home, name='home'),
    path('download/<int:file_id>', views.download_file, name='download_file'),
    path("login/", auth_views.LoginView.as_view(template_name="login.html"), name="login"),
    path("logout/", auth_views.LogoutView.as_view(template_name="logout.html"), name="logout"),
    path('my_files/', views.my_files, name='my_files'),
    path('view_file/', views.view_file, name='view_file'),
    path("register/", views.register, name="register"),
    path('share/<int:file_id>/', views.share_file, name='share_file'),
    path('upload/', views.upload_file, name='upload_file'),
]