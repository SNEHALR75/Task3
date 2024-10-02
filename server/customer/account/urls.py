from django.urls import path
from .api import *



urlpatterns = [
	path('signin/',SignInView.as_view() ),
	path('signup/',SignUpView.as_view() ),
	path('user/info/',UserInfoView.as_view()),
	path('logout/',LogoutView.as_view() ),
	path('refresh/',CookieTokenRefreshView.as_view())

]









