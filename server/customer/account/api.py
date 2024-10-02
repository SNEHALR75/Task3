from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny, BasePermission
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.viewsets import ModelViewSet
from rest_framework.generics import RetrieveAPIView, ListAPIView, CreateAPIView
from rest_framework.views import APIView
from .serializers import UserSerializer
from account.autheticate import CustomAuthentication
from django.middleware import csrf
from django.conf import settings
from rest_framework_simplejwt import tokens as jwt_tokens, views as jwt_views, serializers as jwt_serializers, exceptions as jwt_exceptions

from django.contrib.auth import get_user_model
User = get_user_model()


import logging
logger = logging.getLogger(__name__)



class SignUpView(CreateAPIView):
    serializer_class = UserSerializer
    queryset = User.objects.all()

    def perform_create(self, serializer):
        serializer.save()
        logger.info(f"New User created: {serializer.data['username']}")






def get_tokens_for_user(user):
    refresh = jwt_tokens.RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }



class SignInView(APIView):

    def post(self,request):
        response = Response()
        try:
            username=request.data.get('username')
            password=request.data.get('password')
            user = User.objects.get( username=username )
        except:
            return Response(data={"detail":"Incorrect un/pw."},status=400)
        else:
            if user.check_password(password):
                if not user.is_active:
                    return Response(data={"detail":"Inactive Account."},status=400)

                tokens = get_tokens_for_user(user)
                response = Response(data=tokens)
                response.set_cookie(
                        key = settings.SIMPLE_JWT['AUTH_COOKIE'], 
                        value = tokens["access"],
                        expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                        secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                        httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                        samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                    )
                response.set_cookie(
                        key = settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'], 
                        value = tokens["refresh"],
                        expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                        secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                        httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                        samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                    )

                logger.info(f"User logged in: {user.username}")

            else:
                return Response(data={"detail":"Incorrect un/pw."},status=400)
            response["X-CSRFToken"] = csrf.get_token(request)
            return response









class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        response = Response()
        try:
            refreshToken = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            token = jwt_tokens.RefreshToken(refreshToken)
            token.blacklist()
        except Exception as e:
            print(e)
            response = Response(data={"detail": "Invalid Token."},status=400)
        finally:
            response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
            response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            response.delete_cookie("X-CSRFToken")
            response.delete_cookie("csrftoken")
            response["X-CSRFToken"]=None
        logger.info(f"User logged out: {request.user.username}")
        return response
            



class UserInfoView(APIView):
    permission_classes = [IsAuthenticated,]
    authentication_classes = [CustomAuthentication,]
    def get(self,request):
        serializer = UserSerializer(request.user)
        return Response( data=serializer.data, status=200 )



class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs['refresh'] = self.context['request'].COOKIES.get('refresh')
        if attrs['refresh']:
            return super().validate(attrs)
        else:
            raise jwt_exceptions.InvalidToken("No valid token found in cookie 'refresh'.")


class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer

    def finalize_response(self, request, response, *args, **kwargs):
        print( response.data )   
        try:
            response["X-CSRFToken"] = request.COOKIES.get("csrftoken")
            response.set_cookie(
                            key = settings.SIMPLE_JWT['AUTH_COOKIE'], 
                            value = response.data["access"],
                            expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                            secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                            httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                            samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                        )

        except Exception as e:
            print(e)

        return super().finalize_response(request, response, *args, **kwargs)










