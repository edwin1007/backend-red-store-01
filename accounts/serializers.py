from rest_framework import serializers
from django.contrib.auth.models import User
import uuid
from django.contrib.auth import authenticate

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate_email(self, value):
        # Revisar si el email ya está registrado
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Este correo ya está registrado.")
        return value

    def create(self, validated_data):
        # Generar username único usando UUID
        username = str(uuid.uuid4())[:10]  # Django limita username a 150, pero aquí recortamos

        user = User.objects.create_user(
            username=username,
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if email and password:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise serializers.ValidationError("Correo o contraseña incorrectos.")

            user = authenticate(username=user.username, password=password)
            if user is None:
                raise serializers.ValidationError("Correo o contraseña incorrectos.")

        else:
            raise serializers.ValidationError("Debe ingresar email y contraseña.")

        data['user'] = user
        return data