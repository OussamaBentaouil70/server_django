import base64
from django.conf import settings
import jwt
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login

from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.authentication import JWTAuthentication

from .serializers import UserSerializer, MemberSerializer, OwnerSerializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
import requests
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from .models import Member, Owner, Rule
from django.db import models
 # Assuming you have these models defined



def create_dynamic_model_class(tag):
    class Meta:
        managed = False

    attrs = {
        '__module__': __name__,
        'tag': models.CharField(max_length=100),
        'name': models.CharField(max_length=255),
        'description': models.TextField(),
        'Meta': Meta,
    }

    model_class = type(f'Rule_{tag.replace(" ", "_")}', (models.Model,), attrs)
    return model_class





@api_view(['POST'])
def register_user(request):
    data = request.data
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')
    fonction = data.get('fonction')

    if not username:
        return Response({'error': 'Username is required'}, status=status.HTTP_400_BAD_REQUEST)

    Model = Owner if role == 'owner' else Member  # Determine the appropriate model based on the role

    if Model.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

    if not password or len(password) < 6:
        return Response({'error': 'Password is required and should be at least 6 characters long'}, status=status.HTTP_400_BAD_REQUEST)

    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    if Model.objects.filter(email=email).exists():
        return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

    user = Model.objects.create(
        username=username,
        email=email,
        password=make_password(password),
        role=role,
        fonction=fonction
    )
    
    serializer = UserSerializer(user)
    return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(['POST'])
def login_user(request):
    data = request.data
    email = data.get('email')
    password = data.get('password')

    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    if not password:
        return Response({'error': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(request, email=email, password=password)

    if user is None:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    update_last_login(None, user)
    user_data = UserSerializer(user).data
    refresh = RefreshToken.for_user(user)
    refresh['user'] = user_data
    access_token = str(refresh.access_token)
    
    
    response_data = {
          'token': access_token,
        'user': user_data,
    }   

    if user.role == 'owner':
        members = Member.objects.filter(owner=user)
        members_serializer = MemberSerializer(members, many=True)
        response_data['members'] = members_serializer.data

    return Response(response_data, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile(request):
    user = request.user
    serializer = UserSerializer(user)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_user(request):
    response = Response({'message': 'Logged out'}, status=status.HTTP_200_OK)
    response.delete_cookie('token')
    return response

# Member management by owner

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_member_by_owner(request):
    owner = request.user

    if owner.role != 'owner':
        return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)

    data = request.data
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    fonction = data.get('fonction')

    if not fonction:
        return Response({'error': 'Fonction is required'}, status=status.HTTP_400_BAD_REQUEST)

    if Member.objects.filter(username=username).exists() or Member.objects.filter(email=email).exists():
        return Response({'error': 'Username or email already exists'}, status=status.HTTP_400_BAD_REQUEST)

    hashed_password = make_password(password)
    member = Member.objects.create(
        username=username,
        email=email,
        password=hashed_password,
        role='member',
        fonction=fonction,
        owner=owner
    )

    owner.members.add(member)
    owner.save()

    serializer = MemberSerializer(member)
    return Response(serializer.data, status=status.HTTP_201_CREATED)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_member_by_owner(request, user_id):
    owner = request.user

    if owner.role != 'owner':
        return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)

    data = request.data
    username = data.get('username')
    email = data.get('email')
    fonction = data.get('fonction')

    if not fonction:
        return Response({'error': 'Fonction is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        member = Member.objects.get(id=user_id, owner=owner)
        member.username = username
        member.email = email
        member.fonction = fonction
        member.save()

        serializer = MemberSerializer(member)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Member.DoesNotExist:
        return Response({'error': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_member_by_owner(request, user_id):
    owner = request.user

    if owner.role != 'owner':
        return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)

    try:
        member = Member.objects.get(id=user_id, owner=owner)
        member.delete()
        return Response({'message': 'Member deleted successfully'}, status=status.HTTP_200_OK)
    except Member.DoesNotExist:
        return Response({'error': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_members_by_owner(request):
    owner = request.user

    if owner.role != 'owner':
        return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)

    members = Member.objects.filter(owner=owner)
    serializer = MemberSerializer(members, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_member_by_id(request, member_id):
    owner = request.user

    if owner.role != 'owner':
        return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)

    try:
        member = Member.objects.get(id=member_id, owner=owner)
        serializer = MemberSerializer(member)
        return Response(serializer.data)
    except Member.DoesNotExist:
        return Response({'error': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_rules_by_tag(request):
    ELASTIC_PASSWORD = "Nfk6eckgfUx0jhTcPb_G"
    try:
        # Extract the token from the request headers
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Token missing or invalid'}, status=400)
        
        token = auth_header.split(' ')[1]
        print("Token:", token)
        
        # Decode the token to get the payload
        try:
            decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            print("Decoded token:", decoded_token)
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid token'}, status=401)

        # Access user attributes from the token payload
        user_data = decoded_token.get('user', {})
        fonction = user_data.get('fonction')
        # Access other user attributes as needed
        
        if not fonction:
            return JsonResponse({'error': 'User function not found in token.'}, status=400)
        
        print("User function:", fonction)
        
        query = {
            "query": {
                "match": {
                    "tag": fonction,
                }
            }
        }
        
        url = "https://localhost:9200/rules/_search?&filter_path=hits.hits._source"

        auth_header = "Basic " + base64.b64encode(f"elastic:{ELASTIC_PASSWORD}".encode()).decode()

        response = requests.post(
            url,
            headers={
                "Content-Type": "application/json",
                "Authorization": auth_header,
            },
            json=query,
            verify=False
        )

        if response.status_code != 200:
            print("Elasticsearch response:", response.text)
            return JsonResponse({'error': 'Failed to fetch rules by tag'}, status=500)

        data = response.json()
        source_array = [hit['_source'] for hit in data['hits']['hits']]
        
        existing_rules = Rule.objects.filter(tag__in=[rule['tag'] for rule in source_array])
        existing_tags = [rule.tag for rule in existing_rules]

        for rule in source_array:
            if not Rule.objects.filter(tag=rule['tag']).exists():
                dynamic_model = create_dynamic_model_class(rule['tag'])
                new_instance = dynamic_model(tag=rule['tag'], name=rule['name'], description=rule['description'])
                new_instance.save()

        return JsonResponse(source_array, safe=False)

    except Exception as e:
        print("Error while fetching rules by tag", e)
        return JsonResponse({'error': 'Internal server error'}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def delete_rules(request):
    try:
         # Extract the token from the request headers
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Token missing or invalid'}, status=400)
        
        token = auth_header.split(' ')[1]
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_data = decoded_token.get('user', {})
        tag = user_data.get('tag')
        
        
        result = Rule.objects.filter(tag=tag).delete()
        
        if result[0] > 0:
            return JsonResponse({'message': f'{result[0]} records deleted successfully.'})
        else:
            return JsonResponse({'message': 'No records found with the specified tag.'}, status=404)

    except Exception as e:
        print("Error deleting all rules", e)
        return JsonResponse({'error': 'Internal server error'}, status=500)