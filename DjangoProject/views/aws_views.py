import json

import boto3
from botocore.exceptions import ClientError
from django.conf import settings
from django.http import JsonResponse
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response


def get_aws_secret_api_key():
    secret_name = settings.AWS_ORDER_FULFILLMENT_SECRET_NAME
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=settings.AWS_REGION,
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    )

    try:
        # Fetch the secret value
        response = client.get_secret_value(SecretId=secret_name)

        # Secrets Manager encrypts the secrets, so decode them
        secret = json.loads(response['SecretString'])

        return secret

    except ClientError as e:
        # Implement retries
        print(f"Error retrieving secret: {e}")
        return None


def is_authorized_aws_request(request):
    secret = get_aws_secret_api_key()
    secret_api_key_name = secret.get('api_key_name', None)
    secret_api_key_value = secret.get('api_key_value', None)

    if secret_api_key_name and secret_api_key_value:
        received_api_key_value = request.headers.get(secret_api_key_name)
        if received_api_key_value and received_api_key_value == secret_api_key_value:
            return True

    return False

@api_view(['POST'])
def fulfill_order(request):
    print('\n\n\nrequest data', request.data)
    print('\n\n\nrequest headers', request.headers)
    if not is_authorized_aws_request(request):
        return JsonResponse({'error': 'Unauthorized'}, status=401)

    print('\n\n\n\nHello, Order Fulfillment Request Received')
    return Response(status=200)

@api_view(['GET'])
def fulfill_order_send_response(request):
    event_bridge_client = boto3.client(
        'events',
        region_name=settings.AWS_REGION,
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    )

    event_bus_name = 'POC-commerce'

    event_detail = {
        "order_id": "4321",
    }

    response = event_bridge_client.put_events(
        Entries=[
            {
                'Source': 'OF',
                'DetailType': 'FulfillmentResponse',
                'Detail': json.dumps(event_detail),
                'EventBusName': event_bus_name
            }
        ]
    )

    print(f"OF EventBridge event sent. Response: {response}")

    return Response(status=status.HTTP_200_OK)
