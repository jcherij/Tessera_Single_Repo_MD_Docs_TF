"""Tessera tokenizer.

POST /v1/tokenize    {"pan": "4111111111111111"} -> {"token": "tok_...", "last4": "1111"}
POST /v1/detokenize  {"token": "tok_..."}        -> {"pan": "4111111111111111"}

The full PAN is never logged. Sensitive authentication data (CVV, track
data, PIN blocks) is rejected and never stored.
"""

import base64
import json
import logging
import os
import secrets
import time

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_NAME = os.environ["TABLE_NAME"]
KMS_KEY_ID = os.environ["KMS_KEY_ID"]
TOKEN_TTL_DAYS = int(os.environ.get("TOKEN_TTL_DAYS", "365"))

kms = boto3.client("kms")
table = boto3.resource("dynamodb").Table(TABLE_NAME)

SAD_FIELDS = {"cvv", "cvv2", "cvc", "cvc2", "cid", "track", "track1", "track2", "pin", "pin_block"}


def _response(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
        "body": json.dumps(body),
    }


def _luhn_valid(pan):
    digits = [int(d) for d in pan]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _context(token):
    return {"app": "tessera", "token": token}


def tokenize(body, caller):
    if SAD_FIELDS & {k.lower() for k in body}:
        logger.warning(json.dumps({"event": "sad_rejected", "caller": caller}))
        return _response(400, {"error": "sensitive authentication data must not be submitted"})

    pan = str(body.get("pan", "")).replace(" ", "")
    if not (pan.isdigit() and 13 <= len(pan) <= 19 and _luhn_valid(pan)):
        return _response(400, {"error": "invalid PAN"})

    token = "tok_" + secrets.token_urlsafe(24)
    ciphertext = kms.encrypt(
        KeyId=KMS_KEY_ID,
        Plaintext=pan.encode(),
        EncryptionContext=_context(token),
    )["CiphertextBlob"]

    table.put_item(
        Item={
            "token": token,
            "pan_ciphertext": base64.b64encode(ciphertext).decode(),
            "last4": pan[-4:],
            "created_at": int(time.time()),
            "expires_at": int(time.time()) + TOKEN_TTL_DAYS * 86400,
        },
        ConditionExpression="attribute_not_exists(#t)",
        ExpressionAttributeNames={"#t": "token"},
    )

    logger.info(json.dumps({"event": "tokenize", "token": token, "last4": pan[-4:], "caller": caller}))
    return _response(201, {"token": token, "last4": pan[-4:]})


def detokenize(body, caller):
    token = str(body.get("token", ""))
    if not token.startswith("tok_"):
        return _response(400, {"error": "invalid token"})

    item = table.get_item(Key={"token": token}).get("Item")
    if not item or int(item["expires_at"]) < time.time():
        logger.info(json.dumps({"event": "detokenize_miss", "token": token, "caller": caller}))
        return _response(404, {"error": "token not found"})

    pan = kms.decrypt(
        CiphertextBlob=base64.b64decode(item["pan_ciphertext"]),
        EncryptionContext=_context(token),
    )["Plaintext"].decode()

    logger.info(json.dumps({"event": "detokenize", "token": token, "last4": item["last4"], "caller": caller}))
    return _response(200, {"pan": pan})


def lambda_handler(event, _context_obj):
    route = event.get("routeKey", "")
    caller = (
        event.get("requestContext", {}).get("authorizer", {}).get("iam", {}).get("userArn", "unknown")
    )
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"error": "malformed JSON"})

    if route == "POST /v1/tokenize":
        return tokenize(body, caller)
    if route == "POST /v1/detokenize":
        return detokenize(body, caller)
    return _response(404, {"error": "unknown route"})
