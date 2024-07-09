import json
import base64
import os
import time
import urllib.parse

import requests
import cyrtranslit
import ydb
import ydb.iam

SKILL_ID = os.getenv('SKILL_ID')
OAUTH_TOKEN = os.getenv('OAUTH_TOKEN')
CLIENT_ID = os.getenv('CLIENT_ID')
HOST = os.getenv('URL')
SELF_URL = HOST

with open('index.html') as f:
    INDEX = f.read().replace('{HOST}', HOST).replace('{SELF_URL}', SELF_URL).replace('{CLIENT_ID}', CLIENT_ID)

with open('auth.html') as f:
    AUTH = f.read().replace('{HOST}', HOST).replace('{SELF_URL}', SELF_URL).replace('{CLIENT_ID}', CLIENT_ID)

driver = ydb.Driver(
    endpoint=os.getenv('YDB_ENDPOINT'),
    database=os.getenv('YDB_DATABASE'),
    credentials=ydb.iam.MetadataUrlCredentials(),
)
driver.wait(fail_fast=True, timeout=5)
pool = ydb.SessionPool(driver)


class BadRequest(Exception):
    def __init__(self, message, code: int | str = 400):
        super().__init__(message)
        self.message = message
        self.code = code


def evaluate_expressions(expressions: dict[str, str]) -> dict[str, bool]:
    if len(expressions) > 32:
        raise BadRequest('too many expressions')

    result: dict[str, bool | None] = {}

    def eval_one(key: str) -> bool:
        if key in result:
            if result[key] is None:
                raise BadRequest(f'loop including expression {key!r} is detected')
            return result[key]
        result[key] = None
        print(f'evaluating {key!r} = {expressions[key]!r}')
        stack = []
        if len(expressions[key]) > 100:
            raise BadRequest(f'too long expression {key!r}')
        expr = expressions[key].split(' ')
        if len(expr) > 10:
            raise BadRequest(f'expression {expr} is too long')
        for op in expr:
            if op == '^':
                stack.append(stack.pop() ^ stack.pop())
            elif op == '&':
                stack.append(stack.pop() & stack.pop())
            elif op == '|':
                stack.append(stack.pop() | stack.pop())
            elif op == '~':
                stack.append(int(not stack.pop()))
            elif op == '1':
                stack.append(1)
            elif op == '0':
                stack.append(0)
            elif op.isalpha():
                stack.append(eval_one(op))
            else:
                raise BadRequest(f'invalid expression {expr}: unknown op: {op!r}')
        result[key] = bool(stack.pop())
        return result[key]

    return {k: eval_one(k) for k in expressions.keys()}


def check_auth(event, context) -> int:
    headers = {k.title(): v for k, v in event['headers'].items()}
    if headers.get('X-Auth-Token'):
        headers['Authorization'] = f'Bearer {event["headers"]["X-Auth-Token"]}'
    if not headers.get('Authorization'):
        raise BadRequest('no auth token')
    jwt = requests.get('https://login.yandex.ru/info?format=jwt', headers={
        'Authorization': headers['Authorization']
    })
    if jwt.status_code != 200:
        raise BadRequest('unauthorized', 403)
    info = json.loads(base64.b64decode(jwt.text.split('.')[1]).decode('utf-8'))
    uid = info['uid']
    print(f'authorized as {uid}')
    return uid


def handle_unlink(event, context):
    req_id = event['headers']['request_id']
    uid = check_auth(event, context)
    pool.retry_operation_sync(lambda session: session.transaction().execute(
        'delete from users where uid = {};'.format(uid),
        commit_tx=True
    ))
    return {
        'request_id': req_id,
    }


def handle_discovery(event, context):
    req_id = event['headers']['request_id']
    uid = check_auth(event, context)
    rows = pool.retry_operation_sync(lambda session: session.transaction(ydb.SerializableReadWrite()).execute(
        'select Yson::SerializeJson(expressions) as expressions from users where uid = {};'.format(uid),
        commit_tx=True
    )[0].rows)
    if not rows or not rows[0].expressions:
        expressions = {}
    else:
        expressions = json.loads(rows[0].expressions)
    return {
        "request_id": req_id,
        "payload": {
            "user_id": str(uid),
            "devices": render_discovery(expressions),
        }
    }


def render_discovery(expressions):
    return [
        dict(
            id=''.join(hex(x)[2:] for x in key.encode('utf-8')),
            name=f'Переменная {cyrtranslit.to_cyrillic(key)}',
            description=f'Формула: {cyrtranslit.to_cyrillic(expr)}',
            room='Переменные',
            type='devices.types.light',
            capabilities=[
                dict(
                    type='devices.capabilities.on_off',
                    retrievable=True,
                    reportable=True,
                    parameters=dict(
                        split=True
                    ),
                )
            ],
        )
        for key, expr in expressions.items()
    ]


def handle_query(event, context):
    req_id = event['headers']['request_id']
    uid = check_auth(event, context)
    rows = pool.retry_operation_sync(lambda session: session.transaction(ydb.SerializableReadWrite()).execute(
        'select Yson::SerializeJson(expressions) as expressions from users where uid = {};'.format(uid),
        commit_tx=True
    )[0].rows)
    if not rows or not rows[0].expressions:
        expressions = {}
    else:
        expressions = json.loads(rows[0].expressions)
    evaluated = evaluate_expressions(expressions)
    return {
        "request_id": req_id,
        "payload": {
            "devices": render_state(expressions, evaluated, {}),
        },
    }


def handle_action(event, context):
    req_id = event['headers']['request_id']
    uid = check_auth(event, context)
    print('handle_action({})'.format(json.dumps(event['payload'])))

    def process(session):
        txn = session.transaction(ydb.SerializableReadWrite())
        rows = txn.execute(
            'select Yson::SerializeJson(expressions) as expressions from users where uid = {};'.format(uid),
        )[0].rows
        if not rows or not rows[0].expressions:
            return {}, {}, {}
        before = json.loads(rows[0].expressions)
        expressions = json.loads(rows[0].expressions)
        action_result = {}
        for dev in event['payload']['devices']:
            key = bytes.fromhex(dev['id']).decode('utf-8')
            if key not in expressions:
                action_result[key] = dict(status='ERROR', error_code='DEVICE_NOT_FOUND')
                continue
            set_to = key
            visited = set()
            while expressions[set_to] not in ('0', '1'):
                if set_to in visited:
                    print(f'loop detected while setting {key}')
                    action_result[key] = dict(status='ERROR', error_code='INVALID_VALUE')
                    set_to = None
                    break
                visited.add(set_to)
                expr = expressions[set_to]
                if len(expr.split(' ')) != 1:
                    print(f'cant assign to {key}')
                    action_result[key] = dict(status='ERROR', error_code='INVALID_VALUE')
                    set_to = None
                    break
                set_to = expr
            if set_to is not None:
                for cap in dev['capabilities']:
                    if cap['type'] == 'devices.capabilities.on_off':
                        expressions[set_to] = str(int(cap['state']['value']))
                        action_result[key] = dict(status='DONE')
        txn.execute(
            "upsert into users(uid, expressions)"
            "VALUES ({}, Yson::ParseJson('{}'));".format(uid,
                                                                                             json.dumps(expressions)),
            commit_tx=True,
        )
        return before, expressions, action_result

    before, current, action_result = pool.retry_operation_sync(process)
    print('result: {}'.format(json.dumps(action_result)))

    before_eval, current_eval = evaluate_expressions(before), evaluate_expressions(current)
    changed = {k: v for k, v in current_eval.items() if v != before_eval.get(k)}
    notification = requests.post(
        f'https://dialogs.yandex.net/api/v1/skills/{SKILL_ID}/callback/state',
        headers={'Authorization': f'OAuth {OAUTH_TOKEN}'},
        json={
            "ts": int(time.time()),
            "payload": {
                "user_id": str(uid),
                "devices": render_state(current, current_eval, changed),
            },
        }
    )
    print('sent state notification: {}'.format(json.dumps(notification.json())))
    return {
        "request_id": req_id,
        "payload": {
            "devices": [
                dict(
                    id=key.encode('utf-8').hex(),
                    capabilities=[
                        dict(
                            type='devices.capabilities.on_off',
                            state=dict(
                                instance='on',
                                action_result=result,
                            ),
                        )
                    ],
                )
                for key, result in action_result.items()
            ],
        },
    }


def render_state(expressions, evaluated, changed):
    return [
        dict(
            id=key.encode('utf-8').hex(),
            capabilities=[
                dict(
                    type='devices.capabilities.on_off',
                    state=dict(
                        instance='on',
                        value=evaluated[key],
                    ),
                )
            ],
        )
        for key, expr in expressions.items()
    ]


def handle_set_var(event, context, patch):
    if event['headers'].get('Content-Type') != 'application/x-www-form-urlencoded':
        raise BadRequest('application/x-www-form-urlencoded expected')

    uid = check_auth(event, context)
    data = urllib.parse.parse_qs(event['body'])

    def process(session):
        txn = session.transaction(ydb.SerializableReadWrite())
        if not patch:
            expressions = {}
        else:
            rows = txn.execute(
                'select Yson::SerializeJson(expressions) as expressions from users where uid = {};'.format(uid),
            )[0].rows
            if not rows or not rows[0].expressions:
                expressions = {}
            else:
                expressions = json.loads(rows[0].expressions)

        for key, vals in data.items():
            if not vals or not vals[0] or vals[0] == 'x':
                if key in expressions:
                    del expressions[key]
            else:
                expressions[key] = vals[0]

        try:
            evaluate_expressions(expressions)
        except Exception as e:
            return str(e), expressions

        txn.execute(
            "upsert into users(uid, expressions)"
            "values ({}, Yson::ParseJson('{}'));".format(uid, json.dumps(expressions)),
            commit_tx=True,
        )
        return None, expressions

    error, expressions = pool.retry_operation_sync(process)
    notification = requests.post(
        f'https://dialogs.yandex.net/api/v1/skills/{SKILL_ID}/callback/discovery',
        headers={'Authorization': f'OAuth {OAUTH_TOKEN}'},
        json={
            "ts": int(time.time()),
            "payload": {
                "user_id": str(uid),
            },
        }
    )
    print('sent discovery notification: {}'.format(json.dumps(notification.json())))
    return {
        'statusCode': 200 if not error else 400,
        'body': {
            'error': error,
            'expressions': expressions,
        }
    }


def handle_get_vars(event, context):
    uid = check_auth(event, context)
    rows = pool.retry_operation_sync(lambda session: session.transaction(ydb.SerializableReadWrite()).execute(
        'select Yson::SerializeJson(expressions) as expressions from users where uid = {};'.format(uid),
        commit_tx=True
    )[0].rows)
    if not rows or not rows[0].expressions:
        expressions = {}
    else:
        expressions = json.loads(rows[0].expressions)
    return {
        'statusCode': 200,
        'body': {
            'error': None,
            'expressions': expressions,
        }
    }


def handler(event, context):
    if 'request_type' in event:
        print('payload', event.get('payload'))
        try:
            if event['request_type'] == 'unlink':
                return handle_unlink(event, context)
            if event['request_type'] == 'discovery':
                return handle_discovery(event, context)
            if event['request_type'] == 'query':
                return handle_query(event, context)
            if event['request_type'] == 'action':
                return handle_action(event, context)
            raise BadRequest('not found', 404)
        except BadRequest as e:
            return {
                'request_id': event['headers']['request_id'],
                'error_code': 'INTERNAL_ERROR' if isinstance(e.code, int) else e.code,
                'error_message': e.message,
            }
    else:
        if event['isBase64Encoded']:
            event['body'] = base64.b64decode(event['body']).decode('utf-8')
        print('data', event.get('body'))
        try:
            if event['queryStringParameters'].get('vars'):
                if event['httpMethod'] == 'PATCH':
                    return handle_set_var(event, context, patch=True)
                elif event['httpMethod'] == 'POST':
                    return handle_set_var(event, context, patch=False)
                elif event['httpMethod'] == 'GET':
                    return handle_get_vars(event, context)
            elif event['queryStringParameters'].get('auth'):
                return {
                    'statusCode': 200,
                    'headers': {
                        'Content-Type': 'text/html',
                    },
                    'body': AUTH,
                }
            else:
                return {
                    'statusCode': 200,
                    'headers': {
                        'Content-Type': 'text/html',
                    },
                    'body': INDEX,
                }
            raise BadRequest('not found', 404)
        except BadRequest as e:
            return {
                'statusCode': 400 if isinstance(e.code, str) else e.code,
                'body': e.message,
            }
