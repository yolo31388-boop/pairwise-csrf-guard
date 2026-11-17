"""CSRF guard: origin validation, session-bound tokens, rotation, safe methods."""

import hashlib
import hmac

SAFE_METHODS = frozenset({'GET', 'HEAD', 'OPTIONS'})


def origin_ok(origin, allowed_origins):
    """Origin/Referer 缺省拒绝：None、'null'、不在白名单内一律不放行。"""
    if not origin or origin == 'null':
        return False
    return origin in allowed_origins


def token_ok(provided_token, session_token):
    """double-submit token 必须绑定会话：两边都非空且常量时间比较相等。"""
    if not provided_token or not session_token:
        return False
    return hmac.compare_digest(str(provided_token), str(session_token))


def rotate_token(user_id, old_token):
    """登录后轮换：同一 (user, old) 确定性生成新 token，且不等于旧值。"""
    digest = hashlib.sha256(f'{user_id}:{old_token}'.encode('utf-8')).hexdigest()
    if digest == old_token:
        digest = hashlib.sha256(f'{user_id}:{old_token}:re'.encode('utf-8')).hexdigest()
    return digest


def safe_method(method):
    """仅 GET/HEAD/OPTIONS 为安全方法，安全方法不得改状态。"""
    if not method:
        return False
    return str(method).upper() in SAFE_METHODS


def check_request(request, session, allowed_origins):
    """非安全方法必须 Origin 合法且 token 匹配；安全方法直接放行。"""
    method = request.get('method')
    if safe_method(method):
        return True
    if not origin_ok(request.get('origin'), allowed_origins):
        return False
    return token_ok(request.get('token'), session.get('token'))
