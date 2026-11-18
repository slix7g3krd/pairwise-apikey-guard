from security.apikey_guard import (
    hash_key,
    scope_allowed,
    key_active,
    revoke,
    rotate,
    tenant_match,
    contains_key_in_url
)


def test_hash():
    assert hash_key('secret') != 'secret'

def test_hash_det():
    assert hash_key('x') == hash_key('x')

def test_scope():
    assert scope_allowed('read', {'read'}) is True

def test_scope_bad():
    assert scope_allowed('admin', {'read'}) is False

def test_wildcard():
    assert scope_allowed('*', {'read'}) is False

def test_active():
    assert key_active({'active': True, 'expires': 100}, 50) is True

def test_expired():
    assert key_active({'active': True, 'expires': 50}, 100) is False

def test_no_expiry():
    assert key_active({'active': True, 'expires': None}, 100) is False

def test_tenant():
    assert tenant_match('t1', 't1') is True

def test_tenant_bad():
    assert tenant_match('t1', 't2') is False

def test_url():
    assert contains_key_in_url('https://x?api_key=abc') is True

def test_url_safe():
    assert contains_key_in_url('https://x/path') is False

def test_revoke():
    assert revoke({'active': True})['active'] is False

def test_rotate_old():
    assert rotate({'active': True})['old_active'] is False

def test_empty():
    assert scope_allowed('', {'read'}) is False
