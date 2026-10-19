from security import (check_password_strength, hash_password, sha256_hex,
                      verify_password)


def test_hash_has_expected_format():
    stored = hash_password("Secret123", 1000)
    algo, iterations, salt, digest = stored.split("$")
    assert algo == "pbkdf2_sha256"
    assert iterations == "1000"
    assert len(salt) == 32 and len(digest) == 64


def test_same_password_gives_different_hashes():
    assert hash_password("Secret123", 1000) != hash_password("Secret123", 1000)


def test_verify_correct_and_wrong_password():
    stored = hash_password("Secret123", 1000)
    assert verify_password(stored, "Secret123")
    assert not verify_password(stored, "secret123")
    assert not verify_password(stored, "")


def test_verify_rejects_malformed_hash():
    assert not verify_password("garbage", "x")
    assert not verify_password("md5$1$aa$bb", "x")


def test_sha256_known_value():
    assert sha256_hex("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


def test_password_strength_rules():
    assert check_password_strength("Abcdef12") == []
    assert check_password_strength("short1")
    assert check_password_strength("12345678")
    assert check_password_strength("abcdefgh")
