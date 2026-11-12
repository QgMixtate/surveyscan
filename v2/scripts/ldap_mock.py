#!/usr/bin/env python3
"""C31.04: мок-каталог для тестов синхронизации оргструктуры — OpenLDAP в контейнере (LDAPS, самоподписанный CA),
синтетические люди и группы. Это НЕ Active Directory: двоичный objectGUID и userAccountControl проверяются
модульными тестами и на стенде (реальный AD, только чтение). Печатает переменные окружения для go test.

  python3 scripts/ldap_mock.py up   → SURVEYSCAN_TEST_LDAP_*=...
  python3 scripts/ldap_mock.py down
"""
import os, secrets, subprocess, sys, time, pathlib

NAME = 'surveyscan-v2-ldap-mock'
IMAGE = 'osixia/openldap:1.5.0'
STATE = pathlib.Path(os.environ.get('SURVEYSCAN_LDAP_MOCK_STATE', pathlib.Path(__file__).resolve().parent.parent / '.local' / 'ldap-mock'))
BASE = 'dc=example,dc=test'


def run(*a, check=True, inp=None):
    return subprocess.run(a, check=check, capture_output=True, text=True, input=inp)


def ldap(cmd, ldif, password):
    return run('docker', 'exec', '-i', NAME, cmd, '-x', '-H', 'ldap://localhost', '-D', f'cn=admin,{BASE}', '-w', password, inp=ldif)


SEED = f"""dn: ou=people,{BASE}
objectClass: organizationalUnit
ou: people

dn: ou=groups,{BASE}
objectClass: organizationalUnit
ou: groups

dn: ou=service,{BASE}
objectClass: organizationalUnit
ou: service
""" + ''.join(f"""
dn: uid={uid},ou=people,{BASE}
objectClass: inetOrgPerson
uid: {uid}
cn: {cn}
sn: {cn.split()[-1]}
displayName: {cn}
mail: {uid}@example.test
""" for uid, cn in [('ivanov', 'Иван Иванов'), ('petrova', 'Мария Петрова'), ('sidorov', 'Пётр Сидоров')]) + f"""
dn: cn=Linux Admins,ou=groups,{BASE}
objectClass: groupOfNames
cn: Linux Admins
member: uid=ivanov,ou=people,{BASE}
member: uid=petrova,ou=people,{BASE}

dn: cn=Nested,ou=groups,{BASE}
objectClass: groupOfNames
cn: Nested
member: cn=Linux Admins,ou=groups,{BASE}
"""


def up():
    STATE.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE, 0o700)
    run('docker', 'rm', '-f', NAME, check=False)
    # свой одноразовый CA и сертификат сервера (localhost): встроенный в образ CA просрочен
    certs = STATE / 'certs'
    certs.mkdir(exist_ok=True)
    os.chmod(certs, 0o755)
    o = lambda *a: run('openssl', *a)
    o('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=surveyscan ldap mock CA', '-keyout', str(certs / 'ca.key'), '-out', str(certs / 'ca.crt'))
    o('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', str(certs / 'ldap.key'), '-out', str(certs / 'ldap.csr'))
    (certs / 'ext').write_text('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n')
    o('x509', '-req', '-in', str(certs / 'ldap.csr'), '-CA', str(certs / 'ca.crt'), '-CAkey', str(certs / 'ca.key'), '-CAcreateserial', '-days', '30', '-extfile', str(certs / 'ext'), '-out', str(certs / 'ldap.crt'))
    o('rsa', '-in', str(certs / 'ldap.key'), '-traditional', '-out', str(certs / 'ldap.key'))  # GnuTLS образа: PKCS#1
    o('dhparam', '-out', str(certs / 'dhparam.pem'), '2048')  # готовые параметры (≈15 с), формат DSA образ не принимает
    (certs / 'ca.key').unlink()
    for f in certs.iterdir():
        os.chmod(f, 0o644)  # ключ мока — только для одноразового тестового контейнера
    admin = secrets.token_urlsafe(24)
    (STATE / 'admin_password').write_text(admin)
    os.chmod(STATE / 'admin_password', 0o600)
    run('docker', 'run', '-d', '--name', NAME, '--hostname', 'localhost', '-p', '127.0.0.1::636', '-p', '127.0.0.1::389',
        '-e', 'LDAP_ORGANISATION=Example', '-e', 'LDAP_DOMAIN=example.test', '-e', f'LDAP_ADMIN_PASSWORD={admin}',
        '-e', 'LDAP_TLS_VERIFY_CLIENT=never', '-e', 'LDAP_TLS_CRT_FILENAME=ldap.crt', '-e', 'LDAP_TLS_KEY_FILENAME=ldap.key',
        '-e', 'LDAP_TLS_CA_CRT_FILENAME=ca.crt', '-v', f'{certs}:/container/service/slapd/assets/certs', IMAGE, '--copy-service')
    for _ in range(90):
        if run('docker', 'exec', NAME, 'ldapsearch', '-x', '-H', 'ldap://localhost', '-b', BASE, '-D', f'cn=admin,{BASE}', '-w', admin, '-s', 'base', check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        sys.exit('ldap mock did not start')
    for _ in range(120):  # TLS поднимается после первичной настройки
        if run('docker', 'exec', '-e', 'LDAPTLS_CACERT=/container/service/slapd/assets/certs/ca.crt', NAME, 'ldapsearch', '-x', '-H', 'ldaps://localhost',
               '-b', BASE, '-D', f'cn=admin,{BASE}', '-w', admin, '-s', 'base', check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        sys.exit('ldap mock TLS did not start')
    ldap('ldapadd', SEED, admin)
    reader = secrets.token_urlsafe(24)
    ldap('ldapadd', f"dn: cn=reader,ou=service,{BASE}\nobjectClass: simpleSecurityObject\nobjectClass: organizationalRole\ncn: reader\nuserPassword: {reader}\n", admin)
    # служебная учётка только на чтение (как в AD): чтение всего, кроме паролей
    acl = ('dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nadd: olcAccess\n'
           f'olcAccess: {{1}}to * by dn.exact="cn=reader,ou=service,{BASE}" read by * break\n')
    run('docker', 'exec', '-i', NAME, 'ldapmodify', '-Q', '-Y', 'EXTERNAL', '-H', 'ldapi:///', inp=acl)
    (STATE / 'reader_password').write_text(reader + '\n')
    os.chmod(STATE / 'reader_password', 0o600)
    (STATE / 'ca.crt').write_text((certs / 'ca.crt').read_text())
    port = run('docker', 'port', NAME, '636/tcp').stdout.strip().split(':')[-1]
    plain = run('docker', 'port', NAME, '389/tcp').stdout.strip().split(':')[-1]
    for k, v in {'URL': f'ldaps://localhost:{port}', 'PLAIN_URL': f'ldap://localhost:{plain}', 'BASE_DN': BASE,
                 'BIND_DN': f'cn=reader,ou=service,{BASE}', 'PASSWORD_FILE': STATE / 'reader_password',
                 'CA_FILE': STATE / 'ca.crt', 'ADMIN_PASSWORD_FILE': STATE / 'admin_password', 'CONTAINER': NAME}.items():
        print(f'SURVEYSCAN_TEST_LDAP_{k}={v}')


if __name__ == '__main__':
    if sys.argv[1:] == ['up']:
        up()
    elif sys.argv[1:] == ['down']:
        run('docker', 'rm', '-f', NAME, check=False)
    else:
        sys.exit(__doc__)
