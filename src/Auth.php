<?php
namespace DrupalExternalAuth;

use Drupal\Component\Utility\Crypt;
use Wikimedia\PhpSessionSerializer;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

class Auth
{
    /**
     * PDO Connection
     * @var \PDO
     */
    private $pdo;
    /**
     * Current timestamp
     * @var string
     */
    private $timestamp;
    /**
     * Default schema of Drupal instalation
     * @var string
     */
    private $schema = 'drupal';
    private $cookie;
    /**
     * @var Response
     */
    private $response;
    /**
     * The uid of Drupal user.
     * @var string
     */
    private $uid;

    public function __construct(Response $response, \PDO $pdo, string $schema = 'drupal')
    {
        $this->response = $response;
        $this->pdo = $pdo;
        $this->schema = $schema ? $schema.'.' : '';
        $this->timestamp = time();
    }

    public function auth(array $data)
    {
        if (!$this->isLogged()) {
            $uid = $this->getUid($data);
            $this->login($uid);
        }
    }

    public function logout()
    {
        $cookie = $this->getCookie();
        if ($cookie) {
            // Delete from database
            $this->deleteSessionFromDatabase($cookie['value']);
            $this->setCleanCookie($cookie);
        }
    }

    private function isLogged(): bool
    {
        $cookie = $this->getCookie();
        if (!$cookie) {
            return false;
        }
        $sth = $this->pdo->prepare(
            'SELECT uid FROM '.$this->schema.'sessions WHERE sid = :sid'
        );
        $sth->execute([':sid' => Crypt::hashBase64($cookie['value'])]);
        if ($sth->fetch()) {
            return true;
        }
        $this->setCleanCookie($cookie);
        return false;
    }

    private function login(int $uid)
    {
        $sessionDrupal = [
            '_sf2_attributes' => [
                'uid' => $uid
            ],
            '_sf2_meta' => [
                'u' => $this->timestamp,
                'c' => $this->timestamp,
                'l' => ini_get('session.cookie_lifetime')
            ]
        ];
        $sessionDrupalEncoded = PhpSessionSerializer::encode($sessionDrupal);
        $sessionHash = Crypt::randomBytesBase64();
        $name = substr(hash('sha256', $_SERVER['HTTP_HOST']), 0, 32);
        $cookie = Cookie::create(
            'SESS'.$name,
            $sessionHash,
            ini_get('session.cookie_lifetime'),
            '/',
            getenv('DOMAIN'),
            (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == "on"),
            true,
            false,
            null
        );
        $this->response->headers->setCookie($cookie);
        $sth = $this->pdo->prepare(
            "INSERT INTO {$this->schema}sessions
                   (uid,   sid,  hostname,  timestamp,  session)
            VALUES (:uid, :sid, :hostname, :timestamp, :session)"
        );
        $sth->execute([
            ':uid' => $uid,
            ':sid' => Crypt::hashBase64($sessionHash),
            ':hostname' => $_SERVER['REMOTE_ADDR'],
            ':timestamp' => $this->timestamp,
            ':session' => $sessionDrupalEncoded
        ]);
    }

    /**
     * Return existing cookies
     * @return array
     */
    private function getCookie(): array
    {
        foreach ($_COOKIE as $key => $value) {
            if (substr($key, 0, 4) == 'SESS') {
                return [
                    'key'   => $key,
                    'value' => $value
                ];
            }
        }
        return [];
    }

    private function setCleanCookie(array $cookie)
    {
        // Unset from global var
        unset($_COOKIE[$cookie['key']]);
        // Send unset to user
        $this->response->headers->setCookie(Cookie::create(
            $cookie['key'],
            null,
            -1,
            '/',
            getenv('DOMAIN'),
            (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == "on"),
            true,
            false,
            null
        ));
    }

    private function deleteSessionFromDatabase(string $value)
    {
        $sth = $this->pdo->prepare(
            'DELETE FROM '.$this->schema.'sessions WHERE sid = :sid'
        );
        $sth->execute([':sid' => Crypt::hashBase64($value)]);
    }

    private function getUid(array $data): int
    {
        $sth = $this->pdo->prepare(
            'SELECT uid FROM '.$this->schema.'users_field_data WHERE name = :name'
        );
        $sth->execute([':name' => $data['name']]);
        $user = $sth->fetch();
        if ($user) {
            return $this->uid = $user['uid'];
        }
        return $this->createUser($data);
    }

    private function createUser(array $data): int
    {
        $this->pdo->query('INSERT INTO '.$this->schema.'sequences () VALUES ();');
        $this->uid = $this->pdo->lastInsertId();
        $sth = $this->pdo->prepare(
            'INSERT INTO '.$this->schema.'users (uid, uuid, langcode) '.
            'VALUES (:uid, UUID(), :langcode)'
        );
        $sth->execute([
            ':uid' => $this->uid,
            ':langcode' => $data['langcode']
        ]);
        $sth = $this->pdo->prepare(
            "INSERT INTO {$this->schema}users_field_data (
                uid, langcode, preferred_langcode, preferred_admin_langcode,
                name, pass, mail, timezone, status, created, changed, access,
                login, init, default_langcode)
            VALUES (
                :uid, :langcode, :preferred_langcode, :preferred_admin_langcode,
                :name, :pass, :mail, :timezone, :status, :created, :changed, :access,
                :login, :init, :default_langcode)"
        );
        $sth->execute([
            ':uid' => $this->uid,
            ':langcode' => $data['langcode'],
            ':preferred_langcode' => $data['langcode'],
            ':preferred_admin_langcode' => null,
            ':name' => $data['name'],
            ':pass' => $data['pass'],
            ':mail' => null,
            ':timezone' => $data['timezone'],
            ':status' => 1,
            ':created' => $this->timestamp,
            ':changed' => $this->timestamp,
            ':access' => 0,
            ':login' => 0,
            ':init' => null,
            ':default_langcode' => 1
        ]);

        $sth = $this->pdo->prepare(
            "INSERT INTO {$this->schema}user__roles (entity_id, revision_id, bundle, delta, langcode, roles_target_id)
            VALUES (:entity_id, :revision_id, :bundle, :delta, :langcode, :roles_target_id)"
        );
        foreach ($data['roles'] as $role) {
            $sth->execute([
                ':entity_id' => $this->uid,
                ':revision_id' => $this->uid,
                ':bundle' => 'user',
                ':delta' => 0,
                ':langcode' => $data['langcode'],
                ':roles_target_id' => $role
            ]);
        }
        return $this->uid;
    }
}
