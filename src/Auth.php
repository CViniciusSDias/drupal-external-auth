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
    private $timeStamp;
    /**
     * Default schema of Drupal instalation
     * @var string
     */
    private $schema = 'drupal.';
    private $cookie;
    /**
     * @var Response
     */
    private $response;
    public function __construct(Response $response, \PDO $pdo, $schema = 'drupal')
    {
        $this->response = $response;
        $this->pdo = $pdo;
        $this->schema = $schema ? $schema.'.' : '';
        $this->timeStamp = time();
    }
    public function auth($data)
    {
        $uid = $this->getUid($data);
        $sessionDrupal = [
            '_sf2_attributes' => [
                'uid' => $uid
            ],
            '_sf2_meta' => [
                'u' => $this->timeStamp,
                'c' => $this->timeStamp,
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
            ':timestamp' => $this->timeStamp,
            ':session' => $sessionDrupalEncoded
        ]);
    }

    public function logout()
    {
        foreach ($_COOKIE as $key => $value) {
            if (substr($key, 0, 4) == 'SESS') {
                $sth = $this->pdo->prepare(
                    'DELETE FROM '.$this->schema.'sessions WHERE sid = :sid'
                );
                $sth->execute([':sid' => Crypt::hashBase64($value)]);
                $cookie = Cookie::create(
                    $key,
                    null,
                    -1,
                    '/',
                    getenv('DOMAIN'),
                    (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == "on"),
                    true,
                    false,
                    null
                );
                unset($_COOKIE[$key]);
                $this->response->headers->setCookie($cookie);
            }
        }
    }

    private function getUid($data)
    {
        $sth = $this->pdo->prepare(
            'SELECT uid FROM '.$this->schema.'users_field_data WHERE name = :name'
        );
        $sth->execute([':name' => $data['name']]);
        $user = $sth->fetch();
        if ($user) {
            return $user['uid'];
        }
        return $this->createUser($data);
    }
    
    private function createUser($data)
    {
        $this->pdo->query('INSERT INTO '.$this->schema.'sequences () VALUES ();');
        $uid = $this->pdo->lastInsertId();
        $sth = $this->pdo->prepare(
            'INSERT INTO '.$this->schema.'users (uid, uuid, langcode) '.
            'VALUES (:uid, UUID(), :langcode)'
        );
        $sth->execute([
            ':uid' => $uid,
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
            ':uid' => $uid,
            ':langcode' => $data['langcode'],
            ':preferred_langcode' => $data['langcode'],
            ':preferred_admin_langcode' => null,
            ':name' => $data['name'],
            ':pass' => $data['pass'],
            ':mail' => null,
            ':timezone' => $data['timezone'],
            ':status' => 1,
            ':created' => $this->timeStamp,
            ':changed' => $this->timeStamp,
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
                ':entity_id' => $uid,
                ':revision_id' => $uid,
                ':bundle' => 'user',
                ':delta' => 0,
                ':langcode' => $data['langcode'],
                ':roles_target_id' => $role
            ]);
        }
        return $uid;
    }
}
