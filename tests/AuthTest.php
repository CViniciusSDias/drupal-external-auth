<?php
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;
use Wikimedia\PhpSessionSerializer;

class AuthTest extends TestCase
{

    public static function setUpBeforeClass()
    {
        $_SERVER['HTTP_HOST']   = 'localhost';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    public function testAuthWithUserExists()
    {
        $response = new Response();

        $fetchAllMock = $this->getMockBuilder("StdClasss")
            ->setMethods(['execute', 'fetch'])
            ->getMock();

        $fetchAllMock->expects($this->once())
            ->method('fetch')
            ->will($this->returnValue(['uid' => 1]));

        $fetchAllMock->expects($this->any())
            ->method('execute')
            ->withConsecutive(
                [$this->isType('array')],
                [$this->callback(function($params) {
                    $session = PhpSessionSerializer::decode($params[':session']);
                    $this->assertArrayHasKey('_sf2_attributes', $session);
                    $this->assertArrayHasKey('_sf2_meta', $session);
                    $this->assertArrayHasKey('uid', $session['_sf2_attributes']);
                    $this->assertSame(1, $session['_sf2_attributes']['uid']);
                    return true;
                })]
            );

        $mock = $this->getMockBuilder('pdo')
            ->disableOriginalConstructor()
            ->setMethods(['prepare'])
            ->getMock();

        $mock->expects($this->exactly(2))
            ->method('prepare')
            ->withConsecutive(
                [$this->stringStartsWith('SELECT uid FROM drupal.users_field_data')],
                [$this->stringStartsWith('INSERT INTO drupal.sessions')]
            )
            ->will($this->returnValue($fetchAllMock));

        (new \DrupalExternalAuth\Auth($response, $mock))->auth([
            'name' => 'username',
            'pass' => 'PrefixHash$' . 'hashOfPassord',
            'timezone' => 'America/Sao_Paulo',
            'langcode' => 'pt-br',
            'roles' => [
                'administrator'
            ]
        ]);
        foreach ($response->headers->getCookies() as $cookie) {
            $this->assertSame(36, strlen($cookie->getName()));
            $this->assertStringStartsWith('SESS', $cookie->getName());
        }
    }

    public function testNewUser()
    {
        $response = new Response();

        $fetchAllMock = $this->getMockBuilder("StdClasss")
            ->setMethods(['execute', 'fetch'])
            ->getMock();

        $fetchAllMock->expects($this->once())
            ->method('fetch')
            ->will($this->returnValue(null));

        $fetchAllMock->expects($this->exactly(5))
            ->method('execute')
            ->withConsecutive(
                [$this->isType('array')],
                [$this->callback(function($params) {
                    $this->assertArrayHasKey(':uid', $params);
                    return true;
                })],
                [$this->callback(function($params) {
                    $this->assertArrayHasKey(':uid', $params);
                    return true;
                })],
                [$this->callback(function($params) {
                    $this->assertArrayHasKey(':entity_id', $params);
                    $this->assertArrayHasKey(':revision_id', $params);
                    $this->assertArrayHasKey(':roles_target_id', $params);
                    $this->assertSame('administrator', $params[':roles_target_id']);
                    return true;
                })],
                [$this->callback(function($params) {
                    $session = PhpSessionSerializer::decode($params[':session']);
                    $this->assertArrayHasKey('_sf2_attributes', $session);
                    $this->assertArrayHasKey('_sf2_meta', $session);
                    $this->assertArrayHasKey('uid', $session['_sf2_attributes']);
                    $this->assertSame(123, $session['_sf2_attributes']['uid']);
                    return true;
                })]
            );

        $mock = $this->getMockBuilder('pdo')
            ->disableOriginalConstructor()
            ->setMethods(['query', 'lastInsertId', 'prepare'])
            ->getMock();

        $mock->expects($this->once())
            ->method('query')
            ->with($this->stringStartsWith('INSERT INTO drupal.sequences'))
            ->will($this->returnValue($fetchAllMock));

        $mock->expects($this->once())
            ->method('lastInsertId')
            ->will($this->returnValue(123));

        $mock->expects($this->exactly(5))
            ->method('prepare')
            ->withConsecutive(
                [$this->stringStartsWith('SELECT uid FROM drupal.users_field_data')],
                [$this->stringStartsWith('INSERT INTO drupal.users ')],
                [$this->stringStartsWith('INSERT INTO drupal.users_field_data ')],
                [$this->stringStartsWith('INSERT INTO drupal.user__roles ')],
                [$this->stringStartsWith('INSERT INTO drupal.sessions')]
            )
            ->will($this->returnValue($fetchAllMock));

        (new \DrupalExternalAuth\Auth($response, $mock))->auth([
            'name' => 'username',
            'pass' => 'PrefixHash$' . 'hashOfPassord',
            'timezone' => 'America/Sao_Paulo',
            'langcode' => 'pt-br',
            'roles' => [
                'administrator'
            ]
        ]);
        foreach ($response->headers->getCookies() as $cookie) {
            $this->assertSame(36, strlen($cookie->getName()));
            $this->assertStringStartsWith('SESS', $cookie->getName());
        }
    }

    public function testAuthWithUserIsLogged()
    {
        $response = new Response();

        $fetchAllMock = $this->getMockBuilder("StdClasss")
            ->setMethods(['execute', 'fetch'])
            ->getMock();

        $fetchAllMock->expects($this->once())
            ->method('fetch')
            ->will($this->returnValue(['uid' => 123]));

        $fetchAllMock->expects($this->once())
            ->method('execute')
            ->with($this->callback(function($params) {
                $this->assertArrayHasKey(':sid', $params);
                return true;
            }));

        $mock = $this->getMockBuilder('pdo')
            ->disableOriginalConstructor()
            ->setMethods(['query', 'prepare'])
            ->getMock();

        $mock->expects($this->once())
            ->method('prepare')
            ->with($this->stringStartsWith('SELECT uid FROM drupal.sessions'))
            ->will($this->returnValue($fetchAllMock));

        $_COOKIE = ['SESSbla' => 'ble'];
        (new \DrupalExternalAuth\Auth($response, $mock))->auth([
            'name' => 'username',
            'pass' => 'PrefixHash$' . 'hashOfPassord',
            'timezone' => 'America/Sao_Paulo',
            'langcode' => 'pt-br',
            'roles' => [
                'administrator'
            ]
        ]);
        unset($_COOKIE['SESSbla']);
    }

    public function testAuthWithInvalidCookie()
    {
        $response = new Response();

        $fetchAllMock = $this->getMockBuilder("StdClasss")
            ->setMethods(['execute', 'fetch'])
            ->getMock();

        $fetchAllMock->expects($this->exactly(2))
            ->method('fetch')
            ->willReturn(
                $this->returnValue(null),
                $this->returnValue(['uid' => 1]),
            );

        $fetchAllMock->expects($this->exactly(3))
            ->method('execute')
            ->withConsecutive(
                [$this->callback(function($params) {
                    $this->assertArrayHasKey(':sid', $params);
                    return true;
                })],
                [$this->callback(function($params) {
                    $this->assertArrayHasKey(':name', $params);
                    return true;
                })],
                [$this->isType('array')]
            );

        $mock = $this->getMockBuilder('pdo')
            ->disableOriginalConstructor()
            ->setMethods(['query', 'lastInsertId', 'prepare'])
            ->getMock();

        $mock->expects($this->exactly(3))
            ->method('prepare')
            ->withConsecutive(
                [$this->stringStartsWith('SELECT uid FROM drupal.sessions')],
                [$this->stringStartsWith('SELECT uid FROM drupal.users_field_data')],
                [$this->stringStartsWith('INSERT INTO drupal.sessions')]
            )
            ->will($this->returnValue($fetchAllMock));

        $_COOKIE = ['SESSbla' => 'ble'];
        (new \DrupalExternalAuth\Auth($response, $mock))->auth([
            'name' => 'username',
            'pass' => 'PrefixHash$' . 'hashOfPassord',
            'timezone' => 'America/Sao_Paulo',
            'langcode' => 'pt-br',
            'roles' => [
                'administrator'
            ]
        ]);
        unset($_COOKIE['SESSbla']);
    }

    public function testLogout()
    {
        $_COOKIE = ['SESS1234' => 'theHash'];
        $this->assertArrayHasKey('SESS1234', $_COOKIE);

        $fetchAllMock = $this->getMockBuilder("StdClasss")
            ->setMethods(['prepare', 'execute'])
            ->getMock();

        $fetchAllMock->expects($this->exactly(1))
            ->method('execute')
            ->with($this->callback(function($params) {
                $this->assertArrayHasKey(':sid', $params);
                return true;
            }));

        $mock = $this->getMockBuilder('pdo')
            ->disableOriginalConstructor()
            ->getMock();

        $mock->expects($this->exactly(1))
            ->method('prepare')
            ->with($this->stringStartsWith('DELETE FROM'))
            ->will($this->returnValue($fetchAllMock));

        $response = new Response();
        (new \DrupalExternalAuth\Auth($response, $mock))->logout();
        $this->assertArrayNotHasKey('SESS1234', $_COOKIE);
        $this->assertArrayNotHasKey('SESS1234', $response->headers->getCookies());
    }
}