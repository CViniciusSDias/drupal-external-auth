<?php
use Symfony\Component\HttpFoundation\Response;

require 'vendor/autoload.php';

$response = new Response();
$pdo = new \PDO('mysql:host=127.0.0.1;dbname=csp', 'root', 'root');
(new \DrupalExternalAuth\Auth($response, $pdo))->auth([
    'name'     => 'username',
    'pass'     => 'PrefixHash$' . 'hashOfPassord',
    'timezone' => 'America/Sao_Paulo',
    'langcode' => 'pt-br',
    'roles' => ['administrator']
]);
foreach ($response->headers->getCookies() as $cookie) {
    header('Set-Cookie: '.$cookie->getName().strstr($cookie, '='));
}