<?php


declare(strict_types=1);

namespace SimpleSAML\Module\openmetrics\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;

use Prometheus\Storage\Redis as PromRedis;
use Prometheus\CollectorRegistry;
use Prometheus\RenderTextFormat;


class OpenMetrics
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Configuration */
    protected Configuration $moduleConfig;

    /** @var \SimpleSAML\Session */
    protected Session $session;


    public function __construct(Configuration $config, Session $session)
    {
        $this->config = $config;
        $this->moduleConfig = Configuration::getConfig('module_openmetrics.php');
        $this->session = $session;
        //$this->authUtils = new Utils\Auth();
    }

    public function main(Request $request): Response
    {
        // if config.basicAuth['enabled'] is true, enforce basic auth
        if ($this->moduleConfig->hasValue('basicAuth')) {
            // check if Authorization header is set
            if ($request->headers->get('Authorization') == "") {
                $response = new Response();
                $response->setStatusCode(401);
                $response->headers->set('WWW-Authenticate', 'Basic realm="OpenMetrics"');
                return $response;
            }

            // validate basic auth
            $authHeader = $request->headers->get('Authorization');
            if (strpos($authHeader, 'Basic ') !== 0) {
                $response = new Response();
                $response->setStatusCode(401);
                $response->headers->set('WWW-Authenticate', 'Basic realm="OpenMetrics"');
                return $response;
            }

            $encodedCredentials = substr($authHeader, 6);
            $decodedCredentials = base64_decode($encodedCredentials);
            list($username, $password) = explode(':', $decodedCredentials, 2);
            $cred = $this->moduleConfig->getValue('basicAuth');
            list($validUsername, $validPassword) = explode(':', $cred, 2);

            if ($username !== $validUsername || !password_verify($password, $validPassword)) {
                $response = new Response();
                $response->setStatusCode(401);
                $response->headers->set('WWW-Authenticate', 'Basic realm="OpenMetrics"');
                return $response;
            }
        }

        $this->updateMetrics(); // update metrics before rendering

        PromRedis::setDefaultOptions(['host' => "redis"]); // TODO: Remove hardcoded host
        $registry = new CollectorRegistry(new PromRedis());
        $renderer = new RenderTextFormat();
        $result = $renderer->render($registry->getMetricFamilySamples());

        $response = new Response();
        $response->setPublic();
        $response->headers->set('Content-Type', 'text/plain; version=0.0.4');
        $response->setContent($result);

        return $response;
    }

    private function updateMetrics(): void
    {
        // TODO: grab metadata certificate expiration metrics
        // TODO: grab total number of SPs and IDPs metrics
        // TODO: get current sessions metric

        PromRedis::setDefaultOptions(['host' => "redis"]); // TODO: Remove hardcoded host
        $registry = new CollectorRegistry(new PromRedis());

        //$counter = $registry->getOrRegisterCounter('test', 'some_counter', 'it increases', ['type']);
        //$counter->incBy(3, ['blue']);

        // IDP Metadata Certificates Expiration Metrics





    }
}
