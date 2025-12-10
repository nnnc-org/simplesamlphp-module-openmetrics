<?php

namespace SimpleSAML\Module\openmetrics\Auth\Process;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Logger;
use SimpleSAML\Session;

use Prometheus\Storage\Redis as PromRedis;
use Prometheus\CollectorRegistry;

class OpenMetrics extends ProcessingFilter
{
    public function process(array &$state): void
    {
        Assert::keyExists($state, "Destination");
        Assert::keyExists($state["Destination"], "entityid");
        Assert::keyExists($state, "Source");
        Assert::keyExists($state["Source"], "entityid");

        $session = Session::getSessionFromRequest();

        // get multiauth source
        $source = "unknown";
        $multiauth = $session->getDataOfType("multiauth:selectedSource");
        foreach ($multiauth as $key => $value) {
            Logger::info(
                "OpenMetrics: multiauth selectedSource $key => $value",
            );
            $source = $value; // just grabs the last one if multiple exist
        }

        Logger::info("OpenMetrics: Auth Proc Filter - multiauth: $source");
        Logger::info(
            "OpenMetrics: Auth Proc Filter - Source: {$state["Source"]["entityid"]}",
        );
        Logger::info(
            "OpenMetrics: Auth Proc Filter - Destination: {$state["Destination"]["entityid"]}",
        );

        PromRedis::setDefaultOptions(["host" => "redis"]); // TODO: Remove hardcoded host
        $registry = new CollectorRegistry(new PromRedis());
        $spcounter = $registry->getOrRegisterCounter(
            "simplesamlphp",
            "sp_successful_logins_total",
            "Counter of successful logins for SP",
            ["entityId"],
        );
        $idpcounter = $registry->getOrRegisterCounter(
            "simplesamlphp",
            "idp_successful_logins_total",
            "Counter of successful logins for idp",
            ["entityId", "multiauth"],
        );
        $spcounter->inc([$state["Destination"]["entityid"]]);
        $idpcounter->inc([$state["Source"]["entityid"], $source ?? "unknown"]);
    }
}
