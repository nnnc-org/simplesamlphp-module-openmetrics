<?php

namespace SimpleSAML\Module\openmetrics\Auth\Process;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Session;

use Prometheus\Storage\Redis as PromRedis;
use Prometheus\CollectorRegistry;

use SimpleSAML\Module\openmetrics\RedisConfig;

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

        // Prefer the district the user actually selected, recorded by the
        // nebraskacloudAuth:select controller. IDPs that federate through a
        // shared upstream source (e.g. subA-idp -> broker-idp) authenticate as that
        // source, so multiauth:selectedSource only ever reports the upstream. This
        // key preserves per-idp reporting. Falls back to the delegated source.
        $district = null;
        $selectedDistrict = $session->getDataOfType(
            "nebraskacloudAuth:selectedDistrict",
        );
        foreach ($selectedDistrict as $key => $value) {
            Logger::info(
                "OpenMetrics: nebraskacloudAuth selectedDistrict $key => $value",
            );
            $district = $value; // just grabs the last one if multiple exist
        }

        // Label used for the idp login counter's "multiauth" dimension.
        $multiauthLabel = $district ?? $source;

        Logger::info("OpenMetrics: Auth Proc Filter - multiauth: $multiauthLabel");
        Logger::info(
            "OpenMetrics: Auth Proc Filter - Source: {$state["Source"]["entityid"]}",
        );
        Logger::info(
            "OpenMetrics: Auth Proc Filter - Destination: {$state["Destination"]["entityid"]}",
        );

        $moduleConfig = Configuration::getConfig("module_openmetrics.php");
        PromRedis::setDefaultOptions(RedisConfig::options($moduleConfig));
        // Disable promphp's default metrics: its constructor otherwise writes a
        // php_info{version=PHP_VERSION} gauge into Redis on every login, and
        // that series is never pruned, so each PHP upgrade leaves another stale
        // value behind. This filter only needs to increment the login counters.
        $registry = new CollectorRegistry(new PromRedis(), false);
        $spcounter = $registry->getOrRegisterCounter(
            "simplesamlphp",
            "sp_successful_logins_total",
            "Counter of successful logins for SP",
            ["entityId"],
        );
        $idpcounter = $registry->getOrRegisterCounter(
            "simplesamlphp",
            "idp_successful_logins_total",
            "Counter of successful logins for idp by multiauth source",
            ["entityId", "multiauth"],
        );
        $globallogincounter = $registry->getOrRegisterCounter(
            "simplesamlphp",
            "global_successful_logins_total",
            "Counter of successful logins for all SPs and IDPs",
        );
        $spcounter->inc([$state["Destination"]["entityid"]]);
        $idpcounter->inc([$state["Source"]["entityid"], $multiauthLabel ?? "unknown"]);
        $globallogincounter->inc();
    }
}
