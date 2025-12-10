<?php

declare(strict_types=1);

namespace SimpleSAML\Module\openmetrics\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;

// Prometheus Client Libraries
use Prometheus\Storage\Redis as PromRedis;
use Prometheus\CollectorRegistry;
use Prometheus\RenderTextFormat;

// namespaces used for generating metrics
use SimpleSAML\Module; // collect enabled, disabled, & total modules
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Metadata\SAMLBuilder;
use SimpleSAML\Metadata\SAMLParser;
use SimpleSAML\Metadata\Signer;
use SimpleSAML\Auth;
use Symfony\Component\VarExporter\VarExporter;
use SimpleSAML\Module\saml\IdP\SAML2 as SAML2_IdP;
use SimpleSAML\Assert\Assert;
use SimpleSAML\SAML2\Constants as C;
use Exception;
use SimpleSAML\Store\RedisStore;
use Predis\Collection\Iterator;

class OpenMetrics
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Configuration */
    protected Configuration $moduleConfig;

    /** @var \SimpleSAML\Session */
    protected Session $session;

    /** @var \SimpleSAML\Metadata\MetaDataStorageHandler */
    protected MetadataStorageHandler $mdHandler;

    /**
     * @var \SimpleSAML\Auth\Source|string
     * @psalm-var \SimpleSAML\Auth\Source|class-string
     */
    protected $authSource = Auth\Source::class;

    /**
     * Inject the \SimpleSAML\Metadata\MetadataStorageHandler dependency.
     *
     * @param \SimpleSAML\Metadata\MetaDataStorageHandler $mdHandler
     */
    public function setMetadataStorageHandler(
        MetadataStorageHandler $mdHandler,
    ): void {
        $this->mdHandler = $mdHandler;
    }

    /**
     * Inject the \SimpleSAML\Auth\Source dependency.
     *
     * @param \SimpleSAML\Auth\Source $authSource
     */
    public function setAuthSource(Auth\Source $authSource): void
    {
        $this->authSource = $authSource;
    }

    public function __construct(Configuration $config, Session $session)
    {
        $this->config = $config;
        $this->mdHandler = MetaDataStorageHandler::getMetadataHandler($config);
        $this->moduleConfig = Configuration::getConfig(
            "module_openmetrics.php",
        );
        $this->session = $session;
        //$this->authUtils = new Utils\Auth();
    }

    public function main(Request $request): Response
    {
        // if config.basicAuth['enabled'] is true, enforce basic auth
        if ($this->moduleConfig->hasValue("basicAuth")) {
            // check if Authorization header is set
            if ($request->headers->get("Authorization") == "") {
                $response = new Response();
                $response->setStatusCode(401);
                $response->headers->set(
                    "WWW-Authenticate",
                    'Basic realm="OpenMetrics"',
                );
                return $response;
            }

            // validate basic auth
            $authHeader = $request->headers->get("Authorization");
            if (strpos($authHeader, "Basic ") !== 0) {
                $response = new Response();
                $response->setStatusCode(401);
                $response->headers->set(
                    "WWW-Authenticate",
                    'Basic realm="OpenMetrics"',
                );
                return $response;
            }

            $encodedCredentials = substr($authHeader, 6);
            $decodedCredentials = base64_decode($encodedCredentials);
            [$username, $password] = explode(":", $decodedCredentials, 2);
            $cred = $this->moduleConfig->getValue("basicAuth");
            [$validUsername, $validPassword] = explode(":", $cred, 2);

            if (
                $username !== $validUsername ||
                !password_verify($password, $validPassword)
            ) {
                $response = new Response();
                $response->setStatusCode(401);
                $response->headers->set(
                    "WWW-Authenticate",
                    'Basic realm="OpenMetrics"',
                );
                return $response;
            }
        }

        $this->updateMetrics(); // update metrics before rendering

        PromRedis::setDefaultOptions(["host" => "redis"]); // TODO: Remove hardcoded host
        $registry = new CollectorRegistry(new PromRedis());
        $renderer = new RenderTextFormat();
        $result = $renderer->render($registry->getMetricFamilySamples());

        $response = new Response();
        $response->setPublic();
        $response->headers->set("Content-Type", "text/plain; version=0.0.4");
        $response->setContent($result);

        return $response;
    }

    private function updateMetrics(): void
    {
        PromRedis::setDefaultOptions(["host" => "redis"]); // TODO: Remove hardcoded host
        $registry = new CollectorRegistry(new PromRedis());

        // session metrics
        $this->sessionMetrics($registry);

        // reset registry
        //$registry->wipeStorage();

        // IDP Metadata Certificates Expiration Metrics

        $versionGauge = $registry->getOrRegisterGauge(
            "simplesamlphp",
            "installed_version_info",
            "SimpleSAMLphp version info",
            ["version"],
        );
        $versionGauge->set(1, [$this->config->getVersion()]);

        // TODO: get latest simplesamlphp version from github and set as metric

        // modules metrics
        $modules = Module::getModules();
        $enabledCount = 0;
        foreach ($modules as $moduleName) {
            if (Module::isModuleEnabled($moduleName)) {
                $enabledCount++;
            }
        }

        $moduleTotalGauge = $registry->getOrRegisterGauge(
            "simplesamlphp",
            "modules_total",
            "Total number of SimpleSAMLphp modules",
            [],
        );
        $moduleTotalGauge->set(count($modules), []);
        $moduleEnabledGauge = $registry->getOrRegisterGauge(
            "simplesamlphp",
            "modules_enabled_total",
            "Total number of enabled SimpleSAMLphp modules",
            [],
        );
        $moduleEnabledGauge->set($enabledCount, []);

        // hosted & remote SP and IdP counts
        $hostedSPs = $this->getHostedSP();
        $hostedIdPs = $this->getHostedIdP();
        $entries = [
            "hosted" => array_merge($hostedIdPs, $hostedSPs),
            "remote" => [
                "saml20-idp-remote" => !empty($hostedSPs)
                    ? $this->mdHandler->getList("saml20-idp-remote", true)
                    : [],
                "saml20-sp-remote" =>
                    $this->config->getOptionalBoolean(
                        "enable.saml20-idp",
                        false,
                    ) === true
                        ? $this->mdHandler->getList("saml20-sp-remote", true)
                        : [],
                "adfs-sp-remote" =>
                    $this->config->getOptionalBoolean(
                        "enable.adfs-idp",
                        false,
                    ) === true && Module::isModuleEnabled("adfs")
                        ? $this->mdHandler->getList("adfs-sp-remote", true)
                        : [],
            ],
        ];

        $hostedSPGauge = $registry->getOrRegisterGauge(
            "simplesamlphp_metadata",
            "saml20_sp_hosted_total",
            "Total number of hosted SP entities",
            [],
        );
        $hostedSPGauge->set(count($hostedSPs), []);
        $hostedIdPGauge = $registry->getOrRegisterGauge(
            "simplesamlphp_metadata",
            "saml20_idp_hosted_total",
            "Total number of hosted IdP entities",
            [],
        );
        $hostedIdPGauge->set(count($hostedIdPs), []);

        foreach ($entries["remote"] as $type => $sets) {
            $typeFixed = str_replace("-", "_", $type);

            $gauge = $registry->getOrRegisterGauge(
                "simplesamlphp_metadata",
                "{$typeFixed}_total",
                "Total number of {$type} entities in the {$type} metadata set",
                [],
            );
            $gauge->set(count($sets), []);
        }

        // idp-hosted certificate expiration metrics
        foreach ($hostedIdPs as $type => $set) {
            $entityid = $set["entityid"];

            foreach ($set["certificates"] as $index => $cert) {
                $use = [];
                if (isset($cert["signing"]) && $cert["signing"]) {
                    $use[] = "signing";
                }
                if (isset($cert["encryption"]) && $cert["encryption"]) {
                    $use[] = "encryption";
                }
                $this->processCertGauge(
                    $entityid,
                    $cert["X509Certificate"],
                    implode("+", $use),
                    $set["host"],
                    "idp_hosted",
                    $registry,
                );
            }
        }

        // idp-remote certificate expiration metrics
        foreach ($entries["remote"]["saml20-idp-remote"] as $type => $set) {
            $entityid = $set["entityid"];

            $name = "unknown";
            if (isset($set["name"]["en-US"])) {
                $name = $set["name"]["en-US"];
            } elseif (isset($set["name"]["en"])) {
                $name = $set["name"]["en"];
            }

            if (!isset($set["keys"])) {
                if (isset($set["certData"])) {
                    // single cert
                    $this->processCertGauge(
                        $entityid,
                        $set["certData"],
                        "unknown",
                        $name,
                        "idp_remote",
                        $registry,
                    );
                }
                continue;
            }

            foreach ($set["keys"] as $index => $cert) {
                $use = [];
                if (isset($cert["signing"]) && $cert["signing"]) {
                    $use[] = "signing";
                }
                if (isset($cert["encryption"]) && $cert["encryption"]) {
                    $use[] = "encryption";
                }
                $this->processCertGauge(
                    $entityid,
                    $cert["X509Certificate"],
                    implode("+", $use),
                    $name,
                    "idp_remote",
                    $registry,
                );
            }
        }

        // sp-remote certificate expiration metrics
        foreach ($entries["remote"]["saml20-sp-remote"] as $type => $set) {
            $entityid = $set["entityid"];

            if (!isset($set["keys"])) {
                if (isset($set["certData"])) {
                    // single cert
                    $this->processCertGauge(
                        $entityid,
                        $set["certData"],
                        "unknown",
                        $set["name"]["en-US"] ?? "unknown",
                        "sp_remote",
                        $registry,
                    );
                }
                continue;
            }

            foreach ($set["keys"] as $index => $cert) {
                $use = [];
                if (isset($cert["signing"]) && $cert["signing"]) {
                    $use[] = "signing";
                }
                if (isset($cert["encryption"]) && $cert["encryption"]) {
                    $use[] = "encryption";
                }
                // name can be $set["name"]["en-US"], or $set["name"]["en"] - otherwise unknown
                $name = "unknown";
                if (isset($set["name"]["en-US"])) {
                    $name = $set["name"]["en-US"];
                } elseif (isset($set["name"]["en"])) {
                    $name = $set["name"]["en"];
                }

                if (!isset($cert["X509Certificate"])) {
                    // missing cert data, skip!
                    continue;
                }

                $this->processCertGauge(
                    $entityid,
                    $cert["X509Certificate"],
                    implode("+", $use),
                    $name,
                    "sp_remote",
                    $registry,
                );
            }
        }
    }

    private function processCertGauge(
        $entityid,
        $certData,
        $use,
        $name,
        $type,
        $registry,
    ): void {
        $certRaw = $this->formatCertificate($certData);
        $properties = openssl_x509_parse($certRaw);

        $expiration_time = $properties["validTo_time_t"];
        $subjectCN = $properties["subject"]["CN"] ?? "unknown";
        $serialNumber = $properties["serialNumber"] ?? "unknown";

        $gauge = $registry->getOrRegisterGauge(
            "simplesamlphp",
            "metadata_saml20_{$type}_certificate_expiration_timestamp",
            "Expiration timestamp of {$type} metadata certificates",
            ["entityId", "subjectCn", "serialNumber", "use", "name"],
        );
        $gauge->set($expiration_time, [
            $entityid,
            $subjectCN,
            $serialNumber,
            $use,
            $name,
        ]);
    }

    private function formatCertificate($cert)
    {
        // remove whitespace chars
        $cert = preg_replace("/\s+/", "", $cert);

        // remove BEGIN and END certificate lines
        $cert = preg_replace("/-----BEGIN CERTIFICATE-----/", "", $cert);
        $cert = preg_replace("/-----END CERTIFICATE-----/", "", $cert);

        // now format it correct - add newlines after every 76 characters
        $cert = chunk_split($cert, 76, "\n");

        // add BEGIN and END certificate lines
        return "-----BEGIN CERTIFICATE-----\n" .
            $cert .
            "-----END CERTIFICATE-----\n";
    }

    private function sessionMetrics($registry): void
    {
        // process session metrics ??
        $storeType = $this->config->getOptionalString(
            "store.type",
            "phpsession",
        );

        // TODO: add support for other store types
        if ($storeType === "redis") {
            $store = new RedisStore();
            $redis = $store->redis;

            $sessions = 0;
            foreach (new Iterator\Keyspace($redis, "SimpleSAMLphp:*") as $key) {
                //print_r($key);
                $sessions++;
            }

            $gauge = $registry->getOrRegisterGauge(
                "simplesamlphp",
                "active_sessions_total",
                "Total number of active sessions",
                [],
            );
            $gauge->set($sessions, []);
        }
    }

    /**
     * Get an array of entities describing the local SP instances. (stolen from SimpleSamlphp/modules/admin/src/Controller/Federation.php)
     *
     * @return array
     * @throws \SimpleSAML\Error\Exception If OrganizationName is set for an SP instance but OrganizationURL is not.
     * @throws \Symfony\Component\VarExporter\Exception\ExceptionInterface
     * @throws \Exception
     */
    private function getHostedSP(): array
    {
        $entities = [];

        /** @var \SimpleSAML\Module\saml\Auth\Source\SP $source */
        foreach ($this->authSource::getSourcesOfType("saml:SP") as $source) {
            $metadata = $source->getHostedMetadata();
            if (isset($metadata["keys"])) {
                $certificates = $metadata["keys"];
                if (count($metadata["keys"]) === 1) {
                    $cert = array_pop($metadata["keys"]);
                    $metadata["certData"] = $cert["X509Certificate"];
                    unset($metadata["keys"]);
                }
            } else {
                $certificates = [];
            }

            // get the name
            $name = $source
                ->getMetadata()
                ->getOptionalLocalizedString(
                    "name",
                    $source
                        ->getMetadata()
                        ->getOptionalLocalizedString(
                            "OrganizationDisplayName",
                            ["en" => $source->getAuthId()],
                        ),
                );

            $builder = new SAMLBuilder($source->getEntityId());
            $builder->addMetadataSP20(
                $metadata,
                $source->getSupportedProtocols(),
            );
            $builder->addOrganizationInfo($metadata);
            $xml = $builder->getEntityDescriptorText(true);

            // sanitize the resulting array
            unset($metadata["metadata-set"]);
            unset($metadata["entityid"]);

            // sanitize the attributes array to remove friendly names
            if (
                isset($metadata["attributes"]) &&
                is_array($metadata["attributes"])
            ) {
                $metadata["attributes"] = array_values($metadata["attributes"]);
            }

            // sign the metadata if enabled
            $xml = Signer::sign(
                $xml,
                $source->getMetadata()->toArray(),
                "SAML 2 SP",
            );

            $entities[] = [
                "authid" => $source->getAuthId(),
                "entityid" => $source->getEntityId(),
                "type" => "saml20-sp-hosted",
                "url" => $source->getMetadataURL(),
                "name" => $name,
                "metadata" => $xml,
                "metadata_array" => VarExporter::export($metadata),
                "certificates" => $certificates,
            ];
        }

        return $entities;
    }

    /**
     * Get a list of the hosted IdP entities, including SAML 2 and ADFS. (stolen from SimpleSamlphp/modules/admin/src/Controller/Federation.php)
     *
     * @return array
     * @throws \Exception
     * @throws \Symfony\Component\VarExporter\Exception\ExceptionInterface
     */
    private function getHostedIdP(): array
    {
        $entities = [];

        // SAML 2
        if ($this->config->getOptionalBoolean("enable.saml20-idp", false)) {
            try {
                $idps = $this->mdHandler->getList("saml20-idp-hosted");
                $saml2entities = [];
                $httpUtils = new Utils\HTTP();
                $metadataBase = Module::getModuleURL("saml/idp/metadata");
                if (count($idps) > 1) {
                    $selfHost = $httpUtils->getSelfHostWithPath();
                    foreach ($idps as $index => $idp) {
                        if (
                            isset($idp["host"]) &&
                            $idp["host"] !== "__DEFAULT__"
                        ) {
                            $mdHostBase = str_replace(
                                "://" . $selfHost . "/",
                                "://" . $idp["host"] . "/",
                                $metadataBase,
                            );
                        } else {
                            $mdHostBase = $metadataBase;
                        }
                        $idp["url"] =
                            $mdHostBase .
                            "?idpentityid=" .
                            urlencode($idp["entityid"]);
                        $idp["metadata-set"] = "saml20-idp-hosted";
                        $idp["metadata-index"] = $index;
                        $idp["metadata_array"] = SAML2_IdP::getHostedMetadata(
                            $idp["entityid"],
                        );
                        $saml2entities[] = $idp;
                    }
                } else {
                    $saml2entities[
                        "saml20-idp"
                    ] = $this->mdHandler->getMetaDataCurrent(
                        "saml20-idp-hosted",
                    );
                    $saml2entities["saml20-idp"]["url"] = $metadataBase;
                    $saml2entities["saml20-idp"][
                        "metadata_array"
                    ] = SAML2_IdP::getHostedMetadata(
                        $this->mdHandler->getMetaDataCurrentEntityID(
                            "saml20-idp-hosted",
                        ),
                    );
                }

                foreach ($saml2entities as $index => $entity) {
                    Assert::validURI($entity["entityid"]);
                    Assert::maxLength(
                        $entity["entityid"],
                        C::SAML2INT_ENTITYID_MAX_LENGTH,
                        sprintf(
                            "The entityID cannot be longer than %d characters.",
                            C::SAML2INT_ENTITYID_MAX_LENGTH,
                        ),
                    );

                    $builder = new SAMLBuilder($entity["entityid"]);
                    $builder->addMetadataIdP20($entity["metadata_array"]);
                    $builder->addOrganizationInfo($entity["metadata_array"]);

                    $entity["metadata"] = Signer::sign(
                        $builder->getEntityDescriptorText(),
                        $entity["metadata_array"],
                        "SAML 2 IdP",
                    );
                    $entities[$index] = $entity;
                }
            } catch (Exception $e) {
                Logger::error(
                    "Federation: Error loading saml20-idp: " . $e->getMessage(),
                );
            }
        }

        // ADFS
        if (
            $this->config->getOptionalBoolean("enable.adfs-idp", false) &&
            Module::isModuleEnabled("adfs")
        ) {
            try {
                $idps = $this->mdHandler->getList("adfs-idp-hosted");
                $adfsentities = [];
                if (count($idps) > 1) {
                    foreach ($idps as $index => $idp) {
                        $idp["url"] = Module::getModuleURL(
                            "adfs/idp/metadata/?idpentityid=" .
                                urlencode($idp["entityid"]),
                        );
                        $idp["metadata-set"] = "adfs-idp-hosted";
                        $idp["metadata-index"] = $index;
                        $idp["metadata_array"] = ADFS_IdP::getHostedMetadata(
                            $idp["entityid"],
                        );
                        $adfsentities[] = $idp;
                    }
                } else {
                    $adfsentities[
                        "adfs-idp"
                    ] = $this->mdHandler->getMetaDataCurrent("adfs-idp-hosted");
                    $adfsentities["adfs-idp"]["url"] = Module::getModuleURL(
                        "adfs/idp/metadata.php",
                    );
                    $adfsentities["adfs-idp"][
                        "metadata_array"
                    ] = ADFS_IdP::getHostedMetadata(
                        $this->mdHandler->getMetaDataCurrentEntityID(
                            "adfs-idp-hosted",
                        ),
                    );
                }

                foreach ($adfsentities as $index => $entity) {
                    Assert::validURI($entity["entityid"]);
                    Assert::maxLength(
                        $entity["entityid"],
                        C::SAML2INT_ENTITYID_MAX_LENGTH,
                        sprintf(
                            "The entityID cannot be longer than %d characters.",
                            C::SAML2INT_ENTITYID_MAX_LENGTH,
                        ),
                    );

                    $builder = new SAMLBuilder($entity["entityid"]);
                    $builder->addSecurityTokenServiceType(
                        $entity["metadata_array"],
                    );
                    $builder->addOrganizationInfo($entity["metadata_array"]);
                    if (isset($entity["metadata_array"]["contacts"])) {
                        foreach ($entity["metadata_array"]["contacts"] as $c) {
                            try {
                                $contact = ContactPerson::fromArray($c);
                            } catch (ArrayValidationException $e) {
                                Logger::warning(
                                    "Federation: invalid content found in contact: " .
                                        $e->getMessage(),
                                );
                                continue;
                            }
                            $builder->addContact($contact);
                        }
                    }

                    $entity["metadata"] = Signer::sign(
                        $builder->getEntityDescriptorText(),
                        $entity["metadata_array"],
                        "ADFS IdP",
                    );
                    $entities[$index] = $entity;
                }
            } catch (Exception $e) {
                Logger::error(
                    "Federation: Error loading adfs-idp: " . $e->getMessage(),
                );
            }
        }

        // process certificate information and dump the metadata array
        foreach ($entities as $index => $entity) {
            $entities[$index]["type"] = $entity["metadata-set"];
            foreach ($entity["metadata_array"]["keys"] as $kidx => $key) {
                unset($entity["metadata_array"]["keys"][$kidx]["prefix"]);
                $entities[$index]["certificates"][] = $key;
            }

            // only one key, reduce
            if (count($entity["metadata_array"]["keys"]) === 1) {
                $cert = array_pop($entity["metadata_array"]["keys"]);
                $entity["metadata_array"]["certData"] =
                    $cert["X509Certificate"];
                unset($entity["metadata_array"]["keys"]);
            }

            $entities[$index]["metadata_array"] = VarExporter::export(
                $entity["metadata_array"],
            );
        }

        return $entities;
    }
}
