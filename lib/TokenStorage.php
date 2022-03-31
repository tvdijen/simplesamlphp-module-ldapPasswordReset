<?php

namespace SimpleSAML\Module\ldapPasswordReset;

use Exception;
use Ramsey\Uuid\Uuid;
use SimpleSAML\Configuration;
use SimpleSAML\Store;
use Symfony\Component\Ldap\Entry;

use function array_pop;
use function base64_encode;
use function time;

/**
 * This class generates and stores tokens to be used in magic links
 *
 * @package simplesamlphp/simplesamlphp-module-ldapPasswordReset
 */
class TokenStorage
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Configuration */
    protected Configuration $moduleConfig;


    /**
     * @param \SimpleSAML\Configuration $config The configuration to use.
     */
    public function __construct(Configuration $config)
    {
        $this->config = $config;
        $this->moduleConfig = Configuration::getOptionalConfig('module_ldappasswordreset.php');
    }


    /**
     * Store token
     *
     * @param string $token
     * @param \Symfony\Component\Ldap\Entry $user
     * @return void
     */
    public function storeToken(string $token, Entry $user): void
    {
        $store = Store\StoreFactory::getInstance($this->config->getString('store.type'));
        if ($store === false) {
            throw new Exception('Using `phpsession` as a store is not supported when using this module.');
        }

        // TODO: Make expiration configurable
        $expire = time() + (60 * 15);
        $attributes = $user->getAttributes();
        $objectGuid = array_pop($attributes['objectGUID']);
        $store->set('magiclink', $token, ['objectGUID' => $objectGuid], $expire);
    }


    /**
     * Generate token
     *
     * @return string
     */
    public function generateToken(): string
    {
        $uuid = Uuid::uuid4();
        return base64_encode($uuid->toString());
    }
}
