<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldapPasswordReset;

use Exception;
use Ramsey\Uuid\Uuid;
use SimpleSAML\Configuration;
use SimpleSAML\Store;
use Symfony\Component\HttpFoundation\Request;

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

    /** @var \Symfony\Component\HttpFoundation\Request */
    protected Request $request;

    /** @var \SimpleSAML\Store\StoreInterface */
    protected Store\StoreInterface $store;


    /**
     * @param \SimpleSAML\Configuration $config The configuration to use.
     */
    public function __construct(Configuration $config)
    {
        $store = Store\StoreFactory::getInstance($config->getString('store.type'));
        if ($store === false) {
            throw new Exception('Using `phpsession` as a store is not supported when using this module.');
        }

        $this->store = $store;
        $this->config = $config;
    }


    /**
     * Store token
     *
     * @param string $token
     * @param string $mail
     * @param string $session
     * @param int $validUntil
     * @param string|null $referer
     * @return void
     */
    public function storeToken(string $token, string $mail, string $session, int $validUntil, ?string $referer): void
    {
        $this->store->set(
            'magiclink',
            $token,
            ['mail' => $mail, 'session' => $session, 'referer' => $referer],
            $validUntil,
        );
    }


    /**
     * Retrieve stored token
     *
     * @param string $token
     * @return array|null
     */
    public function retrieveToken(string $token): ?array
    {
        return $this->store->get('magiclink', $token);
    }


    /**
     * Delete stored token
     *
     * @param string $token
     * @return void
     */
    public function deleteToken(string $token): void
    {
        $this->store->delete('magiclink', $token);
    }


    /**
     * Generate token
     *
     * @return string
     */
    public function generateToken(): string
    {
        return Uuid::uuid4()->toString();
    }
}
