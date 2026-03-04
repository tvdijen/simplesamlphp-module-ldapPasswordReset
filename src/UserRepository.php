<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldapPasswordReset;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Module\ldap\Connector;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Ldap;
use Symfony\Component\Ldap\Security\LdapUserProvider;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;

use function mb_convert_encoding;

/**
 * This class is a wrapper around the ldap-module
 *
 * @package simplesamlphp/simplesamlphp-module-ldapPasswordReset
 */
class UserRepository
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Configuration */
    protected Configuration $moduleConfig;

    /** @var \SimpleSAML\Configuration */
    protected Configuration $ldapSource;

    /** @var \SimpleSAML\Module\ldap\Connector\Ldap */
    protected Connector\Ldap $connector;


    /**
     */
    public function __construct()
    {
        $this->moduleConfig = Configuration::getOptionalConfig('module_ldapPasswordReset.php');
        $authSource = $this->moduleConfig->getString('ldapSource');
        $authSources = Configuration::getConfig('authsources.php');

        $this->ldapSource = Configuration::loadFromArray(
            $authSources->getValue($authSource),
        );

        $encryption = $this->ldapSource->getOptionalString('encryption', 'ssl');
        Assert::oneOf($encryption, ['none', 'ssl', 'tls']);

        $version = $this->ldapSource->getOptionalInteger('version', 3);
        Assert::positiveInteger($version);

        $this->connector = new Connector\Ldap(
            $this->ldapSource->getString('connection_string'),
            $encryption,
            $version,
            $this->ldapSource->getOptionalString('extension', 'ext_ldap'),
            $this->ldapSource->getOptionalBoolean('debug', false),
            $this->ldapSource->getOptionalArray('options', []),
        );
    }


    /**
     * Find user in LDAP-store
     *
     * @param string $email
     * @return \Symfony\Component\Ldap\Entry|null
     */
    public function findUserByEmail(string $email): ?Entry
    {
        $searchBase = $this->ldapSource->getArray('search.base');

        $searchUsername = $this->ldapSource->getString('search.username');
        Assert::notWhitespaceOnly($searchUsername);

        $searchPassword = $this->ldapSource->getOptionalString('search.password', null);
        Assert::nullOrNotWhitespaceOnly($searchPassword);

        $ldap = new Ldap($this->connector->getAdapter());

        foreach ($searchBase as $baseDn) {
            $ldapUserProvider = new LdapUserProvider(
                $ldap,
                $baseDn,
                $searchUsername,
                $searchPassword,
                [],
                $this->moduleConfig->getOptionalString('ldapIdentifyingAttribute', 'userPrincipalName'),
            );

            try {
                return $ldapUserProvider->loadUserByIdentifier($email)->getEntry();
            } catch (UserNotFoundException $e) {
                // We haven't found the user
                continue;
            }
        }

        return null;
    }


    /**
     * Update user password in LDAP-store
     *
     * @param \Symfony\Component\Ldap\Entry $user
     * @param string $newPassword
     * @return bool
     */
    public function updatePassword(Entry $user, string $newPassword): bool
    {
        $searchUsername = $this->ldapSource->getString('search.username');
        Assert::notWhitespaceOnly($searchUsername);

        $searchPassword = $this->ldapSource->getOptionalString('search.password', null);
        Assert::nullOrNotWhitespaceOnly($searchPassword);

        try {
            $this->connector->bind($searchUsername, $searchPassword);
        } catch (Error\Error $e) {
            throw new Error\Exception("Unable to bind using the configured search.username and search.password.");
        }

        $userPassword = mb_convert_encoding('"' . $newPassword . '"', 'utf-16le');
        $newEntry = new Entry($user->getDn(), [
            'unicodePwd' => [$userPassword],
        ]);

        return $this->connector->updateEntry($newEntry);
    }
}
