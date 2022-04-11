<?php

namespace SimpleSAML\Module\ldapPasswordReset;

use SimpleSAML\{Assert, Configuration, Error, Logger};
use SimpleSAML\Module\ldap\Utils as LdapUtils;
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

    /** @var \Symfony\Component\Ldap\Ldap */
    protected Ldap $ldapObject;

    /** @var \SimpleSAML\Module\ldap\Utils */
    protected LdapUtils $ldapUtils;


    /**
     */
    public function __construct()
    {
        $this->moduleConfig = Configuration::getOptionalConfig('module_ldappasswordreset.php');
        $this->ldapUtils = new LdapUtils();

        $encryption = $this->moduleConfig->getOptionalString('encryption', 'ssl');
        Assert::oneOf($encryption, ['none', 'ssl', 'tls']);

        $version = $this->moduleConfig->getOptionalInteger('version', 3);
        Assert::positiveInteger($version);

        $this->ldapObject = $this->ldapUtils->create(
            $this->moduleConfig->getString('connection_string'),
            $encryption,
            $version,
            $this->moduleConfig->getOptionalString('extension', 'ext_ldap'),
            $this->moduleConfig->getOptionalBoolean('debug', false),
            $this->moduleConfig->getOptionalArray('options', []),
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
        $searchBase = $this->moduleConfig->getString('search.base');

        $searchUsername = $this->moduleConfig->getString('search.username');
        Assert::notWhitespaceOnly($searchUsername);

        $searchPassword = $this->moduleConfig->getOptionalString('search.password', null);
        Assert::nullOrnotWhitespaceOnly($searchPassword);

        $ldapUserProvider = new LdapUserProvider($this->ldapObject, $searchBase, $searchUsername, $searchPassword, [], 'mail');

        try {
            return $ldapUserProvider->loadUserByUsername($email)->getEntry();
        } catch (UserNotFoundException $e) {
            // We haven't found the user
            return null;
        }
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
        $searchUsername = $this->moduleConfig->getString('search.username');
        Assert::notWhitespaceOnly($searchUsername);

        $searchPassword = $this->moduleConfig->getOptionalString('search.password', null);
        Assert::nullOrnotWhitespaceOnly($searchPassword);

        try {
            $this->ldapUtils->bind($this->ldapObject, $searchUsername, $searchPassword);
        } catch (Error\Error $e) {
            throw new Error\Exception("Unable to bind using the configured search.username and search.password.");
        }

        $userPassword = mb_convert_encoding('"' . $newPassword . '"', 'utf-16le');
        $newEntry = new Entry($user->getDn(), [
            'unicodePwd' => [$userPassword],
        ]);

        try {
            $this->ldapObject->getEntryManager()->update($newEntry);
            return true;
        } catch (LdapException $e) {
            Logger::warning($e->getMessage());
            return false;
        }
    }
}
