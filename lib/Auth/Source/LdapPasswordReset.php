<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldap\PasswordReset\Auth\Source\Ldap;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Module;
use SimpleSAML\Utils;

use function var_export;

/**
 * LDAP password reset authentication source.
 *
 * See the `password-reset`-entry in config-templates/authsources.php for information about
 * configuration of this authentication source.
 *
 * @package simplesamlphp/simplesamlphp-module-ldapPasswordReset
 */

class LdapPasswordReset extends Auth\Source
{
    /**
     * The string used to identify our states.
     */
    public const STAGEID = '\SimpleSAML\Module\ldap\PasswordReset\Auth\Source\LdapPasswordReset.state';

    /**
     * The key of the AuthId field in the state.
     */
    public const AUTHID = '\SimpleSAML\Module\ldap\PasswordReset\Auth\Source\LdapPasswordReset.AuthId';

    /**
     * An LDAP configuration object.
     */
    private Configuration $ldapConfig;


    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct(array $info, array $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        $this->ldapConfig = Configuration::loadFromArray(
            $config,
            'authsources[' . var_export($this->authId, true) . ']'
        );
    }


    /**
     * Initialize login.
     *
     * This function saves the information about the login, and redirects to a
     * login page.
     *
     * @param array &$state  Information about the current authentication.
     */
    public function authenticate(array &$state): void
    {
        /*
         * Save the identifier of this authentication source, so that we can
         * retrieve it later. This allows us to call the login()-function on
         * the current object.
         */
        $state[self::AUTHID] = $this->authId;

        // Save the $state-array, so that we can restore it after a redirect
        $id = Auth\State::saveState($state, self::STAGEID);

        /** @var \SimpleSAML\Module\ldap\PasswordReset\Auth\Source\PasswordReset|null $source */
        $source = $this->authSource::getById($state[LdapPasswordReset::AUTHID]);
        if ($source === null) {
            throw new Exception(
                'Could not find authentication source with id ' . $state[LdapPasswordReset::AUTHID]
            );
        }

        $this->handleLogin($request, $source, $state);

        /*
         * Redirect to the login form. We include the identifier of the saved
         * state array as a parameter to the login form.
        $url = Module::getModuleURL('ldapPasswordReset/enterEMail');
        $params = ['AuthState' => $id];
        $httpUtils = new Utils\HTTP();
        $httpUtils->redirectTrustedURL($url, $params);
         */

        // The previous function never returns, so this code is never executed.
        Assert::true(false);
    }
}


