<?php

/*
 * Configuration for the ldapPasswordReset module.
 */

$config = [
    // The hostname of the LDAP server.
    'connection_string' => 'ldaps://ldap.example.org',

    // Whether SSL/TLS should be used when contacting the LDAP server.
    'enable_tls' => true,

    // Whether debug output from the LDAP library should be enabled.
    // Default is FALSE.
    'debug' => true,

    // The port used when accessing the LDAP server.
    // The default is 389.
    'port' => 636,

    // The DN which will be used as a base for the search.
    // This must be a single string.
    'search.base' => 'ou=pwreset,dc=example,dc=org',

    // The attribute the username should match against.
    //
    // This is a string with one attribute name.
    'search.attribute' => 'mail',

    // The username & password the SimpleSAMLphp should bind to before searching. If
    // this is left as NULL, no bind will be performed before searching.
    'search.username' => 'CN=IDP LDAP Account,OU=Service Accounts,DC=example,DC=org',
    'search.password' => 'secret',

    // The email properties
    //
    // The subject for the mail. Defaults to 'Password reset'
    //'email.subject' => 'Password reset',

    // The from-address for the mail. Defaults to 'technicalcontact_email' in config.php
    //'email.from' => 'noreply@example.org',

    // Lock the magic link to the user's browser session. An error message
    // will be shown when the magic link is used from another browser.
    // The default is TRUE
    'lockBrowserSession' => true,

    // The number of minutes the magic link can be used
    // The default is 15 minutes
    'magicLinkExpiration' => 15,
];
