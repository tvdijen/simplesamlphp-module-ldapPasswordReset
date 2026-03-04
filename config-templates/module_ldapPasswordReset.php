<?php

/*
 * Configuration for the ldapPasswordReset module.
 */

$config = [
    // The authsource used for authentication before the password can be reset
    'auth' => 'RADIUS',

    // The attribute returned by the authsource that identifies the user
    'identifyingAttribute' => 'userPrincipalName',

    // The LDAP-source where the password has to be reset
    'ldapSource' => 'LDAP',

    // The attribute to use when searching for the user
    'ldapIdentifyingAttribute' => 'userPrincipalName',
];
