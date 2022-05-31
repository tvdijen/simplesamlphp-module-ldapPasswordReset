# Password reset for an LDAP-account

![Build Status](https://github.com/tvdijen/simplesamlphp-module-ldapPasswordreset/workflows/CI/badge.svg?branch=master)
[![Coverage Status](https://codecov.io/gh/tvdijen/simplesamlphp-module-ldapPasswordreset/branch/master/graph/badge.svg)](https://codecov.io/gh/tvdijen/simplesamlphp-module-ldapPasswordreset)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/tvdijen/simplesamlphp-module-ldapPasswordreset/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/tvdijen/simplesamlphp-module-ldapPasswordreset/?branch=master)

## Install

Install with composer

```bash
vendor/bin/composer require simplesamlphp/simplesamlphp-module-ldapPasswordReset
```

## Configuration

Next thing you need to do is to enable the module: in `config.php`,
search for the `module.enable` key and set `ldapPasswordReset` to true:

```php
'module.enable' => [
    'ldapPasswordReset' => true,
    …
],
```
