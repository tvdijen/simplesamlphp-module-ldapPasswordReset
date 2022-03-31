<?php

namespace SimpleSAML\Module\ldapPasswordReset;

use PHPMailer\PHPMailer\PHPMailer;
use SimpleSAML\{Configuration, Module, Utils};

/**
 * This class takes care of sending the magic links through email
 *
 * @package simplesamlphp/simplesamlphp-module-ldapPasswordReset
 */
class MagicLink
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
     * Send magic link
     *
     * @param string $email
     * @param string $token
     * @return void
     */
    public function sendMagicLink(string $email, string $token): void
    {
        $url = Module::getModuleURL('ldapPasswordReset/resetPassword', ['t' => $token]);

        $mail = new EMail('Password reset', 'noreply@moo-archive.nl', $email);
        $mail->setData(['url' => $url]);
        $mail->setText('{url}');
        $mail->send();
    }
}
