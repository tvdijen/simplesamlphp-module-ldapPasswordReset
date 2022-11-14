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
        $this->moduleConfig = Configuration::getOptionalConfig('module_ldapPasswordReset.php');
    }


    /**
     * Send magic link
     *
     * @param string $email
     * @param string $token
     * @param int $validUntil
     * @return void
     */
    public function sendMagicLink(string $email, string $token, int $validUntil): void
    {
        $url = Module::getModuleURL('ldapPasswordReset/validateMagicLink', ['t' => $token]);

        $mail = new Utils\EMail(
            $this->moduleConfig->getOptionalString('email.subject', 'Password reset'),
            $this->moduleConfig->getOptionalString('email.from', $this->config->getString('technicalcontact_email')),
            $email,
            'ldapPasswordReset:mailtxt.twig',
            'ldapPasswordReset:mailhtml.twig'
        );
        $mail->setData(['url' => $url, 'validUntil' => $validUntil]);
        $mail->setText('{url}');
        $mail->send();
    }
}
