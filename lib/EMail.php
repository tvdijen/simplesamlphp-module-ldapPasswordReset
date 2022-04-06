<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldapPasswordReset;

use SimpleSAML\{Configuration, Utils};
use SimpleSAML\XHTML\Template;

/**
 * E-mailer class that can generate a formatted e-mail from array
 * input data.
 *
 * @package tvdijen/simplesamlphp-module-ldapPasswordreset
 */

class EMail extends Utils\EMail
{
    /*
     * Generate the body of the e-mail
     *
     * @param string $template The name of the template to use
     *
     * @return string The body of the e-mail
     */
    public function generateBody(string $template): string
    {
        $config = Configuration::getInstance();

        $t = new class ($config, $template) extends Template {
            /**
             * Get the contents produced by this template.
             *
             * @return string The HTML rendered by this template, as a string.
             * @throws \Exception if the template cannot be found.
             */
            public function getContents(): string
            {
                return parent::getContents();
            }
        };

        $t->data = [
            'subject' => $this->mail->Subject,
            'text' => $this->text,
            'data' => $this->data,
        ];

        return $t->getContents();
    }
}

