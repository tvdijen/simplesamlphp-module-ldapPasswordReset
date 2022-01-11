<?php

namespace SimpleSAML\Module\ldap\PasswordReset\Controller;

//use SimpleSAML\Assert\Assert;
use SimpleSAML\{Auth, Configuration, Session};
use SimpleSAML\Module\ldapPasswordReset\Auth\Source\LdapPasswordReset;
//use SimpleSAML\HTTP\RunnableResponse;
use SimpleSAML\XHTML\Template;
//use Symfony\Component\HttpFoundation\{RedirectResponse, Request};

/**
 * Controller class for the ldapPasswordReset module.
 *
 * This class serves the password reset code and error views available in the module.
 *
 * @package simplesamlphp/simplesamlphp-module-ldapPasswordReset
 */
class PasswordReset
{
    /** @var \SimpleSAML\Configuration */
    protected Configuration $config;

    /** @var \SimpleSAML\Logger */
//    protected Logger $logger;

    /** @var \SimpleSAML\Session */
    protected Session $session;

    /** @var \SimpleSAML\Utils\HTTP */
//    protected Utils\HTTP $httpUtils;

    /**
     * @var \SimpleSAML\Auth\State|string
     * @psalm-var \SimpleSAML\Auth\State|class-string
     */
    protected $authState = Auth\State::class;

    /**
     * @var \SimpleSAML\Auth\Simple|string
     * @psalm-var \SimpleSAML\Auth\Simple|class-string
     */
    protected $authSimple = Auth\Simple::class;

    /**
     * Password reset Controller constructor.
     *
     * @param \SimpleSAML\Configuration $config The configuration to use.
     * @param \SimpleSAML\Session $session The current user session.
     */
    public function __construct(Configuration $config, Session $session)
    {
        $this->config = $config;
//        $this->httpUtils = new Utils\HTTP();
        $this->logger = new Logger();
//        $this->session = $session;
    }


    /**
     * Inject the \SimpleSAML\Logger dependency.
     *
     * @param \SimpleSAML\Logger $logger
    public function setLogger(Logger $logger): void
    {
        $this->logger = $logger;
    }
     */


    /**
     * Inject the \SimpleSAML\Utils\HTTP dependency.
     *
     * @param \SimpleSAML\Utils\HTTP $httpUtils
    public function setHttpUtils(Utils\HTTP $httpUtils): void
    {
        $this->httpUtils = $httpUtils;
    }
     */


    /**
     * Inject the \SimpleSAML\Auth\State dependency.
     *
     * @param \SimpleSAML\Auth\State $authState
     */
    public function setAuthState(Auth\State $authState): void
    {
        $this->authState = $authState;
    }

    /**
     * Inject the \SimpleSAML\Auth\Simple dependency.
     *
     * @param \SimpleSAML\Auth\Simple $authSimple
     */
    public function setAuthSimple(Auth\Simple $authSimple): void
    {
        $this->authSimple = $authSimple;
    }


    /**
     * Trigger password reset flow
     */
    public function main(): RedirectResponse
    {
        /** @psalm-suppress UndefinedClass */
        $authsource = new $this->authSimple('password-reset');

        return new RunnableResponse([$authsource, 'login'], []);
    }


    /**
     * Display the page where the EMail address should be entered.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function enterEmail(Request $request): Template
    {
        $id = $request->query->get('AuthState', null);
        if ($id === null) {
            throw new Error\BadRequest('Missing AuthState parameter.');
        }

        $this->authState::loadState($id, 'cmdotcom:request', false);

        $t = new Template($this->config, 'cmdotcom:entercode.twig');
        $t->data = [
            'AuthState' => $id,
        ];

        return $t;
    }


    /**
     * Display the page where the user can set a new password.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function promptReset(Request $request): Template
    {
    }
}
