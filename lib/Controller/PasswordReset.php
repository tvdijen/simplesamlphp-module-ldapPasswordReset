<?php

namespace SimpleSAML\Module\ldapPasswordReset\Controller;

use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\{Auth, Configuration, Error, Logger, Module, Session};
use SimpleSAML\Module\ldap\Utils\Ldap;
use SimpleSAML\Module\ldapPasswordReset\MagicLink;
use SimpleSAML\Module\ldapPasswordReset\TokenStorage;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\{RedirectResponse, Request};
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Adapter\ExtLdap\Query;

use function var_export;

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
    protected Logger $logger;

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
     * Display the page where the EMail address should be entered.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function enterEmail(Request $request): Template
    {
        $t = new Template($this->config, 'ldapPasswordReset:enteremail.twig');
        $t->data = [
            'mailSent' => false,
        ];

        if ($request->request->has('email')) {
            $t->data['mailSent'] = true;

            $email = $request->request->get('email');
            $user = $this->findUserByEmail($email);

            if ($user !== null) {
                $tokenStorage = new TokenStorage($this->config);
                $token = $tokenStorage->generateToken();
                $session = $this->session->getTrackID();

                $state = ['ldapPasswordReset:magicLinkRequested' => true];
                $id = Auth\State::saveState($state, 'ldapPasswordReset:request');

                $tokenStorage->storeToken($token, $email, $session, $id);

                $mailer = new MagicLink($this->config);
                $mailer->sendMagicLink($email, $token);
            }
        }

        return $t;
    }


    /**
     * Process a received magic link.
     *
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function validateMagicLink(Request $request): RedirectResponse
    {
        if (!$request->query->has('t')) {
            throw new Error\BadRequest('Missing token.');
        }

        $token = $request->query->get('t');
        Assert::uuid($token, 'Invalid token provided.', Error\BadRequest::class);

        $tokenStorage = new TokenStorage($this->config);
        $token = $tokenStorage->retrieveToken();

        Assert::isArray($token);
        Assert::keyExists($token, 'mail');
        Assert::keyExists($token, 'session');
        Assert::keyExists($token, 'AuthState');

        if ($token !== null) {
            if ($token['session'] === $this->session->getTrackID()) {
                $state = $this->authState::loadState($token['AuthState'], 'ldapPasswordReset:request', false);
                if (($state !== false) && ($state['ldapPasswordReset:magicLinkRequested'] === true)) {
                    // All pre-conditions met - Allow user to change password
                    $state['ldapPasswordReset:magicLinkValidated' => true];

                    // Invalidate token - It may be used only once to reset a password
                    $tokenStorage->deleteToken($token);

                    $id = $this->authState::saveState($state, 'ldapPasswordReset:request');
                    return RedirectResponse(Module::getModuleURL('ldapPasswordReset/resetPassword', ['AuthState', $id]));
                }
            }
        }

        return new RedirectResponse(Module::getModuleURL('ldapPasswordReset/invalidMagicLink');
    }


    /**
     * Display an error message when an invalid magic link was used.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function invalidMagicLink(Request $request): Template
    {
        return new Template($this->config, 'ldapPasswordReset:invalidMagicLink.twig');
    }


    /**
     * Display the page where the user can set a new password.
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function resetPassword(Request $request): Template
    {
        echo "DEBUG";
    }


    /**
     * Find user in LDAP-store
     *
     * @param string $email
     * @return \Symfony\Component\Ldap\Entry|null
     */
    private function findUserByEmail(string $email): ?Entry
    {
        // @TODO: make this a configurable setting
        $authsource = 'passwordReset';
        $config = Configuration::getConfig('authsources.php')->toArray()[$authsource];

        $ldapConfig = Configuration::loadFromArray(
            $config,
            'authsources[' . var_export($authsource, true) . ']'
        );

        $encryption = $ldapConfig->getOptionalString('encryption', 'ssl');
        Assert::oneOf($encryption, ['none', 'ssl', 'tls']);

        $version = $ldapConfig->getOptionalInteger('version', 3);
        Assert::positiveInteger($version);

        $timeout = $ldapConfig->getOptionalInteger('timeout', 3);
        Assert::positiveInteger($timeout);

        $ldapUtils = new Ldap();
        $ldapObject = $ldapUtils->create(
            $ldapConfig->getString('connection_string'),
            $encryption,
            $version,
            $ldapConfig->getOptionalString('extension', 'ext_ldap'),
            $ldapConfig->getOptionalBoolean('debug', false),
            $ldapConfig->getOptionalArray('options', []),
        );


        $searchScope = $ldapConfig->getOptionalString('search.scope', Query::SCOPE_SUB);
        Assert::oneOf($searchScope, [Query::SCOPE_BASE, Query::SCOPE_ONE, Query::SCOPE_SUB]);

        $timeout = $ldapConfig->getOptionalInteger('timeout', 3);
        $searchBase = $ldapConfig->getArray('search.base');
        $options = [
            'scope' => $searchScope,
            'timeout' => $timeout,
        ];

        $searchUsername = $ldapConfig->getString('search.username');
        Assert::notWhitespaceOnly($searchUsername);

        $searchPassword = $ldapConfig->getOptionalString('search.password', null);
        Assert::nullOrnotWhitespaceOnly($searchPassword);

        try {
            $ldapUtils->bind($ldapObject, $searchUsername, $searchPassword);
        } catch (Error\Error $e) {
            throw new Error\Exception("Unable to bind using the configured search.username and search.password.");
        }

        $filter = '(|(mail=' . $email . '))';

        try {
            return $ldapUtils->search($ldapObject, $searchBase, $filter, $options, false);
        } catch (Error\Exception $e) {
            // We haven't found the user
            return null;
        }
    }
}
