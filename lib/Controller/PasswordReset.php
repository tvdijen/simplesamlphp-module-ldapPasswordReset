<?php

namespace SimpleSAML\Module\ldapPasswordReset\Controller;

use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\{Auth, Configuration, Error, Logger, Module, Session};
use SimpleSAML\Module\ldapPasswordReset\MagicLink;
use SimpleSAML\Module\ldapPasswordReset\TokenStorage;
use SimpleSAML\Module\ldapPasswordReset\UserRepository;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\{RedirectResponse, Request};

use function sprintf;

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

    /** @var \SimpleSAML\Configuration */
    protected Configuration $moduleConfig;

    /** @var \SimpleSAML\Session */
    protected Session $session;

    /** @var \SimpleSAML\Module\ldapPasswordReset\UserRepository */
    protected UserRepository $userRepository;

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
        $this->logger = new Logger();
        $this->moduleConfig = Configuration::getConfig('module_ldapPasswordReset.php');
        $this->session = $session;
        $this->userRepository = new UserRepository();
    }


    /**
     * Inject the \SimpleSAML\Logger dependency.
     *
     * @param \SimpleSAML\Logger $logger
     */
    public function setLogger(Logger $logger): void
    {
        $this->logger = $logger;
    }


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
        $t = new Template($this->config, 'ldapPasswordReset:enterEmail.twig');
        $t->data = [
            'mailSent' => false,
        ];

        if ($request->request->has('submit_button')) {
            $t->data['mailSent'] = true;

            $email = $request->request->get('email');
            $user = $this->userRepository->findUserByEmail($email);

            if ($user !== null) {
                $tokenStorage = new TokenStorage($this->config);
                $token = $tokenStorage->generateToken();
                $session = $this->session->getTrackID();

                $state = ['ldapPasswordReset:magicLinkRequested' => true];
                if (isset($request->server->has('HTTP_REFERER'))) {
                    $state['referer'] = $request->server->get('HTTP_REFERER');
                }
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

        $t = $request->query->get('t');
        Assert::uuid($t, 'Invalid token provided.', Error\BadRequest::class);

        $tokenStorage = new TokenStorage($this->config);
        $token = $tokenStorage->retrieveToken($t);

        Assert::nullOrIsArray($token);

        if ($token !== null) {
            Assert::keyExists($token, 'mail');
            Assert::keyExists($token, 'session');
            Assert::keyExists($token, 'AuthState');

            if (
                $this->moduleConfig->getOptionalBoolean('lockBrowserSession', true)
                && $token['session'] !== $this->session->getTrackID()
            ) {
                $this->logger::warning(sprintf(
                    "Token '%s' was used in a different browser session then where it was requested from.",
                    $t,
                ));
            } else {
                $state = $this->authState::loadState($token['AuthState'], 'ldapPasswordReset:request', false);
                if (($state !== false) && ($state['ldapPasswordReset:magicLinkRequested'] === true)) {
                    $this->logger::info(sprintf(
                        "Preconditions for token '%s' were met. User '%s' may change it's password.",
                        $t,
                        $token['mail']
                    ));

                    // All pre-conditions met - Allow user to change password
                    $state['ldapPasswordReset:magicLinkValidated'] = true;
                    $state['ldapPasswordReset:subject'] = $token['mail'];

                    // Invalidate token - It may be used only once to reset a password
                    $tokenStorage->deleteToken($t);

                    $id = $this->authState::saveState($state, 'ldapPasswordReset:request');
                    return new RedirectResponse(
                        Module::getModuleURL('ldapPasswordReset/resetPassword', ['AuthState' => $id])
                    );
                } else {
                   $this->logger::warning(sprintf(
                       "Token '%s' was valid, but according to the AuthState it was never requested.",
                       $t
                   ));
                }
            }
        } else {
            $this->logger::warning(sprintf("Could not find token '%s' in token storage.", $t));
        }

        return new RedirectResponse(Module::getModuleURL('ldapPasswordReset/invalidMagicLink'));
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
        $id = $request->query->get('AuthState', null);
        if ($id === null) {
            throw new Error\BadRequest('Missing AuthState parameter.');
        }

        /** @var array $state */
        $state = $this->authState::loadState($id, 'ldapPasswordReset:request', false);

        $t = new Template($this->config, 'ldapPasswordReset:resetPassword.twig');
        $t->data = [
            'AuthState' => $id,
            'passwordMismatch' => false,
            'emailAddress' => $state['ldapPasswordReset:subject'],
        ];

        // Check if the submit-button was hit, or whether this is a first visit
        if ($request->request->has('submit_button')) {
            // See if the submitted passwords match
            $newPassword = $request->request->get('new-password');
            $retypePassword = $request->request->get('password');

            if (strcmp($newPassword, $retypePassword) === 0) {
                $user = $this->userRepository->findUserByEmail($state['ldapPasswordReset:subject']);
                $result = $this->userRepository->updatePassword($user, $newPassword);
                if ($result === true) {
                    
                    $t->data['passwordChanged'] = true;
                } else {
                    $t->data['passwordChanged'] = false;
                    $t->errorMessage = $e->getMessage();
                }
            } else {
                $t->data['passwordMismatch'] = true;
            }
        }

        return $t;
    }
}
