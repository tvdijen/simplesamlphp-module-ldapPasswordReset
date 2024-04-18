<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldapPasswordReset\Controller;

use SimpleSAML\Assert\Assert;
use SimpleSAML\{Auth, Configuration, Error, Logger, Module, Session};
use SimpleSAML\Module\ldapPasswordReset\MagicLink;
use SimpleSAML\Module\ldapPasswordReset\TokenStorage;
use SimpleSAML\Module\ldapPasswordReset\UserRepository;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\{RedirectResponse, Request};

use function date;
use function sprintf;
use function time;

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

        $state = [];
        if ($request->request->has('submit_button')) {
            /** @psalm-var string|null $id */
            $id = $request->query->get('AuthState', null);
            if ($id === null) {
                throw new Error\BadRequest('Missing AuthState parameter.');
            }

            $t->data['mailSent'] = true;

            /** @psalm-var string $email */
            $email = $request->request->get('email');
            Assert::stringNotEmpty($email);

            /** @var array<mixed> $state */
            $state = $this->authState::loadState($id, 'ldapPasswordReset:request', false);

            $user = $this->userRepository->findUserByEmail($email);
            if ($user !== null) {
                $this->logger::info(sprintf('ldapPasswordReset: a password reset was requested for user %s', $email));

                $tokenStorage = new TokenStorage($this->config);
                $token = $tokenStorage->generateToken();
                $session = $this->session->getTrackID();
                $validUntil = time() + ($this->moduleConfig->getOptionalInteger('magicLinkExpiration', 15) * 60);

                $tokenStorage->storeToken(
                    $token,
                    $email,
                    $session,
                    $validUntil,
                    $state['ldapPasswordReset:referer'] ?? null
                );
                $this->logger::debug(sprintf('ldapPasswordReset: token %s was stored for %s', $token, $email));

                $mailer = new MagicLink($this->config);
                $mailer->sendMagicLink($email, $token, $validUntil);
                $this->logger::info(sprintf(
                    'ldapPasswordReset: token %s was e-mailed to user %s (valid until %s)',
                    $token,
                    $email,
                    date(DATE_RFC2822, $validUntil)
                ));
            } else {
                $this->logger::warning(sprintf(
                    'ldapPasswordReset: a password reset was requested for non-existing user %s',
                    $email
                ));
            }
        } else {
            $state = [];

            if ($request->server->has('HTTP_REFERER')) {
                $state['ldapPasswordReset:referer'] = $request->server->get('HTTP_REFERER');
            }
        }

        $t->data['AuthState'] = $this->authState::saveState($state, 'ldapPasswordReset:request');
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

        /** @psalm-var string $t */
        $t = $request->query->get('t');
        Assert::uuid($t, 'Invalid token provided.', Error\BadRequest::class);

        $tokenStorage = new TokenStorage($this->config);
        $token = $tokenStorage->retrieveToken($t);

        Assert::nullOrIsArray($token);

        if ($token !== null) {
            Assert::keyExists($token, 'mail');
            Assert::keyExists($token, 'session');
            Assert::keyExists($token, 'referer');

            if (
                $this->moduleConfig->getOptionalBoolean('lockBrowserSession', true)
                && $token['session'] !== $this->session->getTrackID()
            ) {
                $this->logger::warning(sprintf(
                    "Token '%s' was used in a different browser session then where it was requested from.",
                    $t,
                ));
            } else {
                $this->logger::info(sprintf(
                    "ldapPasswordReset: pre-conditions for token '%s' were met. User '%s' may change it's password.",
                    $t,
                    $token['mail']
                ));

                // All pre-conditions met - Allow user to change password
                $state = [
                    'ldapPasswordReset:magicLinkValidated' => true,
                    'ldapPasswordReset:subject' => $token['mail'],
                    'ldapPasswordReset:session' => $token['session'],
                    'ldapPasswordReset:token' => $t,
                    'ldapPasswordReset:referer' => $token['referer'],
                ];

                // Invalidate token - It may be used only once to reset a password
//                $tokenStorage->deleteToken($t);

                $id = $this->authState::saveState($state, 'ldapPasswordReset:request');
                return new RedirectResponse(
                    Module::getModuleURL('ldapPasswordReset/resetPassword', ['AuthState' => $id])
                );
            }
        } else {
            $this->logger::warning(sprintf("ldapPasswordReset: Could not find token '%s' in token storage.", $t));
        }

        $this->logger::debug(sprintf("ldapPasswordReset: an invalid magic link was used: %s", $t));
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
        /** @psalm-var string|null $id */
        $id = $request->query->get('AuthState', null);
        if ($id === null) {
            throw new Error\BadRequest('Missing AuthState parameter.');
        }

        /** @var array<mixed> $state */
        $state = $this->authState::loadState($id, 'ldapPasswordReset:request', false);

        $t = new Template($this->config, 'ldapPasswordReset:resetPassword.twig');
        $t->data = [
            'AuthState' => $id,
            'passwordMismatch' => false,
            'emailAddress' => $state['ldapPasswordReset:subject'],
        ];

        // Check if the submit-button was hit, or whether this is a first visit
        if ($request->request->has('submit_button')) {
            $this->logger::debug(sprintf(
                'ldapPasswordReset: a new password was entered for user %s',
                $state['ldapPasswordReset:subject']
            ));

            // See if the submitted passwords match
            /** @psalm-var string $newPassword */
            $newPassword = $request->request->get('new-password');
            /** @psalm-var string $retypePassword */
            $retypePassword = $request->request->get('password');

            if (strcmp($newPassword, $retypePassword) === 0) {
                $this->logger::debug(sprintf(
                    'ldapPasswordReset: new matching passwords were entered for user %s',
                    $state['ldapPasswordReset:subject']
                ));

                $user = $this->userRepository->findUserByEmail($state['ldapPasswordReset:subject']);
                Assert::notNull($user); // Must exist

                /** @psalm-var \Symfony\Component\Ldap\Entry $user */
                $result = $this->userRepository->updatePassword($user, $newPassword);
                if ($result === true) {
                    $this->logger::info(sprintf(
                        'Password was reset for user: %s',
                        $state['ldapPasswordReset:subject']
                    ));

                    $t = new Template($this->config, 'ldapPasswordReset:passwordChanged.twig');
                    if (
                        isset($state['ldapPasswordReset:referer'])
                        && ($state['session'] === $this->session->getTrackID())
                    ) {
                        // If this isn't the same browser, it makes no sense to get back to the
                        // previous authentication-flow. It will fail relentlessly
                        $t->data['referer'] = $state['ldapPasswordReset:referer'];
                    }
                    $t->data['passwordChanged'] = true;

                    // Invalidate token - It may be used only once to reset a password
                    $tokenStorage = new TokenStorage($this->config);
                    $tokenStorage->deleteToken($state['ldapPasswordReset:token']);

                    return $t;
                } else {
                    $this->logger::warning(sprintf(
                        'Password reset has failed for user: %s',
                        $state['ldapPasswordReset:subject']
                    ));

                    $t->data['passwordChanged'] = false;
                }
            } else {
                $this->logger::debug(sprintf(
                    'ldapPasswordReset: mismatching passwords were entered for user %s',
                    $state['ldapPasswordReset:subject']
                ));
                $t->data['passwordMismatch'] = true;
            }
        }

        return $t;
    }
}
