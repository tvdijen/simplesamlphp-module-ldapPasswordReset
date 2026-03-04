<?php

declare(strict_types=1);

namespace SimpleSAML\Module\ldapPasswordReset\Controller;

use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Session;
use SimpleSAML\Module\ldapPasswordReset\UserRepository;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

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

    /** @var \SimpleSAML\Auth\Simple */
    protected Auth\Simple $authSource;

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
     * Initializes the authentication
     *
     * @return \SimpleSAML\XHTML\Template
     */
    public function login(Request $request): Template
    {
        $auth = $this->moduleConfig->getString('auth');
        if (Auth\Source::getById($auth) !== null) {
            $this->authSource = new Auth\Simple($auth);
        } else {
            throw new Error\Exception('No such "' . $auth . '" auth source found.');
        }

        $state = [];
        $id = $this->authState::saveState($state, 'ldapPasswordReset:authenticated');
        $returnTo = Module::getModuleURL('ldapPasswordReset/resetPassword', ['AuthState' => $id]);
        $params['ReturnTo'] = $returnTo;

        $this->authSource->login($params);
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

        $auth = $this->moduleConfig->getString('auth');
        if (Auth\Source::getById($auth) !== null) {
            $this->authSource = new Auth\Simple($auth);
        } else {
            throw new Error\Exception('No such "' . $auth . '" auth source found.');
        }

        /** @var array<mixed> $state */
        $state = $this->authState::loadState($id, 'ldapPasswordReset:authenticated', false);
        $attributes = $this->authSource->getAttributes();
        $identifyingAttribute = $this->moduleConfig->getOptionalString('identifyingAttribute', 'userPrincipalName');
        $subject = $attributes[$identifyingAttribute][0];

        $t = new Template($this->config, 'ldapPasswordReset:resetPassword.twig');
        $t->data = [
            'AuthState' => $id,
            'passwordMismatch' => false,
            'emailAddress' => $subject,
        ];

        // Check if the submit-button was hit, or whether this is a first visit
        if ($request->request->has('submit_button')) {
            $this->logger::debug(sprintf(
                'ldapPasswordReset: a new password was entered for user %s',
                $subject,
            ));

            // See if the submitted passwords match
            /** @psalm-var string $newPassword */
            $newPassword = $request->request->get('new-password');
            /** @psalm-var string $retypePassword */
            $retypePassword = $request->request->get('password');

            if (strcmp($newPassword, $retypePassword) === 0) {
                $this->logger::debug(sprintf(
                    'ldapPasswordReset: new matching passwords were entered for user %s',
                    $subject,
                ));

                $user = $this->userRepository->findUserByEmail($attributes['userPrincipalName'][0]);
                Assert::notNull($user); // Must exist

                /** @psalm-var \Symfony\Component\Ldap\Entry $user */
                $result = $this->userRepository->updatePassword($user, $newPassword);
                if ($result === true) {
                    $this->logger::info(sprintf(
                        'Password was reset for user: %s',
                        $subject,
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

                    return $t;
                } else {
                    $this->logger::warning(sprintf(
                        'Password reset has failed for user: %s',
                        $subject,
                    ));

                    $t->data['passwordChanged'] = false;
                }
            } else {
                $this->logger::debug(sprintf(
                    'ldapPasswordReset: mismatching passwords were entered for user %s',
                    $subject,
                ));
                $t->data['passwordMismatch'] = true;
            }
        }

        return $t;
    }
}
