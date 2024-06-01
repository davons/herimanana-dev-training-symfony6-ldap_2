<?php

namespace App\EventListener;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Ldap\Security\LdapUser;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;

class LoginEventListener
{
    public function __construct(
        private EntityManagerInterface $em,
        private UserPasswordHasherInterface $passwordHasher,
        private UserRepository $userRepository
    ) {}

    public function onLoginSuccess(InteractiveLoginEvent $event): void
    {
        $request = $event->getRequest();
        $userLdap = $event->getAuthenticationToken()->getUser();
        $username = $request->request->get('_username');

        // Check if the user already exists in the database
        $existingUser = $this->userRepository->findOneBy(['email' => $username]);

        // If user doesn't exist and it's an LDAP user, create a new user
        if (null === $existingUser && $userLdap instanceof LdapUser) {
            $user = new User();
            $user->setEmail($userLdap->getEntry()->getAttributes()['mail'][0]);
            // Hash the password securely
            $user->setPassword($this->passwordHasher->hashPassword($user, $request->request->get('_password')));
            $user->setRoles($userLdap->getRoles());

            try {
                // Persist the new user
                $this->em->persist($user);
                $this->em->flush();
            } catch (\Exception $e) {
                // Handle database errors
                // Log the error for investigation
                // You can customize this according to your logging strategy
                error_log('Error while persisting user: ' . $e->getMessage());
                // Optionally, you can throw the exception for it to be handled elsewhere
                throw $e;
            }
        }

    }
}