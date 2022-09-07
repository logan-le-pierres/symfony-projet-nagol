<?php

namespace App\Controller;

use App\Entity\ResetPassword;
use App\Entity\User;
use App\Form\UserType;
use App\Repository\ResetPasswordRepository;
use App\Repository\UserRepository;
use App\Service\Uploader;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Validator\Constraints\DateTime;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class SecurityController extends AbstractController
{

    #[Route("/signup", name:"signup")]
    public function signup(Uploader $uploader, Request $request, EntityManagerInterface $em, UserPasswordHasherInterface $passwordHasher, MailerInterface $mailer): Response
    {
        $user = new User();
        $userForm = $this->createForm(UserType::class, $user);
        $userForm->handleRequest($request);
        if($userForm->isSubmitted() && $userForm->isValid()){
            $picture = $userForm->get('pictureFile')->getData();
            $user->setPicture($uploader->uploadProfilePicture($picture));
            $user->setPassword($passwordHasher->hashPassword($user, $user->getPassword()));
            $em->persist($user);
            $em->flush();
            $this->addFlash('success', 'Salut et bienvenue sur Nagol');
            $email = new TemplatedEmail();
            $email->to($user->getEmail())
                  ->subject('Bienvenue sur Nagol')
                  ->htmlTemplate('@email_templates/welcome.html.twig')
                  ->context([
                    'username' => $user->getFirstname()
                  ]);
            $mailer->send($email);
            return $this->redirectToRoute('login');

        }
        return $this->render('security/signup.html.twig', [
            'form' => $userForm->createView()
        ]);
    }


    #[Route("/login", name:"login")]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if($this->getUser()){
            $this->redirectToRoute('home');
        }
        $error = $authenticationUtils->getLastAuthenticationError();
        $username = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', [
            'error' => $error,
            'username' => $username
        ]);
    }


    #[Route("/logout", name:"logout")]
    public function logout()
    {

    }


    #[Route('/reset-password/{token}', name: 'reset-password')]
    public function resetPassword (RateLimiterFactory $passwordRecoveryLimiter, UserPasswordHasherInterface $userPasswordHasher, Request $request,string $token, ResetPasswordRepository $resetPasswordRepository, EntityManagerInterface $em)
    {
        $limiter = $passwordRecoveryLimiter->create($request->getClientIp());
        if (false === $limiter->consume(1)->isAccepted()){
            $this->addFlash('error', 'Vous avez atteint le maximum de tentatives de connexion, veuillez reassayer plus tard (une heure).');
            return $this->redirectToRoute('login');
        }

        $resetPassword = $resetPasswordRepository->findOneBy(['token' => sha1($token)]);
        if (!$resetPassword || $resetPassword->getExpiredAt() < new DateTime('now')){
                if($resetPassword) {
                    $em->remove($resetPassword);
                    $em->flush();
                }
                    $this->addFlash('error', 'Votre demande a expiré, veuillez refaire une demande');
                    return $this->redirectToRoute('login');
                }
        $passwordForm = $this->createFormBuilder()
                        ->add('password', PasswordType::class, [
                            'label' => 'Mot de passe ',
                            'constraints' => [
                                new Length([
                                    'min' => 4,
                                    'minMessage' => 'Le mot de passe doit faire au moins 4 caractères.'
                                ]),
                                new NotBlank([
                                    'message' => 'Veuillez renseigner un mot de passe.'
                                ])
                            ]])
            ->getForm();

            $passwordForm->handleRequest($request);
            if ($passwordForm->isSubmitted() && $passwordForm->isValid()) {
                $password = $passwordForm->get('password')->getData();
                $user = $resetPassword->getUser();
                $hash = $userPasswordHasher->hashPassword($user, $password);
                $user->setPassword($hash);
                $em->remove($resetPassword);
                $em->flush();
                $this->addFlash('success', 'Votre mot de passe éa été modifié');
                return $this->redirectToRoute('login');
            }


            return $this->render('security/reset_password_form.html.twig', [
                'form' => $passwordForm->createView()
        ]);
    }

    #[Route('/reset_password_request', name: 'reset_password_request')]
    public function resetPasswordRequest (RateLimiterFactory $passwordRecoveryLimiter, MailerInterface $mailer, Request $request, UserRepository $userRepository, ResetPasswordRepository $resetPasswordRepository, EntityManagerInterface $em)
        {

            $limiter = $passwordRecoveryLimiter->create($request->getClientIp());
            if (false === $limiter->consume(1)->isAccepted()){
                $this->addFlash('error', 'Vous avez atteint le maximum de tentatives de connexion, veuillez reassayer plus tard (une heure).');
                return $this->redirectToRoute('login');
            }

            $emailForm = $this->createFormBuilder()->add('email', EmailType::class, [
                'constraints' => [
                    new NotBlank([
                        'message' => 'Veuillez renseigner votre email.'
                    ])
                ]
            ])->getForm();

            $emailForm->handleRequest($request);
            if ($emailForm->isSubmitted() && $emailForm->isValid()) {
                $emailValue = $emailForm->get('email')->getData();
                $user = $userRepository->findOneBy(['email' => $emailValue]);
                if ($user) {
                    $oldResetPassword = $resetPasswordRepository->findOneBy(['user' => $user]);
                    if($oldResetPassword) {
                        $em->remove($oldResetPassword);
                        $em->flush();
                    }
                    $resetPassword = new ResetPassword();
                    $resetPassword->setUser($user);
                    $resetPassword->setExpiredAt(new \DateTimeImmutable('+2 hours'));
                    $token = substr(str_replace(['+','/','='], '', base64_encode(random_bytes(30))), 0, 20);
                    $resetPassword->setToken(sha1($token));
                    $em->persist($resetPassword);
                    $em->flush();
                    $email = new TemplatedEmail();
                    $email->to($emailValue)
                        ->subject('Demande de réinitialisation de mot de pâsse')
                        ->htmlTemplate('@email_templates/reset_password_request.html.twig')
                        ->context([

                            'token' => $token
                        ]);
                    $mailer->send($email);

                    //dump($resetPassword);
                }
                $this->addFlash('success', 'Un email vous a été envoyer pour réinitialiser votre mot de passe ');
                return $this->redirectToRoute('home');


            }

            return $this->render('security/reset_password_request.html.twig', [
                'form' => $emailForm->createView()
            ]);
        }
}
