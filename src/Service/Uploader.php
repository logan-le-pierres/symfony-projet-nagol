<?php


namespace App\Service;

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpFoundation\File\UploadedFile;

class Uploader
{

    public function __construct(private Filesystem $fs, private $profileFolder, private $profileFolderPublic)
    {
    }

    public function uploadProfileImage(UploadedFile $picture, string $oldPicturePath = null): string
    {
        $folder = $this->profileFolder;
        $ext = $picture->guessExtension() ?? 'bin';
        $filename = bin2hex(random_bytes(10)) . '.' . $ext;
        $picture->move($folder, $filename);
        if ($oldPicturePath) {
            $this->fs->remove($folder . '/' . pathinfo($oldPicturePath, PATHINFO_BASENAME));
        }
        return $this->profileFolderPublic . '/' . $filename;
    }
}
//namespace App\Service;
//
//
//
//use Symfony\Component\DependencyInjection\ContainerInterface;
//use Symfony\Component\Filesystem\Filesystem;
//use Symfony\Component\HttpFoundation\File\UploadedFile;
//
//class Uploader
//{
//
//    public function __construct (private ContainerInterface $container, private Filesystem $fs)
//    {
//
//    }
//
//
//    public function uploadProfilePicture (UploadedFile $picture, string $oldPicturePath = null): string
//    {
//
//        // Apres avoir changé 'picture par 'pictureFile', et l'avoir mappé en false on doit ici s'occuper de ne pas avoir l'erreur "Integrity constraint violation: 1048 Column 'picture' cannot be null"
//        $folder = $this->container->getParameter('profile.folder');
//        $ext = $picture->guessExtension() ?? 'bin';
//        $filename = bin2hex(random_bytes(10)) . '.'. $ext;
//        $picture->move($folder, $filename);
//        if ($oldPicturePath) {
//            $this->fs->remove($folder . '/' . pathinfo($oldPicturePath, PATHINFO_BASENAME));
//        }
//        return $this->container->getParameter('profile.folder.public_path') .'/' . $filename;
//
//    }
//
//}