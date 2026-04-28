# Tablette ReMarkable 2

Cette documentation concerne l’installation du logiciel reMarkable client desktop, des modules Google Chrome et les procédures d’exploitation de la tablette reMarkable2 en Wifi via le cloud ou par connexion USB pour la visualisation de contenu et l’échange de fichiers (*.pdf, *.epub) avec PC sous système d’exploitation UBUNTU 20.04 LTS.


## Prérequis : mise à jour des paquets Ubuntu

```bash
sudo apt update && sudo apt full-upgrade && sudo apt autoremove --purge
```

## Installation du logiciel reMarkable client desktop

Sources : [https://remarkablewiki.com/tips/client](https://remarkablewiki.com/tips/client)

### Installation des paquets nécessaires

```bash
sudo apt update && sudo apt install -y libkf5archive5 libqt5xml5
```

### Téléchargement et installation du paquet debian du client ReMarkable 2

```bash
curl -L https://drive.google.com/uc?id=1x_KhRp0_qufjnOO-pyDM1MAhRjeQeJTK --output reMarkable.deb

sudo apt install ./reMarkable.deb
```

## Utilisation du logiciel reMarkable client desktop + connexion tablette en Wifi par le cloud

### Prérequis

1. tablette connectée en Wifi au point d’accès internet (box)
2. compte d’utilisateur reMarkable2 créé sur [https://my.remarkable.com/login](https://my.remarkable.com/login)
3. validation d’un (one-time) code d’enregistrement de la tablette (accès au cloud)

### Procédure de vérification de la synchronisation au cloud sur la tablette

Sur la tablette: **Menu** :arrow_right: **Settings** :arrow_right: **Storage** :arrow_right: **Storage Settings** :arrow_right: **Check sync** (sélectionner)

:arrow_right: Checking…No syncing errors found

### Lancement du logiciel reMarkable client desktop

Ouvrir un terminal (++ctrl+alt+t++) et taper la commande (attention au M majuscule) `reMarkable`

La fenêtre principale doit s’ouvrir :

![Fenêtre principale](../img/remarkable/reMarkable-01-fenetre-principale.png#center#shadow)

- sélectionner **Click here to obtain one-time code**.
- ouverture d’un navigateur et connexion au site [https://my.remarkable.com/](https://my.remarkable.com/login)
- se connecter avec ses identifiants de compte d’utilisateur reMarkable2
- copier le code à usage unique (one-time code)
- coller le code à usage unique dans le champ **Enter one-time code** dans la fenêtre de l’application reMarkable client desktop puis **Log in**
- ouverture d’une session d’application reMarkable client desktop avec affichage du contenu de la tablette (menu MyFiles) d’après les informations de synchronisation par le cloud :

![Session](../img/remarkable/reMarkable-02-session.png#center#shadow)

### Utilisation de LiveView (visualisation à l’écran du PC d’écriture sur tablette)


- Tablette : +Notebook :arrow_right: Create new notebook :arrow_right: Blank :arrow_right: Create
:arrow_right: création et affichage d’une page blanche

- Tablette : icône (carré + flèche) :arrow_right: LiveView (Beta) (sélectionner)
:arrow_right: indication LiveView is connecting puis LiveView ON
- PC : apparition d’un menu pop-up Accept LiveView request ?
:arrow_right: Accept

![Popup](../img/remarkable/reMarkable-03-popup.png#center#shadow)

- PC : affichage du document en cours d’écriture (latences possibles dues au cloud).

![Ecriture](../img/remarkable/reMarkable-04-ecriture.png#center#shadow)

## Navigateur internet + connexion tablette en USB pour le transfert des fichiers

Cette section traite du transfert de fichiers (*.pdf, *.epub) du PC vers la tablette reMarkable2 et réciproquement, sans utilisation du cloud. Le PC et la tablette sont connectés par câble USB. L’accès à la tablette depuis le PC s’effectue via un portail d’accès et navigateur internet (Firefox ou Chrome).

### Prérequis


- connecter la tablette reMarkable2 au PC via le câble USB
- allumer la tablette
- dans Menu :arrow_right: Settings :arrow_right: Storage :arrow_right: USB web interface : off – > on
- relever l’adresse IP: http://10.11.99.1
- copier l’adresse IP dans la barre d’URL d’un navigateur
- affichage d’un portail d’accès à la tablette qui affiche le contenu de My files :

![My Files](../img/remarkable/reMarkable-05-my-files.png#center#shadow)

### Transfert d’un fichier (*.pdf, *.epub) du PC vers la tablette

- à l’aide de la souris, sélectionner le fichier (*.pdf, *. epub) dans son répertoire sur le PC
- à l’aide de la souris, glisser/déposer le fichier sur la page web dans le navigateur
- la page web commute automatiquement en mode «Drop to upload on your reMarkable»
- relâcher la souris: téléchargement du document dans la tablette (menu My files)

Source : [https://support.remarkable.com/hc/en-us/articles/360002661337-Transferring-files-using-a-USB-cable](https://support.remarkable.com/hc/en-us/articles/360002661337-Transferring-files-using-a-USB-cable)

### Transfert d’un fichier (*.pdf, *.epub) de la tablette vers le PC


- connecter la tablette reMarkable2 au PC via le câble USB
- allumer la tablette
- dans Menu/Settings/Storage/USB web interface : off – > on
- relever l’adresse IP: http://10.11.99.1
- copier l’adresse IP dans la barre d’URL d’un navigateur
- affichage d’un portail d’accès à la tablette qui affiche le contenu de My files
- sélectionner le fichier à télécharger et cliquer sur l’icône téléchargement en haut à droite
- le navigateur répond en proposant d’afficher ou de télécharger le document  sur le PC :

![Enregistrer](../img/remarkable/reMarkable-06-enregistrer.png#center#shadow)

## Utilisation par Google Chrome + connexion tablette en Wifi par le cloud

Cette section traite de l’utilisation de la tablette reMarkable2 via le navigateur Google Chrome pour lequel il existe deux extensions permettant de gérer le transfert de fichiers.

### Prérequis : installation du navigateur Google Chrome

Ouvrir un terminal (++ctrl+alt+t++) et taper les commandes :

```bash
sudo sh -c 'echo "deb [arch=amd64] https://dl.google.com/linux/chrome/deb/ stable main" > | etc/apt/sources.list.d/google-chrome.list'

wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -

sudo apt update

sudo apt install -y google-chrome-stable
```

Lancer Google Chrome

### L’extension Read on reMarkable

L'extension permettant de lire en *.pdf sur la tablette toute page ou document consulté via le navigateur :

[https://chrome.google.com/webstore/detail/read-on-remarkable/bfhkfdnddlhfippjbflipboognpdpoeh](https://chrome.google.com/webstore/detail/read-on-remarkable/bfhkfdnddlhfippjbflipboognpdpoeh)

:arrow-right: pour l’utiliser, sélectionner l’extension **Read on reMarkable** dans le menu des extension à droite de la barre d’URL du navigateur.


## Autres cas d’usage

- Tablette reMarkable2, ouvrir le document en lecture
- Barre d’outil latérale, icône «Page» (dernière en bas) sélectionner «Page overview»
- Sélectionner «Go to page» et entrer le numéro de page à l’aide du pavé tactile
