# Requests Chainer pour Burp Suite

Extension Java Montoya qui envoie des requêtes sélectionnées de l'historique dans l'ordre et récupère des variables dans les réponses JSON.

Le bouton **Help** affiche l'adresse complète du [wiki Requests Chainer](https://github.com/Goultarde/requests_chainer/wiki), avec **Open in browser** et **Copy link**. L'adresse reste sélectionnable si aucun navigateur ne s'ouvre.

## Utilisation

1. Dans **Proxy > HTTP history**, sélectionnez plusieurs requêtes, faites un clic droit et choisissez **Extensions > Requests Chainer > Add to Requests Chainer**. Les requêtes sélectionnées depuis l'historique Proxy sont ajoutées de la plus ancienne à la plus récente.
2. Ouvrez l'onglet **Requests Chainer**. Utilisez **Move up / Move down** pour modifier l'ordre si nécessaire.
3. Sélectionnez la première requête. Dans la réponse affichée à droite, surlignez la valeur de l'ID avec la souris et cliquez **Variable from selected response value**. Nommez-la `id`. Si la valeur apparaît plusieurs fois, choisissez son chemin JSON.
4. Sélectionnez la requête qui utilisera l'ID. Surlignez l'ancien ID ou placez le curseur à l'endroit voulu dans la requête affichée à gauche. Cliquez **Insert variable at caret** et saisissez `id`. Le marqueur `{{id}}` peut aussi être tapé directement. Les modifications de la requête sont conservées lorsque vous changez d'étape.
5. Cliquez **Run chain**. Le journal indique le code HTTP de chaque étape et les variables extraites. Une réponse HTTP 4xx/5xx, une variable absente ou un chemin JSON manquant arrête la chaîne.

Pour ignorer temporairement une ou plusieurs requêtes, décochez leur case **Enabled** ou sélectionnez plusieurs lignes puis cliquez **Disable selected**. **Enable selected** les réactive. Leur état est conservé dans les fichiers `.rchain`; les anciens fichiers sont chargés avec toutes les requêtes activées. Les étapes désactivées sont aussi ignorées lors de la préparation d'une requête cible par la règle de session.

Le JAR installé est `build/libs/burp-request-chain.jar`. Pour le reconstruire :

```sh
JAVA_HOME=/usr/lib/jvm/java-26-openjdk PATH=/usr/lib/jvm/java-26-openjdk/bin:$PATH ./gradlew test jar
```

L'extension recalcule le `Content-Length` des requêtes HTTP/1 après substitution. Les variables sont remplacées telles quelles dans la requête brute ; placez-les dans le bon format pour le champ qui les reçoit.

## Application de test locale

### Création automatique depuis une requête cible

1. Parcourez l'application avec le navigateur de Burp pour capturer le déroulement complet dans **Proxy > HTTP history**.
2. Envoyez uniquement la requête finale à Requests Chainer, puis sélectionnez sa ligne.
3. Cliquez **Automate chain finding**. Une nouvelle chaîne `Auto - …` est créée, sans modifier la chaîne d'origine et sans envoyer de trafic.
4. Le journal **DEPENDENCY** indique les numéros d'historique source/cible, la variable et son extraction. Vérifiez ces liens, puis cliquez **Run chain**.

L'analyse remonte récursivement les réponses précédentes du même protocole/hôte/port, conserve l'ordre chronologique et remplace les valeurs retrouvées dans l'URL, le corps et les en-têtes utiles. Elle reconnaît les feuilles JSON imbriquées, les cookies, les en-têtes `X-*`/`Location`/`Authorization`, les corps binaires complets, gzip/deflate et les transformations URL, JSON, base64/base64url (hex pour les corps binaires). Les marqueurs générés `{{auto_1|bytes}}` conservent les octets, y compris ceux qui ne sont pas UTF-8. Les extracteurs sont enregistrés avec **Save chains**, comme les variables manuelles.

Il s'agit d'une inférence : la correspondance d'une valeur ne prouve pas qu'une étape est nécessaire. La réponse précédente la plus récente est privilégiée. Une dépendance purement côté serveur sans valeur réutilisée, une transformation cryptographique, du trafic non capturé ou provenant d'une autre origine ne peut pas être déduite. Les valeurs de moins de six octets sont ignorées pour limiter les faux positifs. Les limites de travail sont signalées dans le journal : 2000 échanges/64 MiB d'historique, 2 MiB par message ou après décompression, 100 étapes et 512 candidats par réponse.

### Recherche ciblée depuis une sélection

1. Sélectionnez une requête capturée dans la chaîne et surlignez sa valeur dans l'éditeur **Request** (vue **Raw**, sans les guillemets JSON).
2. Cliquez **Find source for selection**, à côté de **Automate chain finding**.
3. Choisissez la réponse source proposée : la liste donne le numéro d'historique, la requête et l'extracteur. Les sources les plus récentes apparaissent en premier ; plusieurs correspondances restent un choix explicite.
4. La requête source est insérée immédiatement avant la requête actuelle. Seule la plage surlignée devient `{{auto_selected_N|bytes}}`, même si la valeur apparaît ailleurs.

Cette recherche ne remonte pas récursivement les dépendances de la source et n'envoie aucun trafic. Répétez l'opération sur la requête insérée si elle nécessite elle-même une valeur préalable. Les valeurs courtes sont acceptées dans ce mode explicite. Les extracteurs, encodages et limites d'historique sont ceux de la recherche complète ; le contenu sélectionné doit correspondre à une valeur complète reconnue. Annuler le choix ne modifie pas la chaîne. La recherche conserve la requête capturée d'origine en mémoire, ce qui permet de traiter plusieurs valeurs après une première insertion. Après rechargement d'une chaîne modifiée, la requête originale peut devoir être réimportée depuis l'historique.

### Scénario complexe

Sur la page d'accueil de l'application de test, cliquez **Run complex demo**. Cette partie utilise JavaScript. Elle capture six étapes utiles et 24 requêtes parasites :

- `/flow/start` : nouvelle session, CSRF et valeur UTF-8 ;
- `/flow/challenge` : corps gzip contenant un challenge binaire non UTF-8, et cookie ;
- `/flow/answer` : réutilisation exacte des octets et du cookie ; réponse JSON compressée et en-tête de reçu ;
- `/flow/profile` : branche séparée produisant un identifiant de profil ;
- `/flow/reserve/...` : valeur UTF-8 encodée dans l'URL, ticket dans un objet JSON ;
- `/flow/finish/...` : réunion des dépendances, consommation de la session.

Envoyez seulement **POST /flow/finish/...** à l'extension, puis utilisez **Automate chain finding**. Un rejeu correct doit reconstruire la session et le challenge : la session initiale est déjà consommée. Chaque réponse JSON contient aussi 36 objets parasites imbriqués, avec de faux identifiants, des clés échappées et du texte Unicode. Les réponses parasites contiennent des identifiants réels altérés d’un caractère. Le challenge contient 4096 octets aléatoires, et la valeur d’URL mêle accents, caractères asiatiques, espaces et symboles.

La suite de tests démarre une instance isolée sur un port aléatoire, découvre les six étapes et vérifie deux rejeux avec des valeurs renouvelées.

### Scénario simple existant

`../test-app/server.py` expose `http://127.0.0.1:8765` et fonctionne avec Python standard. L'interface utilise de vrais formulaires HTTP, sans dépendre de JavaScript. Chaque GET `/api/object` génère un nouvel ID (par exemple `chain-a1b2c3d4e5f6`) et le renvoie dans `{"data":{"object":{"id":"..."}}}`. Sélectionnez la valeur reçue dans cette réponse et créez la variable `id`. Le bouton **2. Prepare** crée une étape intermédiaire. Le bouton **3. Use ID** envoie volontairement `REPLACE_ME` ; remplacez cette valeur par `{{id}}` dans l'extension. Le bouton **Show call order** permet de vérifier que les étapes 1, 2 et 3 ont été reçues dans cet ordre, avec le nouvel ID à l'étape 3. Relancez la chaîne pour vérifier qu'un ID différent est généré à chaque exécution.

Pour lancer l'application si elle n'est plus active :

```sh
python3 ../test-app/server.py
```

Ouvrez l'application dans le navigateur intégré de Burp pour remplir l'historique Proxy, ou utilisez un client HTTP configuré sur le proxy Burp `127.0.0.1:8080`.
