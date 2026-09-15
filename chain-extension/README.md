# Requests Chainer pour Burp Suite

Extension Java Montoya qui envoie des requêtes sélectionnées de l'historique dans l'ordre et récupère des variables dans les réponses JSON.

## Utilisation

1. Dans **Proxy > HTTP history**, sélectionnez plusieurs requêtes, faites un clic droit et choisissez **Extensions > Requests Chainer > Add to Requests Chainer**. Les requêtes sélectionnées depuis l'historique Proxy sont ajoutées de la plus ancienne à la plus récente.
2. Ouvrez l'onglet **Requests Chainer**. Utilisez **Move up / Move down** pour modifier l'ordre si nécessaire.
3. Sélectionnez la première requête. Dans la réponse affichée à droite, surlignez la valeur de l'ID avec la souris et cliquez **Variable from selected response value**. Nommez-la `id`. Si la valeur apparaît plusieurs fois, choisissez son chemin JSON.
4. Sélectionnez la requête qui utilisera l'ID. Surlignez l'ancien ID ou placez le curseur à l'endroit voulu dans la requête affichée à gauche. Cliquez **Insert variable at caret** et saisissez `id`. Le marqueur `{{id}}` peut aussi être tapé directement. Les modifications de la requête sont conservées lorsque vous changez d'étape.
5. Cliquez **Run chain**. Le journal indique le code HTTP de chaque étape et les variables extraites. Une réponse HTTP 4xx/5xx, une variable absente ou un chemin JSON manquant arrête la chaîne.

Le JAR installé est `build/libs/burp-request-chain.jar`. Pour le reconstruire :

```sh
JAVA_HOME=/usr/lib/jvm/java-26-openjdk PATH=/usr/lib/jvm/java-26-openjdk/bin:$PATH ./gradlew test jar
```

L'extension recalcule le `Content-Length` des requêtes HTTP/1 après substitution. Les variables sont remplacées telles quelles dans la requête brute ; placez-les dans le bon format pour le champ qui les reçoit.

## Application de test locale

`../test-app/server.py` expose `http://127.0.0.1:8765` et fonctionne avec Python standard. L'interface utilise de vrais formulaires HTTP, sans dépendre de JavaScript. Chaque GET `/api/object` génère un nouvel ID (par exemple `chain-a1b2c3d4e5f6`) et le renvoie dans `{"data":{"object":{"id":"..."}}}`. Sélectionnez la valeur reçue dans cette réponse et créez la variable `id`. Le bouton **2. Prepare** crée une étape intermédiaire. Le bouton **3. Use ID** envoie volontairement `REPLACE_ME` ; remplacez cette valeur par `{{id}}` dans l'extension. Le bouton **Show call order** permet de vérifier que les étapes 1, 2 et 3 ont été reçues dans cet ordre, avec le nouvel ID à l'étape 3. Relancez la chaîne pour vérifier qu'un ID différent est généré à chaque exécution.

Pour lancer l'application si elle n'est plus active :

```sh
python3 ../test-app/server.py
```

Ouvrez l'application dans le navigateur intégré de Burp pour remplir l'historique Proxy, ou utilisez un client HTTP configuré sur le proxy Burp `127.0.0.1:8080`.
