# S3Vibe
## Базовый сценарий
S3-подобное хранилище с веб-интерфейсом. Пользователь может создавать бакеты, загружать файлы, просматривать и скачивать их.

### Все фичи
- Регистрация и авторизация
- Создание бакетов
- Загрузка файлов в бакеты
- Просмотр списка файлов в бакете
- Скачивание файлов

## Архитектура
Микросервисная архитектура:
- `authproxy` - прокси для аутентификации на Python/Twisted
- `s3service` - сервис хранения на Go
- `frontend` - веб-интерфейс на React

## Уязвимости

### Множественные заголовки s3-bucket-id

При проверке доступа к бакету в authproxy используется метод `getHeader()`, который возвращает только первое значение заголовка. Однако при проксировании запроса в s3service все заголовки передаются как есть.

```python
bucket_id = request.getHeader(b's3-bucket-id')  # Возвращает только первое значение
if not bucket_id:
    request.setResponseCode(400)
    # ...
bucket_access = self.auth_manager.check_bucket_access(
    user_info['user_id'],
    bucket_id.decode('utf-8')
)
```

При проксировании:
```python
headers = {}
for key, values in request.requestHeaders.getAllRawHeaders():
    headers[key] = values  # Передаются все значения заголовка
```

В s3service используется `r.Header.Get()`, который также возвращает первое значение. Однако можно отправить запрос напрямую в s3service (минуя authproxy), указав несколько заголовков `s3-bucket-id`. Если s3service обрабатывает все заголовки или использует другой метод получения, можно получить доступ к чужому бакету.

Альтернативно, если отправить запрос напрямую в s3service на порт 2323, можно обойти проверку доступа в authproxy полностью, указав ID бакета жертвы.

### Local File Read через Path Traversal

При листинге объектов используется параметр `prefix`, который передаётся напрямую в функцию `ListObjects` без должной валидации. Функция `sanitize.Path` может не защищать от всех видов path traversal.

```go
func (h *Handler) ListObjects(w http.ResponseWriter, r *http.Request) {
    bucketID := h.getBucketID(r)
    prefix := r.URL.Query().Get("prefix")
    objects, err := h.storage.ListObjects(bucketID, prefix)
    // ...
}
```

В файловой системе:
```go
func (fs *FileSystemStorage) ListObjects(bucketID, prefix string) ([]ObjectInfo, error) {
    bucketPath := sanitize.Path(fs.basePath + "/" + bucketID)
    searchPath := bucketPath
    if prefix != "" {
        searchPath = sanitize.Path(fs.basePath + "/" + bucketID + "/" + prefix)
    }
    // ...
}
```

Если использовать специальные последовательности типа `.%25./` (URL-encoded `../`), можно выйти за пределы бакета и прочитать файлы из других бакетов.

## Эксплуатация

### Множественные заголовки s3-bucket-id
1. Создаём свой бакет и получаем auth token
2. Отправляем HTTP запрос напрямую в s3service на порт 2323 (минуя authproxy)
3. В запросе указываем два заголовка `s3-bucket-id`:
   - Первый: ID своего бакета
   - Второй: ID бакета жертвы из attack_data
4. s3service может обработать оба заголовка или использовать последний
5. Получаем доступ к файлам в бакете жертвы

### Local File Read через Path Traversal
1. Получаем ID бакета жертвы из attack_data
2. Используем параметр `prefix` со значением `.%25./{bucket_id}/` для выхода из текущего бакета
3. Листим файлы в бакете жертвы
4. Скачиваем файлы, используя тот же path traversal в пути к объекту

## Как фиксить

### Множественные заголовки s3-bucket-id
- Проверять, что заголовок `s3-bucket-id` присутствует только один раз
- Валидировать bucket_id на стороне s3service, проверяя доступ через authproxy API
- Не позволять прямые запросы к s3service, только через authproxy
- Использовать единую точку проверки доступа

### Local File Read через Path Traversal
- Строго валидировать параметр `prefix`, запрещая любые попытки выхода за пределы бакета
- Использовать `filepath.Join` и проверять, что результирующий путь начинается с пути бакета
- Нормализовать пути перед использованием
- Запретить специальные символы в именах объектов и префиксах

