# Spring security

## Основные изменения в конфигурации безопасности (SecurityFilterChain)
| №  | Описание                                                                                                                                     |
|----|----------------------------------------------------------------------------------------------------------------------------------------------|
| 1	 | Отключить фильтры для /h2-console                                                                                                            |
| 2  | Настроить доступ к /company/** и /user/** только аутентифицированным пользователям, включить HTTP basic аутентификацию.                      |
| 3  | Закрыть доступ к остальным URL. (denyAll)                                                                                                    |
| 4	 | Разрешить доступ к /info всем пользователям.                                                                                                 |
| 5	 | Написать собственный UserDetailsAdapter.                                                                                                     |
| 6	 | Написать собственный UserDetailsServiceImpl                                                                                                  |
| 7	 | Интегрировать UserDetailsService в SecurityConfig                                                                                            |
| 8  | Написать специальные методы UserRepository, позволяющие eager-загружать пользователей.                                                       |
| 9  | Добавить BCryptPasswordEncoder, исправить хранимые пароли в БД и сохранять пользователей с закодированным паролем                            | 
| 10 | Использовать хранение аутентификации в сессии.                                                                                               | 
| 11 | Использовать стандартную логин-форму.                                                                                                        | 
| 12 | Написать собственную логин-страницу.                                                                                                         | 
| 13 | Включить CSRF.                                                                                                                               | 
| 14 | Добавить logout.                                                                                                                             | 
| 15 | Добавить собственную deny page и настроить её в Security Config                                                                              | 
| 16 | Добавить AnonymousAuthenticationFilter                                                                                                       | 
| 17 | Сделать доступ к публичному API только для анонимных пользователей                                                                           | 
| 18 | Настроить anonymous-аутентификацию, чтобы избежать ошибок c UserDetails                                                                      | 
| 19 | Реализовать endpoint /whoami, который возвращает имя текущего пользователя(включая анонимного).                                              | 
| 20 | Сгенерировать собственный сертификат сервера                                                                                                 | 
| 21 | Настроить сгенерированный сертификат на сервере и посмотреть как это все работает с basic-аутентификацией                                    | 
| 22 | Настроить Mutual TLS, сгенерировав собственный сертификат клиента, и настроить взаимодействие x509 взаимодействие между клиентом и сервером  | 
| 23 | Создание кастомного Voter-а affirmativeBased                                                                                                 | 
| 24 | Method-based авторизация в Spring Security (UserController аннотации @Secured и @PreAuthorized @PostAuthorized (MethodSecurityConfiguration) | 
  