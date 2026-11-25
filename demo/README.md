# Демо: разбор кода на реальном случае (SubTrackr, моё уведомление GHSA-55x6-pm4p-68xc, HIGH)

Уязвимость (найдена мной локальным разбором кода, подтверждена автором, исправлена в v0.6.11):
ссылка сброса пароля собиралась из заголовков запроса (Host / X-Forwarded-*). Атакующий подменяет
заголовок -> жертве приходит письмо со ссылкой на домен атакующего -> токен сброса уходит атакующему.

Было (v0.6.10, internal/handlers/auth.go):
    resetURL := buildBaseURL(c, h.settingsService.GetBaseURL()) + "/reset-password?token=" + ...
Стало (v0.6.11):
    // The link is built only from the administrator-configured Base URL, never from request headers
    body := passwordResetEmailBody(h.settingsService.GetBaseURL(), token)
Плюс тесты на подмену заголовков (auth_reset_link_test.go, email_header_test.go).
https://github.com/bscott/subtrackr/security/advisories/GHSA-55x6-pm4p-68xc

Что дают инструменты на той же уязвимой версии (subtrackr_scan.txt):
- trivy fs: 25 уязвимостей HIGH в зависимостях go.mod
- semgrep p/golang: 6 находок (TLS без MinVersion, cookie сессии без Secure)
- gitleaks: 17 срабатываний в истории git (скрыты, проверить вручную — часто тестовые данные)
- НИ ОДИН инструмент не нашёл саму уязвимость сброса пароля. Её нашёл разбор кода руками.
  Вывод: сканеры дают фон, а критичное находит понимание логики.
