# Технические источники

Официальная документация определяет ожидаемое поведение; фактические результаты устанавливаются только испытанием выбранного AVD.

- Direct Boot, разделение CE/DE, первая разблокировка: https://developer.android.com/privacy-and-security/direct-boot
- Архитектура FBE и ограничения интерпретации: https://source.android.com/docs/security/features/encryption/file-based
- Android Keystore: https://developer.android.com/privacy-and-security/keystore
- Параметры обязательной аутентификации: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationParameters(int,int)
- Системное подтверждение credential: https://developer.android.com/reference/android/app/KeyguardManager#createConfirmDeviceCredentialIntent(java.lang.CharSequence,java.lang.CharSequence)
- Подпись и обновление приложений: https://developer.android.com/studio/publish/app-signing
- Проверка APK: https://developer.android.com/tools/apksigner
- Блокировка недоверенных касаний и диагностический Logcat: https://developer.android.com/about/versions/12/behavior-changes-all#untrusted-touch-events
- Скрытие overlay: https://developer.android.com/reference/android/view/Window#setHideOverlayWindows(boolean)
- Network Security Configuration: https://developer.android.com/privacy-and-security/security-config
- Проверка TLS: https://developer.android.com/privacy-and-security/security-ssl
- MediaProjection, согласие, callback, повторное использование: https://developer.android.com/media/grow/media-projection
- FLAG_SECURE: https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE
- Android Emulator в GitHub Actions — исходники используемого runner: https://github.com/ReactiveCircus/android-emulator-runner

API 34 выбран как фиксированная функциональная платформа. Образ Google APIs x86_64 не является физическим доверенным устройством; выводы об аппаратной криптографической защите из этих опытов не делаются.

- Режимы GPU Android Emulator (используется поддерживаемый `swiftshader`): https://developer.android.com/studio/run/emulator-acceleration
