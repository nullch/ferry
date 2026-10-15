# Changelog

Формат: [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии: [SemVer](https://semver.org/lang/ru/).

## [0.2.0] — unreleased
### Added
- Перенос между дистрибутивами (`-cross-distro`): Debian/Ubuntu, RHEL-семейство, SUSE, Arch, Alpine.
- Абстракция пакетных менеджеров: apt, dnf/yum, zypper, pacman, apk.
- Таблица соответствия имён пакетов (`-pkgmap` для своих строк), сопоставление служб, владельцев и групп.
- Поддержка OpenRC (Alpine) рядом с systemd.
- Режим архива: `push -archive`, `archive -o`, `restore` (с применением или `-extract-to`).
- Тесты, CI, релизные сборки.

## [0.1.0]
### Added
- mTLS-канал, scan → plan → передача → apply → verify для Debian→Debian.
